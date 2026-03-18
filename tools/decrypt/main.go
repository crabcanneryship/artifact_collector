//go:build ignore

// decrypt はアーティファクト・メモリダンプ (.bin) を復号するツール。
//
// ビルド:
//   go build -o decrypt.exe ./tools/decrypt
//
// 使い方:
//   decrypt.exe -key private.pem -in HOST_20260101_artifacts.bin -out artifacts/
//   decrypt.exe -key private.pem -in HOST_20260101_memory.bin    -out memory.raw
//
// アーティファクト (.bin): 内部にエントリ一覧が含まれ -out のディレクトリに展開する。
// メモリダンプ (_memory.bin): -out にファイルパスを指定して raw に復元する。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	magic       = "FCOL0001"
	gcmNonceLen = 12
	aesKeyLen   = 32
)

func main() {
	args := os.Args[1:]
	var keyPath, inPath, outPath string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "-key":
			keyPath = args[i+1]
		case "-in":
			inPath = args[i+1]
		case "-out":
			outPath = args[i+1]
		}
	}
	if keyPath == "" || inPath == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "使い方: decrypt -key private.pem -in FILE.bin -out OUTPUT")
		os.Exit(1)
	}

	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "秘密鍵読み込み失敗: %v\n", err)
		os.Exit(1)
	}

	isMemory := strings.HasSuffix(inPath, "_memory.bin")
	if isMemory {
		if err := decryptRaw(inPath, outPath, priv); err != nil {
			fmt.Fprintf(os.Stderr, "復号失敗: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("復号完了: %s\n", outPath)
	} else {
		count, err := decryptArtifacts(inPath, outPath, priv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "復号失敗: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("復号完了: %d ファイル → %s\n", count, outPath)
	}
}

// ── 復号コア ──────────────────────────────────────────────────────────────────

// openDecryptor はヘッダを読み込んで GCM を初期化し、チャンクリーダーを返す。
func openDecryptor(src *os.File, priv *rsa.PrivateKey) (cipher.AEAD, error) {
	// マジック
	magicBuf := make([]byte, 8)
	if _, err := io.ReadFull(src, magicBuf); err != nil {
		return nil, fmt.Errorf("マジック読み込み失敗: %w", err)
	}
	if string(magicBuf) != magic {
		return nil, fmt.Errorf("マジック不一致 (非対応フォーマット)")
	}
	// RSA暗号化鍵長 + 鍵
	var lenBuf [4]byte
	if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("鍵長読み込み失敗: %w", err)
	}
	encKey := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(src, encKey); err != nil {
		return nil, fmt.Errorf("暗号化鍵読み込み失敗: %w", err)
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA復号失敗 (鍵が違う可能性): %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES初期化失敗: %w", err)
	}
	return cipher.NewGCM(block)
}

// readChunk はチャンク1つを復号して返す。EOF 時は nil, nil。
func readChunk(src *os.File, gcm cipher.AEAD) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("チャンク長読み込み失敗: %w", err)
	}
	cLen := binary.BigEndian.Uint32(lenBuf[:])
	if cLen == 0 {
		return nil, nil // 終端マーカー
	}
	ct := make([]byte, cLen)
	if _, err := io.ReadFull(src, ct); err != nil {
		return nil, fmt.Errorf("暗号文読み込み失敗: %w", err)
	}
	if len(ct) < gcmNonceLen {
		return nil, fmt.Errorf("チャンクが短すぎます")
	}
	plain, err := gcm.Open(nil, ct[:gcmNonceLen], ct[gcmNonceLen:], nil)
	if err != nil {
		return nil, fmt.Errorf("GCM認証失敗 (データ破損または改ざん): %w", err)
	}
	return plain, nil
}

// ── メモリダンプ復号 ──────────────────────────────────────────────────────────

func decryptRaw(srcPath, dstPath string, priv *rsa.PrivateKey) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	gcm, err := openDecryptor(src, priv)
	if err != nil {
		return err
	}
	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	for {
		plain, err := readChunk(src, gcm)
		if err != nil {
			return err
		}
		if plain == nil {
			break
		}
		if _, err := dst.Write(plain); err != nil {
			return fmt.Errorf("書き込み失敗: %w", err)
		}
	}
	return nil
}

// ── アーティファクト復号 ──────────────────────────────────────────────────────

// decryptArtifacts はアーティファクト .bin を復号し outDir に展開する。
// 内部の平文は WriteEntry 形式: [4B name長][name][8B data長][data] の連続。
func decryptArtifacts(srcPath, outDir string, priv *rsa.PrivateKey) (int, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	gcm, err := openDecryptor(src, priv)
	if err != nil {
		return 0, err
	}

	// 全チャンクを結合してエントリストリームを再構成
	var plain []byte
	for {
		chunk, err := readChunk(src, gcm)
		if err != nil {
			return 0, err
		}
		if chunk == nil {
			break
		}
		plain = append(plain, chunk...)
	}

	// エントリを順次展開
	count := 0
	pos := 0
	for pos+12 <= len(plain) {
		nameLen := int(binary.BigEndian.Uint32(plain[pos : pos+4]))
		dataLen := int(binary.BigEndian.Uint64(plain[pos+4 : pos+12]))
		pos += 12
		if pos+nameLen > len(plain) {
			break
		}
		name := string(plain[pos : pos+nameLen])
		pos += nameLen
		if pos+dataLen > len(plain) {
			break
		}
		data := plain[pos : pos+dataLen]
		pos += dataLen

		outPath := filepath.Join(outDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return count, fmt.Errorf("ディレクトリ作成失敗 (%s): %w", outPath, err)
		}
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return count, fmt.Errorf("ファイル書き込み失敗 (%s): %w", outPath, err)
		}
		fmt.Printf("  + %s (%d B)\n", name, len(data))
		count++
	}
	return count, nil
}

// ── 秘密鍵ロード ──────────────────────────────────────────────────────────────

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("PEMデコード失敗")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("RSA秘密鍵ではありません")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("未対応のPEMタイプ: %s", block.Type)
	}
}
