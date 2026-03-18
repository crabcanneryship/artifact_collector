//go:build windows

// Package crypto は RSA-OAEP + AES-256-GCM による暗号化を提供する。
//
// ファイル形式 (.bin):
//
//	[8B]  マジック "FCOL0001"
//	[4B]  RSA暗号化鍵長 (big-endian uint32)
//	[NB]  RSA-OAEP(SHA-256) で暗号化した AES-256 鍵
//	繰り返し (チャンクごと、EOF まで):
//	  [4B]  チャンク暗号文長 (big-endian uint32、0=終端)
//	  [NB]  nonce(12B) + AES-256-GCM 暗号文 + GCMタグ(16B)
//
// アーティファクト (.bin) とメモリダンプ (_memory.bin) は同形式。
// 復号ツール: tools/decrypt/main.go
package crypto

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
)

const (
	Magic       = "FCOL0001"
	ChunkSize   = 64 * 1024 * 1024 // 64MB
	AESKeyLen   = 32
	GCMNonceLen = 12
)

// ── 公開鍵ロード ──────────────────────────────────────────────────────────────

// FindPublicKey は dir 内の最初の *.pem ファイルをRSA公開鍵として読み込む。
func FindPublicKey(dir string) (*rsa.PublicKey, string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil || len(matches) == 0 {
		return nil, "", fmt.Errorf("公開鍵PEMファイルが見つかりません: %s/*.pem", dir)
	}
	for _, path := range matches {
		pub, err := LoadPublicKey(path)
		if err == nil {
			return pub, path, nil
		}
	}
	return nil, "", fmt.Errorf("有効なRSA公開鍵PEMが見つかりません: %s", dir)
}

// LoadPublicKey はPEMファイルからRSA公開鍵を読み込む。
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("PEMファイル読み込み失敗 (%s): %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("PEMデコード失敗: %s", path)
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("公開鍵パース失敗: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("RSA公開鍵ではありません: %s", path)
		}
		return rsaPub, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("未対応のPEMタイプ %q: %s", block.Type, path)
	}
}

// ── EncWriter: ストリーム暗号化ライター ───────────────────────────────────────

// EncWriter は .bin ファイルへのストリーム暗号化書き込みを行う。
// チャンクごとに AES-256-GCM で暗号化し、メモリ使用量を ChunkSize 程度に抑える。
type EncWriter struct {
	dst   *os.File
	gcm   cipher.AEAD
	buf   []byte // 未フラッシュの平文バッファ
	count int    // フラッシュ済みチャンク数
}

// NewEncWriter は dstPath に暗号化ストリームを開始する。
// ヘッダ(マジック + RSA暗号化AES鍵)を即座に書き込む。
func NewEncWriter(dstPath string, pub *rsa.PublicKey) (*EncWriter, error) {
	// AES-256 鍵生成
	aesKey := make([]byte, AESKeyLen)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("AES鍵生成失敗: %w", err)
	}
	// RSA-OAEP で AES鍵を暗号化
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA暗号化失敗: %w", err)
	}
	// AES-GCM 初期化
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES初期化失敗: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM初期化失敗: %w", err)
	}
	// 出力ファイル作成
	dst, err := os.Create(dstPath)
	if err != nil {
		return nil, fmt.Errorf("出力ファイル作成失敗 (%s): %w", dstPath, err)
	}
	// ヘッダ書き込み
	var buf [8]byte
	if _, err := dst.Write([]byte(Magic)); err != nil {
		dst.Close(); return nil, err
	}
	binary.BigEndian.PutUint32(buf[:4], uint32(len(encKey)))
	if _, err := dst.Write(buf[:4]); err != nil {
		dst.Close(); return nil, err
	}
	if _, err := dst.Write(encKey); err != nil {
		dst.Close(); return nil, err
	}
	return &EncWriter{dst: dst, gcm: gcm, buf: make([]byte, 0, ChunkSize)}, nil
}

// Write は平文データを受け取り、ChunkSize に達したらフラッシュする。
func (w *EncWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		space := ChunkSize - len(w.buf)
		n := len(p)
		if n > space {
			n = space
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		total += n
		if len(w.buf) == ChunkSize {
			if err := w.flush(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// WriteEntry は name と data を1エントリとして書き込む (アーティファクト用)。
// エントリ形式: [4B name長][name][8B data長][data] → チャンク化して暗号化
func (w *EncWriter) WriteEntry(name string, data []byte) error {
	nameBytes := []byte(name)
	var hdr [12]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(nameBytes)))
	binary.BigEndian.PutUint64(hdr[4:12], uint64(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(nameBytes); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// Close は残りバッファをフラッシュしてファイルを閉じる。
func (w *EncWriter) Close() error {
	if len(w.buf) > 0 {
		if err := w.flush(); err != nil {
			return err
		}
	}
	// 終端マーカー: チャンク長=0
	var zero [4]byte
	if _, err := w.dst.Write(zero[:]); err != nil {
		return err
	}
	return w.dst.Close()
}

// flush は buf を暗号化して書き出す。
func (w *EncWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	nonce := make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce生成失敗: %w", err)
	}
	ct := w.gcm.Seal(nonce, nonce, w.buf, nil)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	if _, err := w.dst.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.dst.Write(ct); err != nil {
		return err
	}
	w.buf = w.buf[:0]
	w.count++
	return nil
}

// ── ファイル単位の暗号化 (メモリダンプ用) ────────────────────────────────────

// EncryptFile は srcFile をチャンク読み込みしながら dstFile に暗号化書き込みする。
func EncryptFile(srcFile, dstFile string, pub *rsa.PublicKey) error {
	ew, err := NewEncWriter(dstFile, pub)
	if err != nil {
		return err
	}
	src, err := os.Open(srcFile)
	if err != nil {
		ew.Close()
		return fmt.Errorf("ソースファイルオープン失敗: %w", err)
	}
	defer src.Close()
	if _, err := io.Copy(ew, src); err != nil {
		return fmt.Errorf("暗号化コピー失敗: %w", err)
	}
	return ew.Close()
}
