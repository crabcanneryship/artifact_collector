//go:build windows

// Package memory は winpmem を使ったメモリダンプ取得・暗号化を行う。
//
// AcquireAndEncrypt は:
//  1. winpmem で一時rawファイルにダンプ
//  2. crypto.EncryptFile で <dumpBaseName>_memory.bin に暗号化
//  3. 一時rawファイルを削除
package memory

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"artifact_collector/internal/crypto"
)

// DumpResult はメモリダンプ取得結果。
type DumpResult struct {
	BinFile    string
	ElapsedSec float64
}

// AcquireAndEncrypt は winpmem でメモリをダンプし暗号化ファイルを生成する。
// pubKeyPath: RSA公開鍵PEMファイルパス
// dumpBaseName: 出力ベース名 (例: "HOST_20260101120000_memory")
// 出力: <dumpBaseName>.bin
func AcquireAndEncrypt(pubKeyPath, dumpBaseName string) (*DumpResult, error) {
	pub, err := crypto.LoadPublicKey(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("公開鍵読み込み失敗: %w", err)
	}

	variant, err := resolveWinpmem()
	if err != nil {
		return nil, err
	}
	log.Printf("[D] winpmem: %s", variant)

	rawFile := dumpBaseName + ".raw"
	binFile := dumpBaseName + ".bin"

	defer func() {
		if _, err := os.Stat(rawFile); err == nil {
			log.Printf("[D] 一時ダンプファイル削除: %s", rawFile)
			os.Remove(rawFile)
		}
	}()

	// フェーズ1: winpmem でダンプ
	fmt.Printf("  [1/2] ダンプ取得中...\n")
	var outBuf bytes.Buffer
	cmd := exec.Command(variant, rawFile)
	cmd.Stdout = &outBuf
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)
	start := time.Now()
	if err := cmd.Run(); err != nil {
		if info, serr := os.Stat(rawFile); serr != nil || info.Size() == 0 {
			return nil, fmt.Errorf("winpmem 失敗: %w\n%s", err, outBuf.String())
		}
		fmt.Fprintf(os.Stderr, "  [!] winpmem 非0終了 (ファイル生成済み、続行)\n")
	}
	info, err := os.Stat(rawFile)
	if err != nil || info.Size() == 0 {
		return nil, fmt.Errorf("ダンプファイルが生成されませんでした")
	}

	// フェーズ2: 暗号化
	fmt.Printf("  [2/2] 暗号化中 (%s)...\n", formatBytes(uint64(info.Size())))
	if err := crypto.EncryptFile(rawFile, binFile, pub); err != nil {
		return nil, fmt.Errorf("暗号化失敗: %w", err)
	}

	return &DumpResult{BinFile: binFile, ElapsedSec: time.Since(start).Seconds()}, nil
}

func resolveWinpmem() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("実行ファイルパス取得失敗: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	candidates := []string{
		"winpmem.exe",
		"winpmem_x64.exe",
		"winpmem_mini_x64.exe",
		"winpmem_mini_x64_rc1.exe",
		"winpmem_mini_x64_rc2.exe",
	}
	for _, name := range candidates {
		p := filepath.Join(exeDir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf(
		"winpmem が見つかりません。以下のいずれかを同ディレクトリに配置してください:\n  %s",
		strings.Join(candidates, "\n  "))
}

func formatBytes(b uint64) string {
	const (KB = uint64(1024); MB = KB * 1024; GB = MB * 1024)
	switch {
	case b >= GB: return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB: return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB: return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:      return fmt.Sprintf("%d B", b)
	}
}
