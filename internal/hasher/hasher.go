// Package hasher はファイルの SHA-256 ハッシュを計算する。
package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// SHA256File はファイルパスの SHA-256 ハッシュを16進数文字列で返す。
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes はバイト列の SHA-256 ハッシュを16進数文字列で返す。
func SHA256Bytes(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
