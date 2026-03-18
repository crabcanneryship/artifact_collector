// Package collector はアーティファクトを収集してZIPに直接書き込む。
//
// 取得メソッドはカテゴリで決定する:
//
//	Raw (NTFS直接解析): Registry, EventLog, MFT
//	  → OSロック中のファイルもMFT経由で読み取り可能
//	  → ファイル列挙はMFTキャッシュ (ntfs.Session)
//	OS  (Go標準ライブラリ): Prefetch, その他
//	  → os.Open / filepath.WalkDir で取得
//	  → タイムスタンプは FileInfo.ModTime() から取得
//
// 一時ファイルは一切作成しない。全データはZIPストリームに直接書き込む。
package collector

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"artifact_collector/internal/config"
	"artifact_collector/internal/crypto"
	"artifact_collector/internal/hasher"
	"artifact_collector/internal/ntfs"
)

// ── 定数 ──────────────────────────────────────────────────────────────────────

// minEvtxBytes はEventLogファイルの最小有効サイズ。
// Windowsのevtxテンプレートファイルはヘッダのみ (69,632バイト) で実イベントを持たない。
const (
	minEvtxBytes = 69633
	UserHolder   = "{user}"
)

// ── 公開型 ────────────────────────────────────────────────────────────────────

// CollectionResult は1ファイルの収集結果。
type CollectionResult struct {
	OutputPath  string
	BytesCopied uint64
	SHA256      string
	SourcePath  string
	Method      string    // "Raw" or "OS"
	Modified    time.Time // ファイルの最終更新時刻 (ゼロ値=取得不可)
}

// Collector はMFTセッションとCryptストリームを保持する。
type Collector struct {
	doHash  bool
	enc     *crypto.EncWriter
	session *ntfs.Session // Raw取得用MFTキャッシュ (遅延初期化)
}

// New は Collector を生成する。
func New(doHash bool, ew *crypto.EncWriter) *Collector {
	return &Collector{doHash: doHash, enc: ew}
}

// WriteEntry はZIPに任意エントリを書き込む (レポートファイル用)。
func (c *Collector) WriteEntry(entryName string, data []byte) error {
	return c.enc.WriteEntry(entryName, data)
}

// Close はセッションを閉じる。収集完了後に必ず呼ぶ。
func (c *Collector) Close() {
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
}

// getSession はMFTセッションを遅延初期化して返す。
func (c *Collector) getSession(path string) (*ntfs.Session, error) {
	volume := strings.TrimRight(filepath.VolumeName(path), ":")
	if c.session != nil && c.session.Label == volume {
		log.Printf("MFT has been Loaded for %s", c.session.Label)
		return c.session, nil
	}
	fmt.Printf("[*] MFT読み込み中 (初回のみ)...\n")
	sess, err := ntfs.NewSession(volume)
	if err != nil {
		return nil, fmt.Errorf("NTFSセッション作成失敗: %w", err)
	}
	c.session = sess
	fmt.Printf("[*] MFT読み込み完了\n")
	return c.session, nil
}

// ── 収集エントリポイント ───────────────────────────────────────────────────────

// CollectEntry は config.Entry を解釈して収集を実行し、結果スライスを返す。
func (c *Collector) CollectEntry(cfg *config.Config, entry config.Entry) ([]CollectionResult, error) {
	if config.HasUserPlaceholder(entry.Path) {
		return c.collectUserArtifacts(cfg, entry)
	}

	switch entry.Type {
	case config.TypeDir:
		return c.collectDir(entry.Path, entry.Recursive, entry.AcquisitionMethod())
	case config.TypeFile:
		return c.collectFile(entry.Path, entry.AcquisitionMethod())
	default:
		return nil, fmt.Errorf("不明な EntryType: %s", entry.Type)
	}
}

// ── DIR モード ────────────────────────────────────────────────────────────────

func (c *Collector) collectDir(dirPath string, recursive bool, method config.AcquisitionMethod) ([]CollectionResult, error) {
	switch method {
	case config.MethodRaw:
		return c.collectDirRaw(dirPath, recursive)
	default:
		return c.collectDirOs(dirPath, recursive)
	}
}

// collectDirRaw はMFTキャッシュ経由でディレクトリ内ファイルを収集する。
func (c *Collector) collectDirRaw(dirPath string, recursive bool) ([]CollectionResult, error) {
	sess, err := c.getSession(dirPath)
	if err != nil {
		return nil, err
	}

	relDir := volumeRelPath(c.session.Label, dirPath)
	entries, err := sess.ListDirEntries(relDir, recursive)
	if err != nil {
		return nil, fmt.Errorf("ディレクトリ列挙失敗 (%s): %w", dirPath, err)
	}
	if len(entries) == 0 {
		return []CollectionResult{}, nil
	}

	log.Printf("[D] DIR(Raw)列挙完了: %s → %d ファイル", dirPath, len(entries))

	var results []CollectionResult
	for _, entry := range entries {
		// テンプレートevtxをスキップ
		/*		if strings.EqualFold(category, "EventLog") {
				size, err := sess.GetFileSizeByInode(entry.Inode)
				if err == nil && size < minEvtxBytes {
					log.Printf("[D] テンプレートevtxをスキップ (size=%d): %s", size, entry.RelPath)
					continue
				}
			}*/

		data, err := sess.ReadFileByInode(entry.Inode)
		if err != nil {
			log.Printf("[W] inode読み取り失敗 '%s': %v", entry.RelPath, err)
			continue
		}

		fullSrc := c.session.Label + `:\` + entry.RelPath
		entryName := sourceToCryptEntry(fullSrc)

		ts, hasTS := sess.GetFileTimestampsByInode(entry.Inode)
		var modTime time.Time
		if hasTS {
			modTime = ts.Modified
		}

		if err := c.enc.WriteEntry(entryName, data); err != nil {
			log.Printf("[W] 結果書き込み失敗 '%s': %v", entryName, err)
			continue
		}

		r := CollectionResult{
			OutputPath: entryName, BytesCopied: uint64(len(data)),
			SourcePath: fullSrc, Method: "Raw", Modified: modTime,
		}
		if c.doHash {
			r.SHA256 = hasher.SHA256Bytes(data)
		}
		results = append(results, r)
	}
	return results, nil
}

// collectDirOS は os.ReadDir / filepath.WalkDir でディレクトリ内ファイルを収集する。
func (c *Collector) collectDirOs(dirPath string, recursive bool) ([]CollectionResult, error) {
	var results []CollectionResult

	if recursive {
		err := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			r, rerr := c.readAndEncryptOs(path)
			if rerr != nil {
				log.Printf("[W] OS読み取り失敗 '%s': %v", path, rerr)
				return nil
			}
			results = append(results, *r)
			return nil
		})
		return results, err
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("ディレクトリ読み取り失敗 (%s): %w", dirPath, err)
	}
	for _, d := range entries {
		if d.IsDir() {
			continue
		}
		fullPath := filepath.Join(dirPath, d.Name())
		r, rerr := c.readAndEncryptOs(fullPath)
		if rerr != nil {
			log.Printf("[W] OS読み取り失敗 '%s': %v", fullPath, rerr)
			continue
		}
		results = append(results, *r)
	}
	return results, nil
}

// ── FILE モード ───────────────────────────────────────────────────────────────

func (c *Collector) collectFile(path string, method config.AcquisitionMethod) ([]CollectionResult, error) {
	var collect func(string) (*CollectionResult, error)
	switch method {
	case config.MethodRaw:
		collect = c.readAndEncryptRaw
	default:
		collect = c.readAndEncryptOs
	}

	r, err := collect(path)
	if err != nil {
		return nil, err
	}
	results := []CollectionResult{*r}

	return results, nil
}

// ── USER ループモード ─────────────────────────────────────────────────────────

func (c *Collector) collectUserArtifacts(cfg *config.Config, entry config.Entry) ([]CollectionResult, error) {
	// Getting users from OS path based on the requested entry
	index := strings.Index(entry.Path, UserHolder)
	parentDir := entry.Path[0 : index-1]
	dirEntries, err := os.ReadDir(parentDir)

	if err != nil {
		return nil, fmt.Errorf("Usersディレクトリ列挙失敗: %w", err)
	}

	var users []string
	for _, d := range dirEntries {
		if cfg.IsExcludedUser(d.Name()) {
			continue
		}
		users = append(users, d.Name())
	}
	if len(users) == 0 {
		return []CollectionResult{}, nil
	}

	var results []CollectionResult
	for _, user := range users {
		expandedPath := cfg.ExpandUserPath(entry.Path, user)
		userResults, err := c.collectFile(expandedPath, entry.AcquisitionMethod())
		if err != nil {
			log.Printf("[W] ユーザー '%s' の収集失敗: %v", user, err)
			continue
		}
		results = append(results, userResults...)
	}
	return results, nil
}

func (c *Collector) collectUserLoop(cfg *config.Config, entry config.Entry) ([]CollectionResult, error) {
	// ユーザー一覧はRaw(MFT)から取得
	sess, err := c.getSession(entry.Path)
	if err != nil {
		return nil, err
	}

	usersRelPath := volumeRelPath(c.session.Label, c.session.Label+`:\Users`)
	userDirs, err := sess.ListUserDirs(usersRelPath)
	if err != nil {
		return nil, fmt.Errorf("Usersディレクトリ列挙失敗: %w", err)
	}

	var users []string
	for _, d := range userDirs {
		if cfg.IsExcludedUser(d.RelPath) {
			continue
		}
		users = append(users, d.RelPath)
	}
	if len(users) == 0 {
		return []CollectionResult{}, nil
	}

	var results []CollectionResult
	for _, user := range users {
		expandedPath := cfg.ExpandUserPath(entry.Path, user)
		userResults, err := c.collectFile(expandedPath, entry.AcquisitionMethod())
		if err != nil {
			log.Printf("[W] ユーザー '%s' の収集失敗: %v", user, err)
			continue
		}
		results = append(results, userResults...)
	}
	return results, nil
}

// ── 共通収集処理 ──────────────────────────────────────────────────────────────

// readAndEncryptRaw はRaw Volume (MFTキャッシュ) 経由でファイルを読んで暗号化ストリームに書く。
func (c *Collector) readAndEncryptRaw(path string) (*CollectionResult, error) {
	sess, err := c.getSession(path)
	if err != nil {
		return nil, err
	}
	relPath := volumeRelPath(c.session.Label, path)
	inode, exists := sess.FindFileInode(relPath)
	if !exists {
		// $MFT は特別扱い
		if strings.EqualFold(relPath, "$MFT") {
			data, err := sess.ReadFileByRelPath(relPath)
			if err != nil {
				return nil, fmt.Errorf("$MFT読み取り失敗: %w", err)
			}
			return c.encryptData(path, "Raw", data, time.Time{})
		}
		return nil, fmt.Errorf("ファイル読み取り失敗 (%s): inode解決不可", relPath)
	}
	data, err := sess.ReadFileByInode(inode)
	if err != nil {
		return nil, fmt.Errorf("ファイル読み取り失敗 (%s): %w", relPath, err)
	}
	ts, hasTS := sess.GetFileTimestampsByInode(inode)
	var modTime time.Time
	if hasTS {
		modTime = ts.Modified
	}
	return c.encryptData(path, "Raw", data, modTime)
}

// 通常のWindows IOで収集し暗号化ストリームに書き込む
func (c *Collector) readAndEncryptOs(sourcePath string) (*CollectionResult, error) {
	f, err := os.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("ファイルオープン失敗 (%s): %w", sourcePath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("ファイル情報取得失敗 (%s): %w", sourcePath, err)
	}
	modTime := info.ModTime()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("ファイル読み取り失敗 (%s): %w", sourcePath, err)
	}
	return c.encryptData(sourcePath, "OS", data, modTime)
}

// 暗号化ストリームに書き込みCollectionResult
func (c *Collector) encryptData(sourcePath, method string, data []byte, modTime time.Time) (*CollectionResult, error) {
	entryName := sourceToCryptEntry(sourcePath)
	if err := c.enc.WriteEntry(entryName, data); err != nil {
		return nil, fmt.Errorf("結果書き込み失敗 (%s): %w", entryName, err)
	}
	r := &CollectionResult{
		OutputPath: entryName, BytesCopied: uint64(len(data)),
		SourcePath: sourcePath, Method: method, Modified: modTime,
	}
	if c.doHash {
		r.SHA256 = hasher.SHA256Bytes(data)
	}
	return r, nil
}

// ── ユーティリティ ────────────────────────────────────────────────────────────

func volumeRelPath(volume, fullPath string) string {
	prefix := strings.TrimRight(volume, `\`) + `:\`
	rel := strings.TrimPrefix(fullPath, prefix)
	return strings.TrimLeft(rel, `\`)
}

func sourceToCryptEntry(sourcePath string) string {
	parts := strings.FieldsFunc(sourcePath, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	out := make([]string, 0, len(parts))
	for i, p := range parts {
		if i == 0 {
			p = strings.TrimSuffix(p, ":")
		}
		out = append(out, p)
	}
	return strings.Join(out, "/")
}

var _ = filepath.Join
