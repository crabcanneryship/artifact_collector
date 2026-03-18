// Package config はアーティファクト収集定義CSVファイルを読み込む。
//
// CSVフォーマット:
//
//	# コメント行は # で始まる
//	volume,C                           ← ボリューム指定行 (コロンなし) (必須、ヘッダーより前)
//	exclude_users,Default,Public,...   ← 除外ユーザー定数行 (省略時はデフォルト値)
//
//	type,recursive,category,path       ← ヘッダー行 (固定)
//	DIR,NO,EventLog,{volume}:\Windows\System32\winevt\Logs
//	DIR,YES,Prefetch,{volume}:\Windows\Prefetch
//	FILE,NO,Registry,{volume}:\Windows\System32\config\SYSTEM
//	FILE,NO,Registry,{volume}:\Users\{user}\NTUSER.DAT
//
// type:      DIR | FILE
// recursive: YES | NO  (DIRのみ有効。YESで再帰的にサブディレクトリも列挙)
// category:  任意文字列 (Registry の場合は .LOG1/.LOG2 を自動追加チェック)
// path:      {volume} → volume値, {user} → Users配下の各ユーザー に展開
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ── デフォルト除外ユーザーリスト ─────────────────────────────────────────────
// CSVの exclude_users 行で上書き可能。
var defaultExcludeUsers = []string{
	"Default",
	"Public",
	"defaultuser0",
	"defaultuser1",
	"All Users",
}

// ── 公開型 ────────────────────────────────────────────────────────────────────

// EntryType は収集エントリの種別。
type EntryType string

const (
	TypeFile EntryType = "FILE"
	TypeDir  EntryType = "DIR"
)

// Entry は収集定義の1行に対応する。
type Entry struct {
	Type      EntryType // FILE or DIR
	Recursive bool      // DIRのみ有効。true で再帰的列挙
	IsLocked  bool      // ロックされたファイルのフラグ
	Path      string    // 収集対象パス
}

// Config は読み込んだ設定全体。
type Config struct {
	ExcludeUsers []string // Usersループから除外するユーザー名
	Entries      []Entry
}

// ── 公開関数 ──────────────────────────────────────────────────────────────────

// ファイル指定がない場合のデフォルト処理
func New() *Config {
	return &Config{
		ExcludeUsers: []string{"Default", "Public", "All Users"},
		Entries: []Entry{
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\$MFT"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\$Extend\\$UsnJrnl"},
			{Type: TypeDir, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\winevt\\Logs"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SYSTEM"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SYSTEM.LOG1"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SYSTEM.LOG2"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SOFTWARE"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SOFTWARE.LOG1"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SOFTWARE.LOG2"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SAM"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SAM.LOG1"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SAM.LOG2"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SECURITY"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SECURITY.LOG1"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Windows\\System32\\config\\SECURITY.LOG2"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Users\\{user}\\NTUSER.DAT"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Users\\{user}\\NTUSER.DAT.LOG1"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Users\\{user}\\NTUSER.DAT.LOG2"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2"},
			{Type: TypeFile, Recursive: false, IsLocked: true, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Archived History"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Preferences"},
			{Type: TypeDir, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Preferences"},
			{Type: TypeDir, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache"},
			//{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\{profile}\\places.sqlite"},
			//{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\{profile}\\cookies.sqlite"},
			//{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\{profile}\\formhistory.sqlite"},
			//{Type: TypeDir, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\{profile}\\cache2\\entries"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\index.dat"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\index.dat"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Roaming\\Opera Software\\Opera Stable\\History"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Roaming\\Opera Software\\Opera Stable\\Cookies"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Roaming\\Apple Computer\\Safari\\History.db"},
			{Type: TypeFile, Recursive: false, IsLocked: false, Path: "C:\\Users\\{user}\\AppData\\Roaming\\Apple Computer\\Safari\\Cookies\\Cookies.binarycookies"}, {Type: TypeDir, Recursive: true, IsLocked: false, Path: "C:\\$RecycleBin"},
			{Type: TypeDir, Recursive: false, IsLocked: false, Path: "C:\\Windows\\Prefetch"},
		},
	}
}

// Load はCSVファイルを読み込んで Config を返す。
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("設定ファイルオープン失敗 (%s): %w", path, err)
	}
	defer f.Close()

	cfg := &Config{
		ExcludeUsers: append([]string{}, defaultExcludeUsers...),
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 空行・コメント行はスキップ
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := splitCSVLine(line)
		if len(fields) == 0 {
			continue
		}

		// 列数チェック
		if len(fields) < 4 {
			return nil, fmt.Errorf("line %d: 列数不足 (type,recursive,category,path の4列必要): %q", lineNum, line)
		}

		// Entry Type
		entType := EntryType(strings.ToUpper(strings.TrimSpace(fields[0])))
		if entType != TypeFile && entType != TypeDir {
			return nil, fmt.Errorf("line %d: 不正な type %q (FILE または DIR)", lineNum, fields[0])
		}

		// Recursive Flag & Locked Flag
		recursive := strings.ToUpper(strings.TrimSpace(fields[1])) == "YES"
		isLocked := strings.ToUpper(strings.TrimSpace(fields[2])) == "YES"
		Path := strings.TrimSpace(fields[3])

		if Path == "" {
			return nil, fmt.Errorf("line %d: path が空です", lineNum)
		}

		cfg.Entries = append(cfg.Entries, Entry{
			Type:      entType,
			Recursive: recursive,
			IsLocked:  isLocked,
			Path:      Path,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("CSVスキャンエラー: %w", err)
	}

	if len(cfg.Entries) == 0 {
		return nil, fmt.Errorf("設定ファイルにアーティファクト定義がありません")
	}

	return cfg, nil
}

// AcquisitionMethod はファイル取得方法を表す。
type AcquisitionMethod int

const (
	// MethodRaw は Raw Volume (NTFS直接解析) で取得する。
	// ロックされたファイル (Registry Hive, EventLog, MFT) に使用。
	MethodRaw AcquisitionMethod = iota
	// MethodOS は Go 標準の os.Open で取得する。
	// 通常アクセス可能なファイル (Prefetch 等) に使用。
	MethodOS
)

// rawCategories は Raw Volume 取得が必要な category のセット。
// ここに含まれない category は os.Open で取得する。
var rawCategories = map[string]bool{
	"registry": true,
	"eventlog": true,
	"mft":      true,
	"usnjrnl":  true,
}

// AcquisitionMethod はエントリの取得方法を返す。
func (e *Entry) AcquisitionMethod() AcquisitionMethod {
	if e.IsLocked {
		return MethodRaw
	}
	return MethodOS
}

// HasUserPlaceholder は Path に {user} が含まれるか返す。
func HasUserPlaceholder(Path string) bool {
	return strings.Contains(Path, "{user}")
}

// ExpandUserPath は Path の {user} を展開した文字列を返す。
func (cfg *Config) ExpandUserPath(path, user string) string {
	return strings.ReplaceAll(path, "{user}", user)
}

// IsExcludedUser は username が除外リストに含まれるか返す (大文字小文字無視)。
func (cfg *Config) IsExcludedUser(username string) bool {
	lower := strings.ToLower(username)
	for _, ex := range cfg.ExcludeUsers {
		if strings.ToLower(ex) == lower {
			return true
		}
	}
	return false
}

// ── 内部ユーティリティ ────────────────────────────────────────────────────────

// splitCSVLine はカンマ区切りで分割する。引用符は非対応 (単純実装)。
func splitCSVLine(line string) []string {
	parts := strings.Split(line, ",")
	return parts
}
