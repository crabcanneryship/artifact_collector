// Package report は収集結果レポートを生成する。
//
// v2.0: CSVconfig対応。EntryResult (1エントリの収集結果) を単位として管理。
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"artifact_collector/internal/collector"
	"artifact_collector/internal/config"
)

// ── エントリ結果型 ────────────────────────────────────────────────────────────

type entryStatus int

const (
	statusSuccess entryStatus = iota
	statusPartial             // 一部ファイルの収集失敗
	statusSkipped             // 0件
	statusFailure
)

// EntryResult は config.Entry 1行分の収集結果をまとめる。
type EntryResult struct {
	Entry   config.Entry
	Status  entryStatus
	Results []collector.CollectionResult
	ErrMsg  string
}

// ── Report ────────────────────────────────────────────────────────────────────

// Report は収集セッション全体の結果を保持する。
type Report struct {
	timestamp string
	hostname  string
	entries   []EntryResult
	memDump   *memoryDumpInfo // nil = スキップ指定 (-no-memory)
}

// New は Report を生成する。
func New(timestamp string) *Report {
	hostname, _ := os.Hostname()
	return &Report{timestamp: timestamp, hostname: hostname}
}

// ── Add メソッド ──────────────────────────────────────────────────────────────

func (r *Report) AddSuccess(entry config.Entry, results []collector.CollectionResult) {
	r.entries = append(r.entries, EntryResult{
		Entry:   entry,
		Status:  statusSuccess,
		Results: results,
	})
}

func (r *Report) AddPartial(entry config.Entry, results []collector.CollectionResult, errMsg string) {
	r.entries = append(r.entries, EntryResult{
		Entry:   entry,
		Status:  statusPartial,
		Results: results,
		ErrMsg:  errMsg,
	})
}

func (r *Report) AddSkipped(entry config.Entry) {
	r.entries = append(r.entries, EntryResult{
		Entry:  entry,
		Status: statusSkipped,
	})
}

func (r *Report) AddFailure(entry config.Entry, errMsg string) {
	r.entries = append(r.entries, EntryResult{
		Entry:  entry,
		Status: statusFailure,
		ErrMsg: errMsg,
	})
}

// ── 集計 ──────────────────────────────────────────────────────────────────────

func (r *Report) totalFiles() int {
	n := 0
	for _, e := range r.entries {
		n += len(e.Results)
	}
	return n
}

func (r *Report) countByStatus(s entryStatus) int {
	n := 0
	for _, e := range r.entries {
		if e.Status == s {
			n++
		}
	}
	return n
}

func totalBytes(results []collector.CollectionResult) uint64 {
	var t uint64
	for _, r := range results {
		t += r.BytesCopied
	}
	return t
}

// ── コンソール出力 ────────────────────────────────────────────────────────────

func (r *Report) PrintSummary() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║                   収集完了サマリー                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  ホスト名       : %s\n", r.hostname)
	if r.memDump != nil {
		if r.memDump.success {
			fmt.Printf("  メモリダンプ   : ✓ %s (%s / %.1f秒)\n",
				r.memDump.zipEntry, formatBytes(r.memDump.bytes), r.memDump.elapsedSec)
		} else {
			fmt.Printf("  メモリダンプ   : ✗ 失敗 (%s)\n", r.memDump.errMsg)
		}
	} else {
		fmt.Printf("  メモリダンプ   : - スキップ (-no-memory)\n")
	}
	fmt.Printf("  収集日時       : %s\n", r.timestamp)
	fmt.Printf("  対象数         : %d 件\n", len(r.entries))
	fmt.Printf("  成功       : %d 件 (%d ファイル)\n",
		r.countByStatus(statusSuccess)+r.countByStatus(statusPartial), r.totalFiles())
	if r.countByStatus(statusSkipped) > 0 {
		fmt.Printf("  スキップ       : %d 件 (ファイルなし)\n", r.countByStatus(statusSkipped))
	}
	if r.countByStatus(statusFailure) > 0 {
		fmt.Printf("  失敗           : %d 件\n", r.countByStatus(statusFailure))
	}
	fmt.Println()

	for _, e := range r.entries {
		switch e.Status {
		case statusSuccess:
			icon := "✓"
			typeLabel := string(e.Entry.Type)
			fmt.Printf("  %s [%s] %s\n", icon, typeLabel, e.Entry.Path)
			fmt.Printf("      %d ファイル / %s\n", len(e.Results), formatBytes(totalBytes(e.Results)))
		case statusPartial:
			fmt.Printf("  △ [%s] %s\n", e.Entry.Type, e.Entry.Path)
			fmt.Printf("      %d ファイル収集 (一部失敗: %s)\n", len(e.Results), e.ErrMsg)
		case statusSkipped:
			fmt.Printf("  ~ [%s] %s — ファイルなし\n", e.Entry.Type, e.Entry.Path)
		case statusFailure:
			fmt.Printf("  ✗ [%s] %s\n", e.Entry.Type, e.Entry.Path)
			fmt.Printf("      エラー: %s\n", e.ErrMsg)
		}
	}
	fmt.Println()
}

// ── テキストレポート ──────────────────────────────────────────────────────────

func (r *Report) writeText(w io.Writer) {
	fmt.Fprintln(w, "Artifact Collection Report")
	fmt.Fprintln(w, "==========================")
	fmt.Fprintf(w, "Hostname   : %s\n", r.hostname)
	fmt.Fprintf(w, "Timestamp  : %s\n", r.timestamp)
	fmt.Fprintf(w, "Generated  : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Entries    : %d total / %d success / %d skip / %d fail\n\n",
		len(r.entries),
		r.countByStatus(statusSuccess)+r.countByStatus(statusPartial),
		r.countByStatus(statusSkipped),
		r.countByStatus(statusFailure),
	)
	fmt.Fprintln(w, "--------------------------")

	for _, e := range r.entries {
		recursive := "NO"
		if e.Entry.Recursive {
			recursive = "YES"
		}
		switch e.Status {
		case statusSuccess, statusPartial:
			statusStr := "SUCCESS"
			if e.Status == statusPartial {
				statusStr = "PARTIAL"
			}
			fmt.Fprintf(w, "[%s] %s / %s\n", statusStr, e.Entry.Type)
			fmt.Fprintf(w, "  Path      : %s\n", e.Entry.Path)
			fmt.Fprintf(w, "  Recursive : %s\n", recursive)
			fmt.Fprintf(w, "  Files     : %d (%s total)\n", len(e.Results), formatBytes(totalBytes(e.Results)))
			if e.ErrMsg != "" {
				fmt.Fprintf(w, "  Warning   : %s\n", e.ErrMsg)
			}
			for _, res := range e.Results {
				if res.SHA256 != "" {
					fmt.Fprintf(w, "    - %s (%s)  %s\n",
						filepath.Base(res.OutputPath), formatBytes(res.BytesCopied), res.SHA256)
				} else {
					fmt.Fprintf(w, "    - %s (%s)\n",
						filepath.Base(res.OutputPath), formatBytes(res.BytesCopied))
				}
			}
		case statusSkipped:
			fmt.Fprintf(w, "[SKIPPED] %s\n", e.Entry.Type)
			fmt.Fprintf(w, "  Path : %s\n", e.Entry.Path)
		case statusFailure:
			fmt.Fprintf(w, "[FAILED] %s\n", e.Entry.Type)
			fmt.Fprintf(w, "  Path  : %s\n", e.Entry.Path)
			fmt.Fprintf(w, "  Error : %s\n", e.ErrMsg)
		}
		fmt.Fprintln(w)
	}
}

func (r *Report) SaveText(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r.writeText(f)
	return nil
}

func (r *Report) ToTextBytes() []byte {
	var buf bytes.Buffer
	r.writeText(&buf)
	return buf.Bytes()
}

// ── JSONレポート ──────────────────────────────────────────────────────────────

func (r *Report) writeJSON(w io.Writer) error {
	type fileEntry struct {
		Name     string `json:"name"`
		Source   string `json:"source"`
		ZipEntry string `json:"zip_entry"`
		Bytes    uint64 `json:"bytes"`
		SHA256   string `json:"sha256,omitempty"`
	}
	type entryJSON struct {
		Type      string      `json:"type"`
		Recursive bool        `json:"recursive"`
		Category  string      `json:"category"`
		Path      string      `json:"path"`
		Status    string      `json:"status"`
		Files     []fileEntry `json:"files,omitempty"`
		Error     string      `json:"error,omitempty"`
	}
	type rootJSON struct {
		Report struct {
			Hostname   string `json:"hostname"`
			Timestamp  string `json:"timestamp"`
			Volume     string `json:"volume"`
			Entries    int    `json:"entries"`
			TotalFiles int    `json:"total_files"`
		} `json:"report"`
		Artifacts []entryJSON `json:"artifacts"`
	}

	var root rootJSON
	root.Report.Hostname = r.hostname
	root.Report.Timestamp = r.timestamp
	root.Report.Entries = len(r.entries)
	root.Report.TotalFiles = r.totalFiles()

	for _, e := range r.entries {
		statusStr := map[entryStatus]string{
			statusSuccess: "success",
			statusPartial: "partial",
			statusSkipped: "skipped",
			statusFailure: "failed",
		}[e.Status]

		ej := entryJSON{
			Type:      string(e.Entry.Type),
			Recursive: e.Entry.Recursive,
			Path:      e.Entry.Path,
			Status:    statusStr,
			Error:     e.ErrMsg,
		}
		for _, res := range e.Results {
			ej.Files = append(ej.Files, fileEntry{
				Name:     filepath.Base(res.OutputPath),
				Source:   res.SourcePath,
				ZipEntry: res.OutputPath,
				Bytes:    res.BytesCopied,
				SHA256:   res.SHA256,
			})
		}
		root.Artifacts = append(root.Artifacts, ej)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}

func (r *Report) SaveJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.writeJSON(f)
}

func (r *Report) ToJSONBytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := r.writeJSON(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── ヘルパー ──────────────────────────────────────────────────────────────────

func formatBytes(b uint64) string {
	const (
		KB = uint64(1024)
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", b)
	}
}

// ── メモリダンプ記録 (v2.3追加) ──────────────────────────────────────────────

// memoryDumpInfo はメモリダンプの取得結果。
type memoryDumpInfo struct {
	success    bool
	zipEntry   string
	bytes      uint64
	elapsedSec float64
	errMsg     string
}

// AddMemoryDumpSuccess はメモリダンプ成功を記録する。
func (r *Report) AddMemoryDumpSuccess(zipEntry string, bytes uint64, elapsedSec float64) {
	r.memDump = &memoryDumpInfo{
		success:    true,
		zipEntry:   zipEntry,
		bytes:      bytes,
		elapsedSec: elapsedSec,
	}
}

// AddMemoryDumpSkipped はメモリダンプ失敗/スキップを記録する。
func (r *Report) AddMemoryDumpSkipped(errMsg string) {
	r.memDump = &memoryDumpInfo{success: false, errMsg: errMsg}
}
