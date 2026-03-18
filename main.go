// artifact_collector v2.7.0 (Go版)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"artifact_collector/internal/collector"
	"artifact_collector/internal/config"
	"artifact_collector/internal/crypto"
	"artifact_collector/internal/memory"
	"artifact_collector/internal/privilege"
	"artifact_collector/internal/report"
)

func main() {

	configFile := flag.String("config", "", "アーティファクト定義CSVファイルのパス (デフォルト: 内部定義)")
	outputDir := flag.String("output", "", "出力ディレクトリ (デフォルト: カレントディレクトリ)")
	doHash := flag.Bool("hash", true, "SHA-256ハッシュを計算する")
	jsonReport := flag.Bool("json-report", false, "JSONレポートを追加出力する")
	doMemory := flag.Bool("mem", false, "メモリダンプを取得する (winpmem.exe が同ディレクトリに必要)")
	verbose := flag.Bool("verbose", false, "詳細ログを表示する")
	flag.Parse()

	if *verbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	} else {
		log.SetOutput(discard{})
	}

	// ── 公開鍵を自動検索 ──────────────────────────────────────────────────────
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	pub, pemPath, err := crypto.FindPublicKey(exeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		fmt.Fprintf(os.Stderr, "        RSA公開鍵PEMファイルを artifact_collector.exe と同じディレクトリに配置してください。\n")
		os.Exit(1)
	}
	log.Printf("[D] 公開鍵: %s", pemPath)

	// ── セッション情報 ────────────────────────────────────────────────────────
	ts := time.Now().Format("20060102150405")
	hostname, _ := os.Hostname()
	sessionName := fmt.Sprintf("%s_%s", hostname, ts)

	outDir := *outputDir
	if outDir == "" {
		outDir = "."
	}
	artifactsBin := filepath.Join(outDir, sessionName+"_artifacts.bin")

	// ── 設定読み込み ──────────────────────────────────────────────────────────
	cfg := config.New()
	if *configFile != "" {
		cfg, err = config.Load(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] 設定ファイル読み込み失敗: %v\n", err)
			os.Exit(1)
		}
	}

	// ── 権限取得 ──────────────────────────────────────────────────────────────
	if err := privilege.EnableBackupPrivilege(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 管理者権限が必要です: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("artifact_collector  host=%s \n", hostname)
	fmt.Printf("  artifacts → %s\n", artifactsBin)
	if *doMemory {
		fmt.Printf("  memory    → %s_memory.bin\n", filepath.Join(outDir, sessionName))
	}
	fmt.Println()

	// ── メモリダンプ (アーティファクトより先に取得) ───────────────────────────
	rep := report.New(sessionName)
	if *doMemory {
		fmt.Println("[MEM] メモリダンプ取得中...")
		dumpBase := filepath.Join(outDir, sessionName+"_memory")
		result, err := memory.AcquireAndEncrypt(pemPath, dumpBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ メモリダンプ失敗: %v\n", err)
			rep.AddMemoryDumpSkipped(err.Error())
		} else {
			fmt.Printf("  ✓ %s  %.1fs\n\n", result.BinFile, result.ElapsedSec)
			rep.AddMemoryDumpSuccess(result.BinFile, 0, result.ElapsedSec)
		}
	}

	// ── アーティファクト収集 ──────────────────────────────────────────────────
	fmt.Println("[COLLECT] アーティファクト収集中...")
	ew, err := crypto.NewEncWriter(artifactsBin, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 暗号化ファイル作成失敗: %v\n", err)
		os.Exit(1)
	}

	col := collector.New(*doHash, ew)
	for _, entry := range cfg.Entries {
		results, err := col.CollectEntry(cfg, entry)
		label := fmt.Sprintf("[%s] %s", entry.Type, entry.Path)
		if err != nil {
			fmt.Printf("  ✗ %s\n      %v\n", label, err)
			rep.AddFailure(entry, err.Error())
			continue
		}
		if len(results) == 0 {
			fmt.Printf("  ~ %s  (スキップ: ファイルなし)\n", label)
			rep.AddSkipped(entry)
			continue
		}
		fmt.Printf("  ✓ %s  %d ファイル\n", label, len(results))
		rep.AddSuccess(entry, results)
	}
	col.Close()
	fmt.Println()

	// ── レポート ──────────────────────────────────────────────────────────────
	rep.PrintSummary()
	if err := ew.WriteEntry("collection_report.txt", rep.ToTextBytes()); err != nil {
		fmt.Fprintf(os.Stderr, "  ! レポート書き込み失敗: %v\n", err)
	}
	if *jsonReport {
		if b, err := rep.ToJSONBytes(); err == nil {
			ew.WriteEntry("collection_report.json", b)
		}
	}

	if err := ew.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 暗号化ファイル確定失敗: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[DONE] %s\n", artifactsBin)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
