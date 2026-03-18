# forensic-collector (Go版)

Raw Volume 読み取り (NTFS直接解析) でライブWindows環境からアーティファクトを収集する。

## 収集対象

| アーティファクト | パス |
|---|---|
| **$MFT** | `C:\$MFT` |
| **Security.evtx** | `C:\Windows\System32\winevt\Logs\Security.evtx` |
| **SYSTEM** | `C:\Windows\System32\config\SYSTEM` |

## 収集方式

```
\\.\C: を FILE_FLAG_NO_BUFFERING で開く
        ↓
FSCTL_GET_NTFS_VOLUME_DATA でボリューム情報取得
        ↓
$MFT (inode 0) のデータランから MFT 全体を読み込む
        ↓
MFT を線形走査して目的ファイルの inode を解決
 └─ $FILE_NAME 属性の親 inode + ファイル名 (大小文字無視) で照合
        ↓
inode の $DATA 属性からファイル内容を取得
 ├─ 非常駐: データランを辿りクラスタ単位で読む (断片化対応)
 └─ 常駐:  レコード内埋め込みデータを返す
```

## ビルド

### Windows 上でビルド

```powershell
go build -o forensic-collector.exe ./cmd
```

### クロスコンパイル (Linux/Mac → Windows)

```bash
GOOS=windows GOARCH=amd64 go build -o forensic-collector.exe ./cmd
```

## 実行

> **⚠️ 管理者権限 (Administrator) で実行してください**

```powershell
# 基本実行
.\forensic-collector.exe

# 出力先・オプション指定
.\forensic-collector.exe -output D:\evidence -hash -json

# 別ボリューム
.\forensic-collector.exe -volume D: -output D:\evidence
```

## フラグ

| フラグ | デフォルト | 説明 |
|---|---|---|
| `-output <DIR>` | `.\forensic_output_<timestamp>` | 出力先ディレクトリ |
| `-volume <VOL>` | `C:` | 収集対象ボリューム |
| `-hash` | `true` | SHA-256 ハッシュを計算 |
| `-json` | `false` | JSON レポートを追加出力 |
| `-verbose` | `false` | デバッグログを表示 |

## 出力ファイル

```
forensic_output_20240101_120000\
├── MFT                      ← $MFT のコピー
├── Security.evtx            ← セキュリティイベントログ
├── SYSTEM                   ← SYSTEM レジストリハイブ
├── collection_report.txt    ← テキストレポート
└── collection_report.json   ← JSON レポート (-json 指定時)
```

## プロジェクト構成

```
forensic-collector-go/
├── go.mod
├── cmd/
│   ├── main.go          # エントリポイント・CLI
│   └── platform.go      # OS判定
└── internal/
    ├── ntfs/
    │   ├── volume_windows.go  # Raw Volume / NTFS パーサ
    │   └── volume_other.go    # 非Windows スタブ
    ├── collector/
    │   └── collector.go       # アーティファクト収集
    ├── hasher/
    │   └── hasher.go          # SHA-256
    ├── privilege/
    │   ├── privilege_windows.go  # SeBackupPrivilege 有効化
    │   └── privilege_other.go    # 非Windows スタブ
    └── report/
        └── report.go          # TXT / JSON レポート
```

## 依存ライブラリ

| パッケージ | 用途 |
|---|---|
| `golang.org/x/sys/windows` | Win32 API (CreateFile, DeviceIoControl, etc.) |
| 標準ライブラリのみ | その他すべて |
