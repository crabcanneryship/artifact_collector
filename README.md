# forensic-collector

Collects essencial forensic artifacts from Windows. Linux and others will be added in the future.

## Artifatcs (by default, being fixed
$MFT
UsnJrnl
EventLog
HKLM Registry Hives (SAM, SECURITY, SOFTWARE, SYSTEM)
HKCU Registry Hives (NTUSER.dat, UsrClass.dat)
Web History such as Chrome and Edge
etc.

### How to build
go build -o artifact_collector.exe ./cmd
### Linux/Mac
GOOS=windows GOARCH=amd64 go build -o artifact_collector.exe ./cmd

## Execution
# Administrator rights and public RSA key (.pem) needed
# base command to collect pre-defined artifacts
.\artifact_collector.exe
# example of using options (collecting memory, customizing artifacts, reporting in JSON format)
.\artifact_collector.exe -mem -config artifacts.csv -json

## Flags
| Flag | Default | Description |
|---|---|---|
| -config | <pre defined> | extraordinary paths are needed to be collected (e.g. D is used as System disk, backup evtx files exist) |
| -hash | true | calculats and report SHA256 hash |
| -json | false | export JSON log |
| -verbose | false | shows debug log message on the console |

## OUTPUT
<executing directory>\<machine name>_<timestamp>.bin
# files will be stored in a format like below

## Structure
artifact_collector/
├── go.mod
└── internal/
    ├── ntfs/
    │   ├── volume.go      # Raw Volume処理
    ├── collector/
    │   └── collector.go   # アーティファクト収集
    ├── crypto/
    │   └── crypto.go      # 暗号化
    ├── hasher/
    │   └── hasher.go      # SHA256Hash生成
    ├── memory/
    │   └── memory.go      # メモリーダンプ収集
    │   └── winpmem.go     # winpmem呼出
    ├── privilege/
    │   ├── privilege.go   # SeBackupPrivilege 有効化
    └── report/
        └── report.go      # generates report(s) in TXT and JSON
├── main.go                # entry point for CLI
└── tools
    └── decrypt/
        └── main.go        # decrypts encrypted result file
```

## 依存ライブラリ
| package | usage |
|---|---|
| `golang.org/x/sys/windows` | Win32 API (CreateFile, DeviceIoControl, etc.) |
| 標準ライブラリのみ | その他すべて |
