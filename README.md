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

## How to build
# Windows
```
go build -o artifact_collector.exe            # collector
go build -o decryptor.exe ./tools/decrypt/    # decryptor
```
# Linux/Mac
```
GOOS=windows GOARCH=amd64 go build -o artifact_collector.exe           # collector
GOOS=windows GOARCH=amd64 go build -o decryptor.exe ./tools/decrypt    # decryptor
```

## Execution
# Administrator rights and public RSA key (.pem) needed
# base command to collect pre-defined artifacts
```
.\artifact_collector.exe
```
# example of using options (collecting memory, customizing artifacts, reporting in JSON format)
```
.\artifact_collector.exe -mem -config artifacts.csv -json
```

## Flags
| Flag | Default | Description |
|---|---|---|
| -config | <pre defined> | extraordinary paths are needed to be collected (e.g. D is used as System disk, backup evtx files exist) |
| -hash | true | calculats and report SHA256 hash |
| -json | false | export JSON log |
| -verbose | false | shows debug log message on the console |

## OUTPUT
# general
```
<executing directory>\<machine name>_<timestamp>.bin
```
# using -mem option (separate file is generated)
```
<executing directory>\<machine name>_<timestamp>_memory.bin
```

## Structure
```
artifact_collector/
├── go.mod
└── internal/
    ├── ntfs/
    │   ├── volume.go      # handles Raw Volume
    ├── collector/
    │   └── collector.go   # collects artifacts
    ├── crypto/
    │   └── crypto.go      # crypts the result
    ├── hasher/
    │   └── hasher.go      # generates SHA256 hash
    ├── memory/
    │   └── memory.go      # dumps memory 
    │   └── winpmem.go     # handles winpmem (winpmem_mini_x64.exe needed)
    ├── privilege/
    │   ├── privilege.go   # enables SeBackupPrivilege
    └── report/
        └── report.go      # generates report(s) in TXT and JSON
├── main.go                # entry point for CLI
└── tools
    └── decrypt/
        └── main.go        # decrypts encrypted result file
```

## Dependencies
| package | usage |
|---|---|
| `golang.org/x/sys/windows` | Win32 API (CreateFile, DeviceIoControl, etc.) |
| standard libraries | all others |


## Key generation
# PowerShell
```
$rsa = [System.Security.Cryptography.RSA]::Create(4096)

# secret key
$privBytes = $rsa.ExportRSAPrivateKey()
$privB64 = [Convert]::ToBase64String($privBytes)
"-----BEGIN RSA PRIVATE KEY-----`n" + ($privB64 -replace '.{64}', "$&`n") + "`n-----END RSA PRIVATE KEY-----" | Out-File private.pem -Encoding ascii

# public key
$pubBytes = $rsa.ExportSubjectPublicKeyInfo()
$pubB64 = [Convert]::ToBase64String($pubBytes)
"-----BEGIN PUBLIC KEY-----`n" + ($pubB64 -replace '.{64}', "$&`n") + "`n-----END PUBLIC KEY-----" | Out-File public.pem -Encoding ascii
```

# bash
```
# secret key
openssl genrsa -out private.pem 4096

# public key from secret key
openssl rsa -in private.pem -pubout -out public.pem
```

# files generated
- `private.pem`: PKCS#8 secret key (keep secure in a lab environment for decryption)
- `public.pem`: PKIX/SubjectPublicKeyInfo public key (deliver with the collector)


## Decryption
```
decryptor.exe -key private.pem -in HOST_20261212121212.bin -out HOST                 # Windows artifacts in a directory, following structures as it was e.g. HOST\C\Windows\System32\winevtx\Logs\Security.evtx
decryptor.exe -key private.pem -in HOST_20261212121212_memory.bin -out memory.raw    # memory dump
```
