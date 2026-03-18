//go:build windows

package privilege

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EnableBackupPrivilege は SeBackupPrivilege / SeSecurityPrivilege / SeRestorePrivilege を
// 現在のプロセストークンで有効化する。
// Raw Volume アクセスに SeBackupPrivilege が必要。
func EnableBackupPrivilege() error {
	privs := []string{
		"SeBackupPrivilege",
		"SeSecurityPrivilege",
		"SeRestorePrivilege",
	}

	// 現在のプロセストークンを取得
	var token windows.Token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken 失敗: %w", err)
	}
	defer token.Close()

	for _, name := range privs {
		if err := enablePrivilege(token, name); err != nil {
			// 一部の権限は環境によって存在しないため警告のみ
			fmt.Printf("[!] %s の有効化をスキップ: %v\n", name, err)
		}
	}
	return nil
}

func enablePrivilege(token windows.Token, name string) error {
	var luid windows.LUID
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp,
		uint32(unsafe.Sizeof(tp)), nil, nil)
}
