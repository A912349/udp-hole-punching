//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const updateBackupSuffix = ".old"

// cleanupUpdateBackup removes the previous version left behind by the last
// self-update. The running executable was renamed to "<name>.old" during the
// swap, so the next start (which is already the new binary) deletes it.
func cleanupUpdateBackup() {
	exe, err := executablePath()
	if err != nil {
		return
	}
	_ = os.Remove(exe + updateBackupSuffix)
}

// swapAndRestart installs the downloaded binary at the same path and starts
// it as a new process. Windows refuses to overwrite or delete a running
// executable but allows renaming it, so the running image is moved aside and
// the new file takes its place under the ORIGINAL name: autostart entries
// (HKCU Run, scheduled tasks, service wrappers) keep pointing at the
// unchanged path and launch the new version. If starting the new process
// fails, the old binary is moved back so the node stays runnable.
func swapAndRestart(tmp, exe string) error {
	backup := exe + updateBackupSuffix
	_ = os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		return fmt.Errorf("move running executable aside: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(backup, exe)
		return fmt.Errorf("install new executable: %w", err)
	}
	attr := &os.ProcAttr{
		Dir:   filepath.Dir(exe),
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}
	proc, err := os.StartProcess(exe, os.Args, attr)
	if err != nil {
		_ = os.Rename(exe, tmp)
		_ = os.Rename(backup, exe)
		return fmt.Errorf("start updated process: %w", err)
	}
	_ = proc.Release()
	// Give the new process time to bind its ports before the old one exits,
	// then leave the rest to it. The leftover .old file is removed on the
	// next start.
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
	return nil
}
