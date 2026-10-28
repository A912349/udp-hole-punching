//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// cleanupUpdateBackup removes leftovers from a previous Windows-style update.
// Unix updates replace the executable atomically in place, so there is no
// backup file to clean.
func cleanupUpdateBackup() {}

// swapAndRestart atomically replaces the executable at the SAME path and then
// re-executes the new image in-place (same PID, same command line, open
// sockets closed by the exec). Renaming over a running binary is allowed on
// Linux/macOS/BSDs, and because the path never changes, systemd units,
// procd/OpenWrt init scripts, cron @reboot entries and every other autostart
// mechanism keep working unchanged.
func swapAndRestart(tmp, exe string) error {
	if err := os.Rename(tmp, exe); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	syncDir(filepath.Dir(exe))
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		return fmt.Errorf("restart with new binary: %w", err)
	}
	return nil
}

// syncDir flushes the directory entry so the new binary survives a power cut.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}
