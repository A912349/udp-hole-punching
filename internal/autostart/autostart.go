// Package autostart installs per-user startup entries for the mesh programs.
package autostart

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func Install(name string, args []string, env []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	work, _ := filepath.Abs(filepath.Dir(exe))
	logPath := filepath.Join(configDir(name), name+".log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		cmdline := quote(exe) + " " + joinArgs(args)
		// HKCU Run needs no administrator rights and survives normal logins.
		return exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", name, "/t", "REG_SZ", "/d", `cmd.exe /d /c "`+cmdline+` >> "`+logPath+`" 2>&1"`, "/f").Run()
	}
	if runtime.GOOS == "darwin" {
		dir := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		p := filepath.Join(dir, "com.mesh."+name+".plist")
		items := append([]string{exe}, args...)
		items = append(items, "")
		data := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>com.mesh." + name + "</string><key>ProgramArguments</key><array>"
		for _, v := range items[:len(items)-1] {
			data += "<string>" + xmlEscape(v) + "</string>"
		}
		data += "</array><key>WorkingDirectory</key><string>" + xmlEscape(work) + "</string><key>StandardOutPath</key><string>" + xmlEscape(logPath) + "</string><key>StandardErrorPath</key><string>" + xmlEscape(logPath) + "</string><key>RunAtLoad</key><true/></dict></plist>\n"
		return os.WriteFile(p, []byte(data), 0600)
	}
	// Linux and other Unix systems: always install a system-wide unit.
	// This deliberately avoids systemd --user, which is unavailable in many
	// containers and is unsuitable for a root-managed mesh service.
	dir := "/etc/systemd/system"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	unit := "[Unit]\nDescription=Mesh " + name + "\nAfter=network-online.target\n\n[Service]\nWorkingDirectory=" + escapeUnit(work) + "\nExecStart=" + quote(exe) + " " + joinArgs(args) + "\nRestart=always\nRestartSec=5\nStandardOutput=append:" + logPath + "\nStandardError=append:" + logPath + "\n"
	for _, item := range env {
		if strings.HasPrefix(item, "MESH_") {
			if i := strings.IndexByte(item, '='); i > 5 {
				unit += "Environment=\"" + strings.ReplaceAll(item, `"`, `\"`) + "\"\n"
			}
		}
	}
	unit += "\n[Install]\nWantedBy=default.target\n"
	path := filepath.Join(dir, "mesh-"+name+".service")
	if err := os.WriteFile(path, []byte(unit), 0600); err != nil {
		return err
	}
	unitName := "mesh-" + name + ".service"
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return exec.Command("systemctl", "enable", "--now", unitName).Run()
}

func Remove(name string) error {
	if runtime.GOOS == "windows" {
		return exec.Command("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", name, "/f").Run()
	}
	if runtime.GOOS == "darwin" {
		return os.Remove(filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", "com.mesh."+name+".plist"))
	}
	unit := "mesh-" + name + ".service"
	_ = exec.Command("systemctl", "disable", "--now", unit).Run()
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return os.Remove(filepath.Join("/etc/systemd/system", unit))
}

func configDir(name string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "Mesh", "logs")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "mesh", "logs")
}
func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }
func joinArgs(a []string) string {
	out := make([]string, len(a))
	for i, v := range a {
		out[i] = quote(v)
	}
	return strings.Join(out, " ")
}
func escapeUnit(s string) string { return strings.ReplaceAll(s, " ", `\x20`) }
func xmlEscape(s string) string  { b, _ := xml.Marshal(s); return strings.Trim(string(b), `"`) }
