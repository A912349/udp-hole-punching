//go:build linux

package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
)

func openTUN(name string) (*os.File, error) {
	if len(name) == 0 || len(name) > 15 {
		return nil, fmt.Errorf("TUN interface name must be 1..15 bytes")
	}
	f, e := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	var req [18]byte
	copy(req[:16], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = iffTUN | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		f.Close()
		return nil, errno
	}
	return f, nil
}

// readTUN deliberately bypasses os.File.Read. Go's runtime poller rejects
// some /dev/net/tun implementations with "not pollable", while the raw Linux
// read(2) syscall is valid and blocks until the kernel supplies an IP frame.
func readTUN(file *os.File, buffer []byte) (int, error) {
	return syscall.Read(int(file.Fd()), buffer)
}

func configureTUN(name, ip string, prefix int) error {
	address, e := netip.ParseAddr(ip)
	if e != nil || !address.Is4() {
		return fmt.Errorf("invalid mesh IPv4 address %q", ip)
	}
	network := netip.PrefixFrom(address, prefix).Masked().String()
	ipCommand, e := findIPCommand()
	if e != nil {
		return e
	}
	run := func(args ...string) error {
		if out, e := exec.Command(ipCommand, args...).CombinedOutput(); e != nil {
			return fmt.Errorf("ip %v: %s", args, string(out))
		}
		return nil
	}
	if e = run("link", "set", "dev", name, "mtu", "1279", "up"); e != nil {
		return e
	}
	if e = run("addr", "replace", fmt.Sprintf("%s/%d", ip, prefix), "dev", name); e != nil {
		return e
	}
	route := []string{"route", "replace", network, "dev", name, "scope", "link", "src", ip}
	if e = run(append(route, "table", "main")...); e != nil {
		return e
	}
	// Android/Termux can route normal traffic through an rmnet policy table.
	// Add the same narrow mesh route there without ever changing a default route.
	if output, err := exec.Command(ipCommand, "route", "get", "1.1.1.1").Output(); err == nil {
		if _, table, found := strings.Cut(string(output), " table "); found {
			table = strings.Fields(table)[0]
			if table != "main" && table != "local" {
				return run(append(route, "table", table)...)
			}
		}
	}
	return nil
}

func configureTUNRoutes(name string, wanted, installed map[string]bool) error {
	ipCommand, err := findIPCommand()
	if err != nil {
		return err
	}
	run := func(args ...string) error {
		if out, e := exec.Command(ipCommand, args...).CombinedOutput(); e != nil {
			return fmt.Errorf("ip %v: %s", args, string(out))
		}
		return nil
	}
	for route := range installed {
		if !wanted[route] {
			if err := run("route", "del", route, "dev", name); err != nil {
				return err
			}
		}
	}
	for route := range wanted {
		if err := run("route", "replace", route, "dev", name); err != nil {
			return err
		}
	}
	return nil
}

func findIPCommand() (string, error) {
	if path, err := exec.LookPath("ip"); err == nil {
		return path, nil
	}
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "ip")
		if _, err = os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	for _, candidate := range []string{"/sbin/ip", "/usr/sbin/ip"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("iproute2 command 'ip' was not found")
}
