//go:build linux

package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
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
func configureTUN(name, ip string, prefix int) error {
	address, e := netip.ParseAddr(ip)
	if e != nil || !address.Is4() {
		return fmt.Errorf("invalid mesh IPv4 address %q", ip)
	}
	network := netip.PrefixFrom(address, prefix).Masked().String()
	run := func(args ...string) error {
		if out, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
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
	return run("route", "replace", network, "dev", name, "scope", "link", "src", ip, "table", "main")
}
