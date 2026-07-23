//go:build linux

package main

import (
	"fmt"
	"net"
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
func readTUN(device tunDevice, buffer []byte) (int, error) {
	file, ok := device.(*os.File)
	if !ok {
		return 0, fmt.Errorf("unexpected Linux TUN implementation %T", device)
	}
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
	policyTable := ""
	if output, e := exec.Command(ipCommand, "route", "get", "1.1.1.1").Output(); e == nil {
		if _, table, found := strings.Cut(string(output), " table "); found {
			fields := strings.Fields(table)
			if len(fields) > 0 && fields[0] != "main" && fields[0] != "local" {
				policyTable = fields[0]
			}
		}
	}
	for route := range installed {
		if !wanted[route] {
			if err := run("route", "del", route, "dev", name); err != nil {
				return err
			}
			if policyTable != "" {
				_ = run("route", "del", route, "dev", name, "table", policyTable)
			}
		}
	}
	for route := range wanted {
		if err := run("route", "replace", route, "dev", name); err != nil {
			return err
		}
		if policyTable != "" {
			if err := run("route", "replace", route, "dev", name, "table", policyTable); err != nil {
				return err
			}
		}
	}
	return nil
}

// configureSystemDNS integrates the mesh resolver with systemd-resolved when
// available. It is deliberately best-effort: distributions without
// resolvectl can still use the listener through a local DNS forwarder.
func configureSystemDNS(iface, meshIP, dnsTarget string) error {
	if dnsTarget == "" {
		return nil
	}
	// systemd-resolved accepts an address but not a custom DNS port. A
	// loopback fallback therefore needs a local forwarder such as dnsmasq;
	// never point resolved at 127.0.0.1:53 when our listener is on another port.
	if strings.HasPrefix(dnsTarget, "127.0.0.1#") {
		return configureFallbackDNS(meshIP, dnsTarget)
	}
	if iface == "" || meshIP == "" {
		return configureFallbackDNS(meshIP, dnsTarget)
	}
	resolvectl, err := exec.LookPath("resolvectl")
	if err != nil {
		return configureFallbackDNS(meshIP, dnsTarget)
	}
	if out, err := exec.Command(resolvectl, "dns", iface, meshIP).CombinedOutput(); err != nil {
		if fallbackErr := configureFallbackDNS(meshIP, dnsTarget); fallbackErr == nil {
			return nil
		}
		return fmt.Errorf("resolvectl dns: %s", string(out))
	}
	if out, err := exec.Command(resolvectl, "domain", iface, "~mesh", "mesh").CombinedOutput(); err != nil {
		if fallbackErr := configureFallbackDNS(meshIP, dnsTarget); fallbackErr == nil {
			return nil
		}
		return fmt.Errorf("resolvectl domain: %s", string(out))
	}
	return nil
}

func configureFallbackDNS(meshIP, dnsTarget string) error {
	if strings.HasPrefix(dnsTarget, "127.0.0.1#") {
		if dirInfo, e := os.Stat("/etc/dnsmasq.d"); e == nil && dirInfo.IsDir() {
			path := filepath.Join("/etc/dnsmasq.d", "mesh-node.conf")
			if e = os.WriteFile(path, []byte("server=/mesh/"+dnsTarget+"\n"), 0644); e == nil {
				if _, e = exec.Command("pkill", "-HUP", "-x", "dnsmasq").CombinedOutput(); e == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("local DNS listener %s requires dnsmasq forwarding", dnsTarget)
	}
	info, statErr := os.Lstat("/etc/resolv.conf")
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	data, readErr := os.ReadFile("/etc/resolv.conf")
	if readErr != nil {
		return readErr
	}
	nameserver := meshIP
	if nameserver == "" {
		host, _, err := net.SplitHostPort(dnsTarget)
		if err != nil {
			return err
		}
		nameserver = host
	}
	text := string(data)
	if strings.Contains(text, "nameserver "+nameserver) {
		return nil
	}
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver "+nameserver+"\nsearch mesh\n"+text), 0644); err != nil {
		return err
	}
	return nil
}

// configureSiteNAT makes replies from ordinary LAN hosts work without adding
// a route to every home router. Conntrack restores the original virtual source
// on replies, which are then routed back through the TUN interface.
func configureSiteNAT(localLAN, remoteVirtual []string) error {
	if len(localLAN) == 0 || len(remoteVirtual) == 0 {
		return nil
	}
	ipTables, err := exec.LookPath("iptables")
	if err != nil {
		return nil
	}
	run := func(args ...string) ([]byte, error) { return exec.Command(ipTables, args...).CombinedOutput() }
	if _, err := run("-w", "-t", "nat", "-L"); err != nil {
		return fmt.Errorf("iptables unavailable")
	}
	for _, src := range remoteVirtual {
		for _, dst := range localLAN {
			args := []string{"-w", "-t", "nat", "-C", "POSTROUTING", "-s", src, "-d", dst, "-j", "MASQUERADE"}
			if _, err := run(args...); err != nil {
				add := []string{"-w", "-t", "nat", "-A", "POSTROUTING", "-s", src, "-d", dst, "-j", "MASQUERADE"}
				if out, e := run(add...); e != nil {
					return fmt.Errorf("iptables MASQUERADE %s to %s: %s", src, dst, string(out))
				}
			}
			for _, direction := range [][2]string{{src, dst}, {dst, src}} {
				check := []string{"-w", "-t", "filter", "-C", "FORWARD", "-s", direction[0], "-d", direction[1], "-j", "ACCEPT"}
				if _, err := run(check...); err != nil {
					add := []string{"-w", "-t", "filter", "-A", "FORWARD", "-s", direction[0], "-d", direction[1], "-j", "ACCEPT"}
					if out, e := run(add...); e != nil {
						return fmt.Errorf("iptables FORWARD %s to %s: %s", direction[0], direction[1], string(out))
					}
				}
			}
		}
	}
	if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %s", string(out))
	}
	return nil
}

func cleanupTUN(name string, installed map[string]bool) {
	if name == "" {
		return
	}
	ipCommand, err := findIPCommand()
	if err != nil {
		return
	}
	// Closing a non-persistent TUN normally removes it. Explicitly deleting
	// the named link as well also cleans up interfaces left behind when the
	// process was killed between TUNSETIFF and close(). The name is supplied
	// by the user and is never interpreted by a shell.
	for route := range installed {
		_, _ = exec.Command(ipCommand, "route", "del", route, "dev", name).CombinedOutput()
	}
	_, _ = exec.Command(ipCommand, "link", "del", "dev", name).CombinedOutput()
}

func configurePlatformNetwork(int) error { return nil }
func cleanupPlatformNetwork(int)         {}

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
