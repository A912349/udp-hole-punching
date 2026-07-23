//go:build windows

package main

// Windows uses the official Wintun user-mode API. The DLL contains the signed
// Wintun driver and is expected next to mesh-node.exe (or in PATH). This keeps
// the data plane identical to Linux while avoiding a custom kernel driver.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	wintunSessionCapacity = 8 * 1024 * 1024
	wintunPoolName        = "Home UDP Mesh"
	waitObjectTimeout     = 100
	waitObjectFailed      = 0xffffffff
)

var (
	wintunDLL                = syscall.NewLazyDLL("wintun.dll")
	wintunOpenAdapter        = wintunDLL.NewProc("WintunOpenAdapter")
	wintunCreateAdapter      = wintunDLL.NewProc("WintunCreateAdapter")
	wintunCloseAdapter       = wintunDLL.NewProc("WintunCloseAdapter")
	wintunStartSession       = wintunDLL.NewProc("WintunStartSession")
	wintunEndSession         = wintunDLL.NewProc("WintunEndSession")
	wintunGetReadWaitEvent   = wintunDLL.NewProc("WintunGetReadWaitEvent")
	wintunReceivePacket      = wintunDLL.NewProc("WintunReceivePacket")
	wintunReleaseReceive     = wintunDLL.NewProc("WintunReleaseReceivePacket")
	wintunAllocateSend       = wintunDLL.NewProc("WintunAllocateSendPacket")
	wintunSendPacket         = wintunDLL.NewProc("WintunSendPacket")
	kernel32WaitForSingleObj = syscall.NewLazyDLL("kernel32.dll").NewProc("WaitForSingleObject")
)

type wintunDevice struct {
	adapter uintptr
	session uintptr
	event   uintptr
	mu      sync.Mutex
	closed  bool
}

func openTUN(name string) (tunDevice, error) {
	if name == "" {
		name = "mesh0"
	}
	if len(name) > 255 {
		return nil, errors.New("Windows TUN adapter name is limited to 255 bytes")
	}
	if err := wintunDLL.Load(); err != nil {
		return nil, fmt.Errorf("load wintun.dll: %w (copy the official Wintun DLL next to mesh-node.exe)", err)
	}
	wname := syscall.StringToUTF16Ptr(name)
	poolName := syscall.StringToUTF16Ptr(wintunPoolName)
	adapter, _, openErr := wintunOpenAdapter.Call(
		uintptr(unsafe.Pointer(poolName)),
		uintptr(unsafe.Pointer(wname)),
	)
	if adapter == 0 {
		var createErr uint32
		adapter, _, openErr = wintunCreateAdapter.Call(
			uintptr(unsafe.Pointer(poolName)),
			uintptr(unsafe.Pointer(wname)),
			0,
			uintptr(unsafe.Pointer(&createErr)),
		)
		if adapter == 0 {
			return nil, fmt.Errorf("open or create Wintun adapter %q: %w", name, winCallError(openErr))
		}
	}
	session, _, sessionErr := wintunStartSession.Call(adapter, wintunSessionCapacity)
	if session == 0 {
		wintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("start Wintun session: %w", winCallError(sessionErr))
	}
	event, _, eventErr := wintunGetReadWaitEvent.Call(session)
	if event == 0 {
		wintunEndSession.Call(session)
		wintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("get Wintun read event: %w", winCallError(eventErr))
	}
	return &wintunDevice{adapter: adapter, session: session, event: event}, nil
}

func winCallError(err error) error {
	if err == nil || err == syscall.Errno(0) {
		return errors.New("Windows API call failed")
	}
	return err
}

func (d *wintunDevice) Read(buffer []byte) (int, error) {
	for {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return 0, io.EOF
		}
		session, event := d.session, d.event
		d.mu.Unlock()

		var size uint32
		packet, _, receiveErr := wintunReceivePacket.Call(session, uintptr(unsafe.Pointer(&size)))
		if packet != 0 {
			if int(size) > len(buffer) {
				wintunReleaseReceive.Call(session, packet)
				return 0, io.ErrShortBuffer
			}
			copy(buffer, unsafe.Slice((*byte)(unsafe.Pointer(packet)), int(size)))
			wintunReleaseReceive.Call(session, packet)
			return int(size), nil
		}
		if receiveErr != nil && receiveErr != syscall.Errno(0) {
			// Wintun returns a null packet while its ring is empty. Waiting on
			// the event is still the correct recovery path for that condition.
			_ = receiveErr
		}
		result, _, waitErr := kernel32WaitForSingleObj.Call(event, waitObjectTimeout)
		if result == waitObjectFailed {
			return 0, fmt.Errorf("wait for Wintun packet: %w", winCallError(waitErr))
		}
	}
}

func readTUN(device tunDevice, buffer []byte) (int, error) {
	return device.Read(buffer)
}

func (d *wintunDevice) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	packet, _, err := wintunAllocateSend.Call(d.session, uintptr(len(data)))
	if packet == 0 {
		return 0, fmt.Errorf("allocate Wintun packet: %w", winCallError(err))
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(packet)), len(data)), data)
	wintunSendPacket.Call(d.session, packet)
	return len(data), nil
}

func (d *wintunDevice) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	session, adapter := d.session, d.adapter
	d.session, d.adapter = 0, 0
	d.mu.Unlock()
	if session != 0 {
		wintunEndSession.Call(session)
	}
	if adapter != 0 {
		wintunCloseAdapter.Call(adapter)
	}
	return nil
}

func windowsInterfaceIndex(name string) (string, error) {
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return "", fmt.Errorf("find Windows interface %q: %w", name, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		if strings.EqualFold(strings.Join(fields[4:], " "), name) {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("Windows interface %q was not found", name)
}

func windowsPrefix(cidr string) (string, string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return "", "", fmt.Errorf("invalid IPv4 route %q", cidr)
	}
	prefix = prefix.Masked()
	ones, bits := prefix.Bits(), 32
	mask := net.CIDRMask(ones, bits)
	return prefix.Addr().String(), net.IP(mask).String(), nil
}

func runWindows(command string, args ...string) error {
	if out, err := exec.Command(command, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %s", command, args, strings.TrimSpace(string(out)))
	}
	return nil
}

func configureTUN(name, ip string, prefix int) error {
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() || prefix < 1 || prefix > 32 {
		return fmt.Errorf("invalid mesh IPv4 address %q/%d", ip, prefix)
	}
	mask := net.IP(net.CIDRMask(prefix, 32)).String()
	if err := configureWindowsAddress(name, ip, prefix, mask); err != nil {
		return err
	}
	// Keep the host adapter MTU aligned with the overlay. Without this,
	// Windows emits 1500-byte packets while the overlay accepts at most 1279;
	// a Wintun read could then terminate on io.ErrShortBuffer.
	if err := runWindows("netsh", "interface", "ipv4", "set", "subinterface", "name="+name, "mtu=1279", "store=active"); err != nil {
		return fmt.Errorf("set Wintun MTU: %w", err)
	}
	return addWindowsRoute(name, netip.PrefixFrom(address, prefix).Masked().String())
}

func configureWindowsAddress(name, ip string, prefix int, mask string) error {
	interfaceIndex, err := windowsInterfaceIndex(name)
	if err != nil {
		return err
	}
	// New-NetIPAddress updates the NetTCPIP store directly and works for
	// Wintun adapters that accept netsh's command but do not materialize the
	// address. Values are passed through the child environment, not embedded
	// in PowerShell source, so a custom adapter name cannot inject a command.
	ps := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", `$ErrorActionPreference = 'Stop'
$index = [uint32]$env:MESH_TUN_IFINDEX
$ip = $env:MESH_TUN_IP
$prefix = [int]$env:MESH_TUN_PREFIX
$old = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne $ip }
$old | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
if (-not @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $ip })) {
    New-NetIPAddress -InterfaceIndex $index -IPAddress $ip -PrefixLength $prefix -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null
}
if (-not @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $ip })) {
    throw "IPv4 address was not materialized on interface index $index"
}`)
	ps.Env = append(os.Environ(), "MESH_TUN_IFINDEX="+interfaceIndex, "MESH_TUN_IP="+ip, fmt.Sprintf("MESH_TUN_PREFIX=%d", prefix))
	psOutput, psErr := ps.CombinedOutput()
	if psErr == nil {
		if err := windowsHasAddress(name, ip); err == nil {
			return nil
		}
	}

	// Keep netsh as a fallback for stripped-down Windows installations where
	// the NetTCPIP PowerShell module is unavailable.
	netshSetErr := runWindows("netsh", "interface", "ipv4", "set", "address", "name="+name, "source=static", "gateway=none", "store=active")
	netshErr := runWindows("netsh", "interface", "ipv4", "add", "address", "name="+name, "address="+ip, "mask="+mask, "type=unicast", "store=active")
	if netshSetErr == nil && netshErr == nil {
		if err := windowsHasAddress(name, ip); err == nil {
			return nil
		}
	}
	return fmt.Errorf("Windows did not assign %s to adapter %q (PowerShell: %v, output: %s; netsh set: %v; netsh add: %v)", ip, name, psErr, strings.TrimSpace(string(psOutput)), netshSetErr, netshErr)
}

func windowsHasAddress(name, ip string) error {
	target := net.ParseIP(ip).To4()
	if target == nil {
		return fmt.Errorf("invalid IPv4 address %q", ip)
	}
	interfaceIndex, err := windowsInterfaceIndex(name)
	if err != nil {
		return err
	}
	index, err := strconv.Atoi(interfaceIndex)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 10; attempt++ {
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range interfaces {
			if iface.Index != index {
				continue
			}
			addresses, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, address := range addresses {
				candidate, _, err := net.ParseCIDR(address.String())
				if err == nil && candidate.To4() != nil && candidate.To4().Equal(target) {
					return nil
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("address %s is absent from interface %q", ip, name)
}

func addWindowsRoute(name, cidr string) error {
	idx, err := windowsInterfaceIndex(name)
	if err != nil {
		return err
	}
	destination, mask, err := windowsPrefix(cidr)
	if err != nil {
		return err
	}
	// Delete is intentionally best-effort: route.exe returns an error when
	// the route is not present, which is normal on the first start.
	_ = runWindows("route", "delete", destination, "mask", mask, "if", idx)
	// A zero next hop creates an on-link route. This is required for Wintun's
	// layer-3 adapter, which does not perform ARP for a synthetic gateway.
	return runWindows("route", "add", destination, "mask", mask, "0.0.0.0", "metric", "1", "if", idx)
}

func deleteWindowsRoute(name, cidr string) error {
	idx, err := windowsInterfaceIndex(name)
	if err != nil {
		return err
	}
	destination, mask, err := windowsPrefix(cidr)
	if err != nil {
		return err
	}
	return runWindows("route", "delete", destination, "mask", mask, "if", idx)
}

func configureTUNRoutes(name string, wanted, installed map[string]bool) error {
	for route := range installed {
		if !wanted[route] {
			if err := deleteWindowsRoute(name, route); err != nil {
				return err
			}
		}
	}
	for route := range wanted {
		if !installed[route] {
			if err := addWindowsRoute(name, route); err != nil {
				return err
			}
		}
	}
	return nil
}

func configureSystemDNS(iface, meshIP, dnsTarget string) error {
	if dnsTarget != net.JoinHostPort(meshIP, "53") {
		return fmt.Errorf("Windows split-DNS is unavailable for local listener %s; use the mesh adapter DNS manually", dnsTarget)
	}
	return runWindows("netsh", "interface", "ipv4", "set", "dnsservers", "name="+iface, "source=static", "address="+meshIP, "register=primary", "validate=no")
}

func configureSiteNAT([]string, []string) error { return nil }

func windowsFirewallRuleName(port int) string {
	return fmt.Sprintf("Home UDP Mesh inbound %d", port)
}

func windowsLANFirewallRuleName() string { return "Home UDP Mesh LAN discovery" }

func configurePlatformNetwork(port int) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find mesh-node executable for firewall rule: %w", err)
	}
	rule := windowsFirewallRuleName(port)
	// Replacing our own rule makes restarts with a different executable path
	// deterministic and avoids accumulating stale rules for ephemeral ports.
	_ = runWindows("netsh", "advfirewall", "firewall", "delete", "rule", "name="+rule)
	if err := runWindows("netsh", "advfirewall", "firewall", "add", "rule", "name="+rule, "dir=in", "action=allow", "enable=yes", "profile=any", "protocol=UDP", fmt.Sprintf("localport=%d", port), "program="+executable); err != nil {
		return err
	}
	lanRule := windowsLANFirewallRuleName()
	_ = runWindows("netsh", "advfirewall", "firewall", "delete", "rule", "name="+lanRule)
	return runWindows("netsh", "advfirewall", "firewall", "add", "rule", "name="+lanRule, "dir=in", "action=allow", "enable=yes", "profile=any", "protocol=UDP", fmt.Sprintf("localport=%d", lanDiscoveryPort), "program="+executable)
}

func cleanupPlatformNetwork(port int) {
	_ = runWindows("netsh", "advfirewall", "firewall", "delete", "rule", "name="+windowsFirewallRuleName(port))
	_ = runWindows("netsh", "advfirewall", "firewall", "delete", "rule", "name="+windowsLANFirewallRuleName())
}

func cleanupTUN(name string, installed map[string]bool) {
	for route := range installed {
		_ = deleteWindowsRoute(name, route)
	}
	// The adapter is intentionally retained so its signed driver installation
	// is reusable. Only the settings owned by this process are reset.
	_ = runWindows("netsh", "interface", "ipv4", "set", "dnsservers", "name="+name, "source=dhcp")
}
