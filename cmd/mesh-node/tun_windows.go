//go:build windows

package main

// Windows uses the official Wintun user-mode API. The DLL contains the signed
// Wintun driver and is expected next to mesh-node.exe (or in PATH). This keeps
// the data plane identical to Linux while avoiding a custom kernel driver.

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// wintun.dll is downloaded by the Windows CI job and embedded into the
// executable. Keeping the file in the source tree only as a CI build input
// avoids requiring a separate runtime file beside mesh-node.exe.
//
//go:embed wintun.dll
var embeddedWintun []byte

const (
	wintunSessionCapacity = 8 * 1024 * 1024
	wintunPoolName        = "Home UDP Mesh"
	waitObjectTimeout     = 100
	waitObjectFailed      = 0xffffffff
)

var (
	windowsTUNDebug          atomic.Bool
	wintunDLL                *syscall.LazyDLL
	wintunOpenAdapter        *syscall.Proc
	wintunCreateAdapter      *syscall.Proc
	wintunCloseAdapter       *syscall.Proc
	wintunStartSession       *syscall.Proc
	wintunEndSession         *syscall.Proc
	wintunGetReadWaitEvent   *syscall.Proc
	wintunReceivePacket      *syscall.Proc
	wintunReleaseReceive     *syscall.Proc
	wintunAllocateSend       *syscall.Proc
	wintunSendPacket         *syscall.Proc
	iphlpapiDLL              = syscall.NewLazyDLL("iphlpapi.dll")
	convertInterfaceLUID     = iphlpapiDLL.NewProc("ConvertInterfaceLuidToIndex")
	kernel32WaitForSingleObj = syscall.NewLazyDLL("kernel32.dll").NewProc("WaitForSingleObject")
	wintunGetAdapterLUID     *syscall.Proc
)

func init() {
	path := filepath.Join(os.TempDir(), "home-udp-mesh-wintun.dll")
	if err := os.WriteFile(path, embeddedWintun, 0600); err != nil {
		log.Printf("write embedded wintun.dll: %v", err)
	}
	wintunDLL = syscall.NewLazyDLL(path)
	wintunOpenAdapter = wintunDLL.NewProc("WintunOpenAdapter")
	wintunCreateAdapter = wintunDLL.NewProc("WintunCreateAdapter")
	wintunCloseAdapter = wintunDLL.NewProc("WintunCloseAdapter")
	wintunStartSession = wintunDLL.NewProc("WintunStartSession")
	wintunEndSession = wintunDLL.NewProc("WintunEndSession")
	wintunGetReadWaitEvent = wintunDLL.NewProc("WintunGetReadWaitEvent")
	wintunReceivePacket = wintunDLL.NewProc("WintunReceivePacket")
	wintunReleaseReceive = wintunDLL.NewProc("WintunReleaseReceivePacket")
	wintunAllocateSend = wintunDLL.NewProc("WintunAllocateSendPacket")
	wintunSendPacket = wintunDLL.NewProc("WintunSendPacket")
	wintunGetAdapterLUID = wintunDLL.NewProc("WintunGetAdapterLUID")
}

type wintunDevice struct {
	adapter uintptr
	session uintptr
	event   uintptr
	luid    uint64
	mu      sync.Mutex
	closed  bool
}

func (d *wintunDevice) adapterLUID() uint64 { return d.luid }

func (d *wintunDevice) setDebug(v bool) { windowsTUNDebug.Store(v) }

func windowsTUNDebugf(format string, args ...any) {
	if windowsTUNDebug.Load() {
		log.Printf("[mesh-node] debug Windows TUN: "+format, args...)
	}
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

	// Получаем LUID адаптера
	var luid uint64
	ret, _, luidErr := wintunGetAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		wintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("get Wintun adapter LUID: %w", winCallError(luidErr))
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
	return &wintunDevice{adapter: adapter, session: session, event: event, luid: luid}, nil
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

func writeTUN(device tunDevice, buffer []byte) (int, error) {
	return device.Write(buffer)
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

func windowsInterfaceIndexByLUID(luid uint64) (string, error) {
	luidStr := strconv.FormatUint(luid, 10)
	windowsTUNDebugf("searching interface by LUID=%s", luidStr)
	var index uint32
	ret, _, callErr := convertInterfaceLUID.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&index)),
	)
	if ret == 0 && index != 0 {
		windowsTUNDebugf("LUID=%s resolved by Windows API to ifIndex=%d", luidStr, index)
		return strconv.FormatUint(uint64(index), 10), nil
	}
	windowsTUNDebugf("Windows API LUID conversion failed for %s: return=%d error=%v; falling back to PowerShell", luidStr, ret, callErr)
	const query = `$l=[uint64]$env:MESH_TUN_LUID; $a=@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.ifLuid.Value -eq $l -or $_.InterfaceLuid.Value -eq $l -or $_.Luid.Value -eq $l }); if (-not $a) { $a=@(Get-NetIPInterface -IncludeAllCompartments -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceLuid.Value -eq $l }) }; if ($a) { $a[0].ifIndex }`
	for attempt := 0; attempt < 30; attempt++ {
		ps := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query)
		ps.Env = append(os.Environ(), "MESH_TUN_LUID="+luidStr)
		if output, err := ps.Output(); err == nil {
			index := strings.TrimSpace(string(output))
			if index != "" && index != "0" {
				windowsTUNDebugf("LUID=%s resolved to ifIndex=%s on attempt=%d", luidStr, index, attempt+1)
				return index, nil
			}
			if attempt == 0 || attempt == 29 {
				windowsTUNDebugf("LUID=%s query returned no interface on attempt=%d", luidStr, attempt+1)
			}
		} else if attempt == 0 || attempt == 29 {
			windowsTUNDebugf("LUID=%s PowerShell query failed on attempt=%d: %v", luidStr, attempt+1, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	windowsTUNDebugf("LUID=%s was not resolved after 30 attempts", luidStr)
	return "", fmt.Errorf("Windows interface for LUID %s was not found", luidStr)
}

func windowsInterfaceIndex(name string, luid uint64) (string, error) {
	// Если LUID известен, используем быстрый надёжный способ
	if luid != 0 {
		return windowsInterfaceIndexByLUID(luid)
	}

	// Fallback – старый код (на случай, если LUID не определён)
	for attempt := 0; attempt < 30; attempt++ {
		ps := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$n=$env:MESH_TUN_NAME; $a=@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $n -or $_.InterfaceAlias -eq $n }); if (-not $a) { $w=@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.DriverDescription -match 'Wintun' }); if ($w.Count -eq 1) { $a=$w } }; if ($a) { $a[0].ifIndex }`)
		ps.Env = append(os.Environ(), "MESH_TUN_NAME="+name)
		if output, err := ps.Output(); err == nil {
			if index := strings.TrimSpace(string(output)); index != "" {
				if _, err := strconv.Atoi(index); err == nil {
					return index, nil
				}
			}
		}
		out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
		if err == nil {
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
		}
		time.Sleep(200 * time.Millisecond)
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

func configureTUN(name, ip string, prefix int, luid uint64) error {
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() || prefix < 1 || prefix > 32 {
		return fmt.Errorf("invalid mesh IPv4 address %q/%d", ip, prefix)
	}
	mask := net.IP(net.CIDRMask(prefix, 32)).String()
	if err := configureWindowsAddress(name, ip, prefix, mask, luid); err != nil {
		return err
	}
	if err := runWindows("netsh", "interface", "ipv4", "set", "subinterface", "name="+name, "mtu=1279", "store=active"); err != nil {
		return fmt.Errorf("set Wintun MTU: %w", err)
	}
	return addWindowsRoute(name, netip.PrefixFrom(address, prefix).Masked().String(), luid)
}

func configureWindowsAddress(name, ip string, prefix int, mask string, luid uint64) error {
	interfaceIndex, err := windowsInterfaceIndex(name, luid)
	if err != nil {
		return err
	}
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
		if err := windowsHasAddress(name, ip, luid); err == nil {
			return nil
		}
	}

	netshSetErr := runWindows("netsh", "interface", "ipv4", "set", "address", "name="+name, "source=static", "gateway=none", "store=active")
	netshErr := runWindows("netsh", "interface", "ipv4", "add", "address", "name="+name, "address="+ip, "mask="+mask, "type=unicast", "store=active")
	if netshSetErr == nil && netshErr == nil {
		if err := windowsHasAddress(name, ip, luid); err == nil {
			return nil
		}
	}
	return fmt.Errorf("Windows did not assign %s to adapter %q (PowerShell: %v, output: %s; netsh set: %v; netsh add: %v)", ip, name, psErr, strings.TrimSpace(string(psOutput)), netshSetErr, netshErr)
}

func windowsHasAddress(name, ip string, luid uint64) error {
	target := net.ParseIP(ip).To4()
	if target == nil {
		return fmt.Errorf("invalid IPv4 address %q", ip)
	}
	interfaceIndex, err := windowsInterfaceIndex(name, luid)
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

func addWindowsRoute(name, cidr string, luid uint64) error {
	idx, err := windowsInterfaceIndex(name, luid)
	if err != nil {
		return err
	}
	destination, mask, err := windowsPrefix(cidr)
	if err != nil {
		return err
	}
	_ = runWindows("route", "delete", destination, "mask", mask, "if", idx)
	return runWindows("route", "add", destination, "mask", mask, "0.0.0.0", "metric", "1", "if", idx)
}

func deleteWindowsRoute(name, cidr string, luid uint64) error {
	idx, err := windowsInterfaceIndex(name, luid)
	if err != nil {
		return err
	}
	destination, mask, err := windowsPrefix(cidr)
	if err != nil {
		return err
	}
	return runWindows("route", "delete", destination, "mask", mask, "if", idx)
}

func configureTUNRoutes(name string, wanted, installed map[string]bool, luid uint64) error {
	for route := range installed {
		if !wanted[route] {
			if err := deleteWindowsRoute(name, route, luid); err != nil {
				return err
			}
		}
	}
	for route := range wanted {
		if !installed[route] {
			if err := addWindowsRoute(name, route, luid); err != nil {
				return err
			}
		}
	}
	return nil
}

func configureSystemDNS(iface, meshIP, dnsTarget string, luid uint64) error {
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

func cleanupTUN(name string, installed map[string]bool, luid uint64) {
	for route := range installed {
		_ = deleteWindowsRoute(name, route, luid)
	}
	_ = runWindows("netsh", "interface", "ipv4", "set", "dnsservers", "name="+name, "source=dhcp")
}
