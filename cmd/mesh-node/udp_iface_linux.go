//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// bindUDPInterface pins a UDP socket to a network interface with
// SO_BINDTODEVICE. All traffic then flows through that interface only:
// Android policy routing can no longer pull it into a VPN TUN (VLESS,
// WireGuard and similar apps), which silently breaks UDP hole punching.
// Requires CAP_NET_RAW (root/Magisk); callers must fall back to the
// wildcard socket when this fails.
func bindUDPInterface(conn *net.UDPConn, iface string) error {
	if conn == nil || iface == "" {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var bindErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface+"\x00")
	}); ctrlErr != nil {
		return ctrlErr
	}
	if bindErr != nil {
		return fmt.Errorf("SO_BINDTODEVICE(%s): %w", iface, bindErr)
	}
	return nil
}

// procNetRoutePath is a variable so tests can point it at a fixture.
var procNetRoutePath = "/proc/net/route"

// defaultRouteInterface returns the interface of the IPv4 default route from
// the main routing table. VpnService-based apps route per-UID traffic through
// separate policy tables, so even with a VPN proxy active this reports the
// physical uplink (wlan0/rmnet...) — exactly where mesh traffic belongs.
func defaultRouteInterface() string {
	data, err := os.ReadFile(procNetRoutePath)
	if err != nil {
		return ""
	}
	best, bestMetric := "", -1
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Default route: destination and mask are both 0.0.0.0.
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		metric, err := strconv.Atoi(fields[5])
		if err != nil {
			metric = 0
		}
		if best == "" || metric < bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	return strings.TrimSpace(best)
}
