//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDefaultRouteInterfaceParsing(t *testing.T) {
	fixture := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"lo\t00000000\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n" +
		"rmnet_data1\t0A873240\t00000000\t0001\t0\t0\t0\tFFFFFFF8\t0\t0\t0\n" +
		"wlan0\t00000000\t00000000\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"rmnet_data2\t00000000\t00000000\t0003\t0\t0\t1200\t00000000\t0\t0\t0\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := procNetRoutePath
	procNetRoutePath = path
	defer func() { procNetRoutePath = orig }()

	// Only wlan0 and rmnet_data2 are default routes; wlan0 wins on metric.
	if got := defaultRouteInterface(); got != "wlan0" {
		t.Fatalf("defaultRouteInterface() = %q, want %q", got, "wlan0")
	}
}

func TestDefaultRouteInterfaceMissing(t *testing.T) {
	orig := procNetRoutePath
	procNetRoutePath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { procNetRoutePath = orig }()

	if got := defaultRouteInterface(); got != "" {
		t.Fatalf("missing route table must yield an empty interface, got %q", got)
	}
}

func TestBindUDPInterface(t *testing.T) {
	// Loopback always exists; SO_BINDTODEVICE needs CAP_NET_RAW, which
	// root-based deployments (Magisk) have. Without privileges the call
	// must fail gracefully, not panic.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("no UDP socket: %v", err)
	}
	defer conn.Close()

	if err := bindUDPInterface(conn, "lo"); err != nil {
		t.Skipf("SO_BINDTODEVICE unavailable without CAP_NET_RAW: %v", err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var gotErr error
	if err := raw.Control(func(fd uintptr) {
		got, err := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		gotErr = err
		if err == nil && strings.TrimRight(got, "\x00") != "lo" {
			t.Errorf("SO_BINDTODEVICE = %q, want lo", got)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if gotErr != nil {
		t.Fatalf("getsockopt: %v", gotErr)
	}
}
