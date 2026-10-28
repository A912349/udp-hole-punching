package main

import (
	"net"
	"testing"
)

func fakeAddrs(ips ...string) func(net.Interface) ([]net.Addr, error) {
	return func(net.Interface) ([]net.Addr, error) {
		out := make([]net.Addr, 0, len(ips))
		for _, ip := range ips {
			out = append(out, &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(24, 32)})
		}
		return out, nil
	}
}

func TestFingerprintIgnoresOrderAndLoopback(t *testing.T) {
	wifi := []net.Interface{
		{Name: "wlan0", Flags: net.FlagUp},
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
	}
	same := []net.Interface{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
		{Name: "wlan0", Flags: net.FlagUp},
	}
	first := fingerprintInterfaces(wifi, fakeAddrs("192.168.1.5"), "")
	second := fingerprintInterfaces(same, fakeAddrs("192.168.1.5"), "")
	if first == "" || first != second {
		t.Fatalf("fingerprint must be order-independent and skip loopback: %q vs %q", first, second)
	}
}

func TestFingerprintDetectsNetworkSwitch(t *testing.T) {
	wifi := fingerprintInterfaces([]net.Interface{{Name: "wlan0", Flags: net.FlagUp}}, fakeAddrs("192.168.1.5"), "")
	lte := fingerprintInterfaces([]net.Interface{{Name: "rmnet0", Flags: net.FlagUp}}, fakeAddrs("10.20.30.40"), "")
	if wifi == lte {
		t.Fatal("a Wi-Fi to LTE switch must change the fingerprint")
	}
}

func TestFingerprintSkipsDownAndOwnTunInterfaces(t *testing.T) {
	down := fingerprintInterfaces([]net.Interface{{Name: "wlan0", Flags: 0}}, fakeAddrs("192.168.1.5"), "")
	if down != "" {
		t.Fatalf("down interfaces must be ignored, got %q", down)
	}
	tun := fingerprintInterfaces([]net.Interface{{Name: "mesh0", Flags: net.FlagUp}}, fakeAddrs("10.6.0.2"), "mesh0")
	if tun != "" {
		t.Fatalf("the mesh TUN must be excluded to avoid self-triggered recovery, got %q", tun)
	}
}

func TestFingerprintIgnoresIPv6OnlyInterfaces(t *testing.T) {
	v6 := fingerprintInterfaces([]net.Interface{{Name: "wlan0", Flags: net.FlagUp}},
		func(net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)}}, nil
		}, "")
	if v6 != "" {
		t.Fatalf("the mesh transport is IPv4 only; IPv6-only interfaces must not produce a fingerprint, got %q", v6)
	}
}

func TestFingerprintDetectsPrefixChange(t *testing.T) {
	old := fingerprintInterfaces([]net.Interface{{Name: "wlan0", Flags: net.FlagUp}},
		func(net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.5"), Mask: net.CIDRMask(24, 32)}}, nil
		}, "")
	newFp := fingerprintInterfaces([]net.Interface{{Name: "wlan0", Flags: net.FlagUp}},
		func(net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.5"), Mask: net.CIDRMask(28, 32)}}, nil
		}, "")
	if old == newFp {
		t.Fatal("a prefix change must change the fingerprint")
	}
}
