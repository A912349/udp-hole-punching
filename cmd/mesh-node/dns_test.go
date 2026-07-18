package main

import (
	"net"
	"testing"
)

func TestResolverFromResolvConfSkipsMeshAddresses(t *testing.T) {
	got := resolverFromResolvConf("# generated\nnameserver 10.77.0.1\nnameserver 192.168.2.1\n")
	if got != "192.168.2.1:53" {
		t.Fatalf("resolverFromResolvConf() = %q, want 192.168.2.1:53", got)
	}
}

func TestResolverFromResolvConfFallsBackWhenOnlyMeshAddressesExist(t *testing.T) {
	if got := resolverFromResolvConf("nameserver 10.77.0.1\nnameserver 10.77.4.1\n"); got != "" {
		t.Fatalf("resolverFromResolvConf() = %q, want empty", got)
	}
}

func TestIsMeshDNSAddress(t *testing.T) {
	for _, test := range []struct {
		ip   string
		mesh bool
	}{
		{"10.77.0.1", true},
		{"10.77.255.254", true},
		{"10.76.0.1", false},
		{"192.168.2.1", false},
	} {
		if got := isMeshDNSAddress(net.ParseIP(test.ip)); got != test.mesh {
			t.Errorf("isMeshDNSAddress(%s) = %v, want %v", test.ip, got, test.mesh)
		}
	}
}

func TestDNSTargetForListener(t *testing.T) {
	local, err := net.ResolveUDPAddr("udp4", "127.0.0.1:5353")
	if err != nil {
		t.Fatal(err)
	}
	if got := dnsTargetForListener(local); got != "127.0.0.1#5353" {
		t.Fatalf("dnsTargetForListener() = %q, want 127.0.0.1#5353", got)
	}

	mesh, err := net.ResolveUDPAddr("udp4", "10.77.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	if got := dnsTargetForListener(mesh); got != "10.77.0.1:53" {
		t.Fatalf("dnsTargetForListener() = %q, want 10.77.0.1:53", got)
	}
}
