package main

import (
	"encoding/binary"
	"home-udp-mesh/internal/protocol"
	"net/netip"
	"testing"
)

func testChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func testUDPChecksum(p []byte) uint16 {
	ihl := int(p[0]&15) * 4
	pseudo := make([]byte, 12+len(p)-ihl)
	copy(pseudo[0:4], p[12:16])
	copy(pseudo[4:8], p[16:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(p)-ihl))
	copy(pseudo[12:], p[ihl:])
	return testChecksum(pseudo)
}

func TestPrefixTranslationPreservesHostAndHeaderChecksum(t *testing.T) {
	n := &node{id: &protocol.Identity{ID: "self"}, subnetRoutes: []subnetRoute{{LAN: mustTestPrefix("192.168.1.0/24"), Virtual: mustTestPrefix("10.77.1.0/24"), Owner: "self"}}}
	p := make([]byte, 28)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], netip.MustParseAddr("192.168.1.42").AsSlice())
	copy(p[16:20], netip.MustParseAddr("10.77.2.9").AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 1234)
	binary.BigEndian.PutUint16(p[22:24], 53)
	binary.BigEndian.PutUint16(p[24:26], 8)
	binary.BigEndian.PutUint16(p[26:28], testUDPChecksum(p))
	binary.BigEndian.PutUint16(p[10:12], testChecksum(p[:20]))
	if !n.translateLocalPacket(p, true) {
		t.Fatal("source route was not translated")
	}
	if got := netip.AddrFrom4([4]byte(p[12:16])).String(); got != "10.77.1.42" {
		t.Fatalf("translated source = %s", got)
	}
	if testChecksum(p[:20]) != 0 {
		t.Fatal("invalid IPv4 checksum after translation")
	}
	if testUDPChecksum(p) != 0 {
		t.Fatal("invalid UDP checksum after translation")
	}
}

func mustTestPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
