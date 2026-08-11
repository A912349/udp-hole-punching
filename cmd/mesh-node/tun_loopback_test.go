package main

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
)

type testTUN struct{ writes [][]byte }

func (*testTUN) Read([]byte) (int, error) { return 0, io.EOF }
func (t *testTUN) Write(p []byte) (int, error) {
	t.writes = append(t.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (*testTUN) Close() error { return nil }

func TestLoopbackTUNPacketWritesUnchangedPacket(t *testing.T) {
	tun := &testTUN{}
	n := &node{tun: tun}
	packet := []byte{0x45, 0, 0, 20, 0, 1, 0, 0, 64, 1, 0, 0, 10, 77, 0, 2, 10, 77, 0, 1}
	if !n.loopbackTUNPacket(packet) {
		t.Fatal("loopbackTUNPacket() = false")
	}
	if len(tun.writes) != 1 || !bytes.Equal(tun.writes[0], packet) {
		t.Fatalf("TUN writes = %v, want original packet", tun.writes)
	}
}

func TestLocalMeshIPMatchesOnlyOwnAddress(t *testing.T) {
	n := &node{}
	n.meshIPv4.Store(0x0a4d0001) // 10.77.0.1
	if !n.isLocalMeshIP(netip.MustParseAddr("10.77.0.1")) {
		t.Fatal("own mesh IP was not recognized")
	}
	if n.isLocalMeshIP(netip.MustParseAddr("10.77.0.2")) {
		t.Fatal("peer mesh IP was recognized as local")
	}
}
