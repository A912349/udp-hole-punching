package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func meshDNSQuery() []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 123)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	return append(query, 4, 'n', 'o', 'd', 'e', 4, 'm', 'e', 's', 'h', 0, 0, 1, 0, 1)
}

func TestDNSAnswerSectionCounts(t *testing.T) {
	query := meshDNSQuery()
	questionEnd := len(query)
	// Typical EDNS request: one additional OPT record.
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0)
	answer := dnsAnswer(query, questionEnd, net.IPv4(10, 77, 0, 1))
	if binary.BigEndian.Uint16(answer[6:8]) != 1 || binary.BigEndian.Uint16(answer[8:10]) != 0 || binary.BigEndian.Uint16(answer[10:12]) != 0 {
		t.Fatalf("incorrect response section counts: %x", answer[6:12])
	}
	if len(answer) != questionEnd+16 {
		t.Fatalf("unexpected answer length: %d", len(answer))
	}
	if !bytes.Equal(answer[len(answer)-4:], []byte{10, 77, 0, 1}) {
		t.Fatal("incorrect IPv4 answer")
	}
}

func TestDNSListenerSurvivesSetupAndStopsOnCancel(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	n := &node{dir: map[string]*peer{"test": {Name: "node", MeshIP: "10.77.0.1"}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.runDNSListener(ctx, listener, func() { close(setupDone) })
	}()
	<-setupDone
	conn, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	query := meshDNSQuery()
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 512)
	size, err := conn.Read(response)
	if err != nil {
		t.Fatalf("DNS unavailable after setup: %v", err)
	}
	if size != len(query)+16 || binary.BigEndian.Uint16(response[:2]) != 123 {
		t.Fatalf("incorrect DNS response: %x", response[:size])
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS did not stop after cancellation")
	}
}
