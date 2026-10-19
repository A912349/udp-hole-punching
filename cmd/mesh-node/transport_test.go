package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestReceiveSocketStopsWhenReplacedSocketIsClosed(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	n := &node{receiveSockets: map[*net.UDPConn]struct{}{conn: {}}}
	n.receiveWG.Add(1)
	done := make(chan struct{})
	go func() {
		n.receiveSocket(context.Background(), conn)
		close(done)
	}()

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP reader kept spinning after its socket was closed")
	}
}

// rebindUDPConn and STUN must not wait forever behind a receive loop that is
// parked in a blocking read on a socket without incoming traffic. After an IP
// change no packets arrive on the old socket, so an unbounded read held the
// shared lock permanently and the endpoint refresh after a control-channel
// reconnect never completed (the node stayed registered with a dead endpoint).
func TestRebindUDPConnUnblocksIdleReceiveLoop(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	n := &node{
		c:              config{bind: "0.0.0.0"},
		conn:           conn,
		symmetricConns: map[string]*net.UDPConn{},
		receiveSockets: map[*net.UDPConn]struct{}{},
	}
	n.receiveWG.Add(1)
	go func() {
		n.receiveSocket(context.Background(), conn)
	}()

	// Let the reader block inside its read call, mirroring an idle socket.
	time.Sleep(100 * time.Millisecond)

	rebound := make(chan error, 1)
	go func() { rebound <- n.rebindUDPConn() }()
	select {
	case err := <-rebound:
		if err != nil {
			t.Fatalf("rebindUDPConn: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rebindUDPConn blocked behind an idle UDP receive loop")
	}
	if next := n.currentUDPConn(); next == nil || next == conn {
		t.Fatal("rebindUDPConn did not install a new UDP socket")
	}
	done := make(chan struct{})
	go func() {
		n.receiveWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("old UDP reader kept running after rebind")
	}
	_ = n.currentUDPConn().Close()
}
