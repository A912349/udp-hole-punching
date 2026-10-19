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
