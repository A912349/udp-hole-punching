package main

import (
	"context"
	"testing"
	"time"
)

func TestLocalUDPWaitsForQueueSpace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &node{udpSendQueue: make(chan outboundDatagram, 1), udpSendDone: ctx.Done()}
	n.udpSendQueue <- outboundDatagram{data: []byte("first")}
	data := make([]byte, maxFastFrame)
	data[0] = 42
	done := make(chan bool, 1)
	go func() { done <- n.enqueueUDP(outboundDatagram{data: data}, true) }()
	select {
	case result := <-done:
		t.Fatalf("local packet did not wait for space: %v", result)
	case <-time.After(20 * time.Millisecond):
	}
	<-n.udpSendQueue
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("local packet dropped")
		}
	case <-time.After(time.Second):
		t.Fatal("producer did not resume")
	}
	frame := <-n.udpSendQueue
	if frame.data[0] != 42 {
		t.Fatal("incorrect queued packet")
	}
	if n.stats.queueDrops.Load() != 0 {
		t.Fatal("backpressure counted as packet loss")
	}
}

func TestLocalUDPWaitStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &node{udpSendQueue: make(chan outboundDatagram, 1), udpSendDone: ctx.Done()}
	n.udpSendQueue <- outboundDatagram{}
	done := make(chan bool, 1)
	go func() { done <- n.enqueueUDP(outboundDatagram{data: make([]byte, maxFastFrame)}, true) }()
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("packet queued after shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("producer stuck after cancellation")
	}
}

func TestRelayUDPDoesNotWaitForQueueSpace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &node{udpSendQueue: make(chan outboundDatagram, 1), udpSendDone: ctx.Done()}
	n.udpSendQueue <- outboundDatagram{}
	done := make(chan bool, 1)
	go func() { done <- n.enqueueUDP(outboundDatagram{data: make([]byte, maxFastFrame)}, false) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("relay accepted into full queue")
		}
	case <-time.After(time.Second):
		t.Fatal("relay worker blocked")
	}
	if n.stats.queueDrops.Load() != 1 || n.stats.txQueueDrops.Load() != 1 || n.stats.rxQueueDrops.Load() != 0 {
		t.Fatal("incorrect TX drop counters")
	}
}
