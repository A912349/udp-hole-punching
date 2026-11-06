package main

import (
	"net/netip"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

// TestNodeJSONCodecReusesPooledStateAcrossFrames locks the node's pooled JSON
// helpers. sync.Pool hands a frame's HMAC state straight back to the next frame
// on the same thread, so two frames run back to back through one state: a state
// that failed to rewind its keyed start would leave the second frame's MAC
// covering the first frame's bytes too, and only decoding both frames would
// show that.
func TestNodeJSONCodecReusesPooledStateAcrossFrames(t *testing.T) {
	self, e := protocol.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	other, e := protocol.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	var tun benchTUN
	n := newBenchNode(self, &tun, netip.MustParseAddr("10.41.0.1"), nil)
	n.macPool.New = func() any { return protocol.NewPooledMAC(n.key) }

	first := protocol.NewPacket("PING", self.ID, other.ID, map[string]any{"frame": "one"})
	first.Timestamp = time.Now().Unix()
	second := protocol.NewPacket("PING", self.ID, other.ID, map[string]any{"frame": "two"})
	second.Timestamp = first.Timestamp + 1

	wireOne, e := n.encodePacket(first)
	if e != nil {
		t.Fatal("encodePacket frame one: ", e)
	}
	wireTwo, e := n.encodePacket(second)
	if e != nil {
		t.Fatal("encodePacket frame two: ", e)
	}

	backOne, e := n.decodePacket(wireOne)
	if e != nil {
		t.Fatal("decodePacket frame one: ", e)
	}
	if payloadString(backOne, "frame") != "one" {
		t.Fatal("frame one decoded as ", payloadString(backOne, "frame"))
	}
	backTwo, e := n.decodePacket(wireTwo)
	if e != nil {
		t.Fatal("decodePacket frame two: ", e)
	}
	if payloadString(backTwo, "frame") != "two" {
		t.Fatal("frame two decoded as ", payloadString(backTwo, "frame"))
	}

	// A node that never pools (a hand-built node, or a mesh version predating the
	// pool) must read this node's frames, and the pooled node must read that
	// node's frames, so the wire keeps one meaning across mesh versions.
	plain, e := protocol.EncodePacket(first, n.key)
	if e != nil {
		t.Fatal("EncodePacket: ", e)
	}
	crossIn, e := n.decodePacket(plain)
	if e != nil {
		t.Fatal("pooled decode of an unpooled frame: ", e)
	}
	if payloadString(crossIn, "frame") != "one" {
		t.Fatal("unpooled frame read as ", payloadString(crossIn, "frame"))
	}
	pooledWire, e := n.encodePacket(second)
	if e != nil {
		t.Fatal("encodePacket again: ", e)
	}
	crossOut, e := protocol.DecodePacket(pooledWire, n.key)
	if e != nil {
		t.Fatal("unpooled decode of a pooled frame: ", e)
	}
	if payloadString(crossOut, "frame") != "two" {
		t.Fatal("pooled frame read as ", payloadString(crossOut, "frame"))
	}
}
