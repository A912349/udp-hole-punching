package main

import (
	"net"
	_ "net/http/pprof"
	"time"

	"home-udp-mesh/internal/protocol"
)

func symmetricScanPortPass(center, step int, visit func(port int) bool) bool {
	first := center % step
	if first < 0 {
		first += step
	}
	if first == 0 {
		first = step
	}
	last := first + (maxUDPPort-first)/step*step
	if center < 1 {
		for port := first; port <= last; port += step {
			if !visit(port) {
				return false
			}
		}
		return true
	}
	beforeCenter := center - step
	if beforeCenter >= first && !visit(beforeCenter) {
		return false
	}
	for port := center + step; port <= last; port += step {
		if !visit(port) {
			return false
		}
	}
	for port := first; port < beforeCenter; port += step {
		if !visit(port) {
			return false
		}
	}
	return visit(center)
}
func (n *node) symmetricScanCancelled(cancel chan struct{}) bool {
	select {
	case <-cancel:
		return true
	default:
		return false
	}
}
func (n *node) completeSymmetricScan(peerID, sessionID string) {
	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()

	cancel := n.symmetricScans[peerID]
	if cancel == nil || n.symmetricSessions[peerID] != sessionID {
		// A normal HELLO_ACK does not prove that the symmetric scan succeeded.
		return
	}

	delete(n.symmetricScans, peerID)
	delete(n.symmetricSessions, peerID)
	close(cancel)
	n.symmetricConnected[peerID] = true
	n.debugf("symmetric scan completed for %s", peerID[:8])
}
func payloadString(packet protocol.Packet, key string) string {
	value, _ := packet.Payload[key].(string)
	return value
}
func (n *node) sendToAddress(packet protocol.Packet, address *net.UDPAddr) {
	encoded, err := n.encodePacketForPeer(packet)
	if err != nil {
		return
	}
	conn := n.connForPeer(packet.Destination)
	if conn == nil {
		return
	}
	_, _ = conn.WriteToUDP(encoded, address)
}
func (n *node) encodePacketForPeer(packet protocol.Packet) ([]byte, error) {
	if packet.TTL == protocol.DefaultTTL &&
		(packet.Type == "HELLO" || packet.Type == "HELLO_ACK") &&
		payloadString(packet, "session_id") == "" &&
		n.speaksCompactHello(packet.Destination) {
		if encoded, err := protocol.EncodeCompact(packet, n.key); err == nil {
			return encoded, nil
		}
	}
	return protocol.EncodePacket(packet, n.key)
}
func (n *node) markCompactHello(id string) {
	n.mu.Lock()
	if peer := n.neighbors[id]; peer != nil {
		peer.compactHelloUntil = time.Now().Add(compactHelloCapabilityTTL)
	}
	n.mu.Unlock()
}
