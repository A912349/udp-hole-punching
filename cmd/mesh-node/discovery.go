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
func (n *node) handleSymmetricBurst(packet protocol.Packet, observed *net.UDPAddr) {
	if n.c.role != "superpeer" {
		return
	}
	n.mu.RLock()
	peer := n.neighbors[packet.Source]
	n.mu.RUnlock()
	if peer == nil || peer.NAT != "symmetric" {
		return
	}
	sessionID := payloadString(packet, "session_id")
	n.symmetricMu.Lock()
	armedSession := n.symmetricSessions[packet.Source]
	previous := n.symmetricBurstAt[packet.Source]
	previousSession := n.symmetricBurstSess[packet.Source]
	if armedSession != "" && sessionID != armedSession {
		n.symmetricMu.Unlock()
		return
	}
	if previousSession == sessionID && time.Since(previous) < 5*time.Second {
		n.symmetricMu.Unlock()
		return
	}
	n.symmetricBurstAt[packet.Source] = time.Now()
	n.symmetricBurstSess[packet.Source] = sessionID
	n.symmetricMu.Unlock()
	// A burst is optional: the control-plane event already started the scan.
	// When one arrives, use its observed mapping to refine the scan window.
	endpoint := peer.Endpoint
	if observed != nil {
		endpoint = observed.String()
	}
	// The control-plane event normally started the scan already. Restart only
	// when the burst supplies a different observed mapping that can refine it.
	refine := observed != nil && observed.String() != peer.Endpoint
	n.startSymmetricScan(packet.Source, endpoint, sessionID, refine)
}
func payloadString(packet protocol.Packet, key string) string {
	value, _ := packet.Payload[key].(string)
	return value
}
func (n *node) handleSymmetricScanEvent(peerID, sessionID, endpoint string) {
	if n.c.role != "superpeer" || peerID == "" || sessionID == "" || endpoint == "" {
		return
	}
	n.mu.RLock()
	peer := n.neighbors[peerID]
	n.mu.RUnlock()
	if peer == nil || peer.NAT != "symmetric" {
		return
	}
	// The control-plane event is the rendezvous barrier: begin scanning before
	// acknowledging it, so both peers scan concurrently. A later UDP burst can
	// refine the window but must never be required to start the scan.
	n.symmetricMu.Lock()
	if existing := n.symmetricScans[peerID]; existing != nil {
		delete(n.symmetricScans, peerID)
		delete(n.symmetricSessions, peerID)
		close(existing)
	}
	delete(n.symmetricConnected, peerID)
	n.symmetricSessions[peerID] = sessionID
	delete(n.symmetricBurstAt, peerID)
	delete(n.symmetricBurstSess, peerID)
	n.symmetricMu.Unlock()
	n.startSymmetricScan(peerID, endpoint, sessionID, true)
	err := n.request("POST", "/v1/symmetric-scan/ack", map[string]any{
		"source_node_id": peerID,
		"session_id":     sessionID,
	}, &map[string]any{})
	if err != nil {
		n.logf("symmetric scan ACK for %s failed: %v", peerID[:8], err)
	}
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
