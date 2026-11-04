package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

		"golang.org/x/net/websocket"
	"sync/atomic"
	"time"
)

func (n *node) connectControl() (bool, error) {
	if n.control != nil {
		return false, nil
	}
	u, err := url.Parse(strings.TrimRight(n.c.server, "/") + "/v1/ws")
	if err != nil {
		return false, err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return false, fmt.Errorf("unsupported control-plane URL scheme %q", u.Scheme)
	}
	n.logf("connecting control WebSocket via %s", u.String())
	origin := "http://" + u.Host
	wsConfig, err := websocket.NewConfig(u.String(), origin)
	if err != nil {
		return false, err
	}
	wsConfig.Dialer = &net.Dialer{Timeout: 10 * time.Second, Resolver: meshResolver(n.c.bootstrapDNS...)}
	wsConfig.Header.Set("X-Mesh-Token", n.c.token)
	if n.c.inviteToken != "" {
		wsConfig.Header.Set("X-Mesh-Invite", n.c.inviteToken)
	}
	if u.Scheme == "wss" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		pool, err := controlCertPool(n.c.controlCA)
		if err != nil {
			return false, err
		}
		tlsConfig.RootCAs = pool
		if n.c.controlInsecure {
			tlsConfig.InsecureSkipVerify = true
			n.logf("WARNING: TLS certificate verification is disabled")
		}
		wsConfig.TlsConfig = tlsConfig
	}
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		return false, fmt.Errorf("connect control websocket: %w", err)
	}
	reconnected := n.controlConnected
	n.control = ws
	n.controlConnected = true
	n.controlReply = make(chan controlFrame, 1)
	go n.readControl(ws, n.controlReply)
	n.logf("control WebSocket connected")
	if reconnected {
		// Refresh the endpoint as soon as the socket is back, not when some
		// later request happens to receive a reply: after a resume from doze
		// the first request can time out (or 404 on an evicted node) before
		// any reply-path trigger runs, and the node would keep advertising a
		// stale NAT mapping until the next successful reconnect.
		go n.refreshEndpointAfterControlReconnect()
	}
	return reconnected, nil
}
func meshResolver(bootstrap ...string) *net.Resolver {
	servers := []string{}
	if system := systemResolver(); system != "" {
		servers = append(servers, system)
	}
	for _, value := range bootstrap {
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			host, port = value, "53"
		}
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil && ip.To4() != nil {
			servers = append(servers, net.JoinHostPort(ip.String(), port))
		}
	}
	// Last-resort public resolver for bootstrap connectivity.
	servers = append(servers, "8.8.8.8:53")
	var index atomic.Uint32
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		for i := 0; i < len(servers); i++ {
			server := servers[int(index.Add(1)-1)%len(servers)]
			conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp4", server)
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("no IPv4 DNS server available")
	}}
}
func controlCertPool(explicit string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if explicit != "" {
		pem, err := os.ReadFile(explicit)
		if err != nil {
			return nil, fmt.Errorf("read --control-ca-file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate found in --control-ca-file")
		}
		return pool, nil
	}
	// Termux keeps its CA bundle outside the Android system paths. Add known
	// OS/package-manager bundles without weakening verification or accepting
	// an insecure TLS connection.
	paths := []string{
		os.Getenv("SSL_CERT_FILE"),
		"/data/data/com.termux/files/usr/etc/tls/cert.pem",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/cert.pem",
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		pem, readErr := os.ReadFile(path)
		if readErr == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	return pool, nil
}
func (n *node) readControl(ws *websocket.Conn, replies chan<- controlFrame) {
	for {
		var frame controlFrame
		if err := websocket.JSON.Receive(ws, &frame); err != nil {
			n.controlMu.Lock()
			if n.control == ws {
				n.control = nil
			}
			n.controlMu.Unlock()
			// Clearing the pointer alone leaked one file descriptor per
			// reconnect and left the dead socket in place. Close it and start
			// reconnecting immediately instead of waiting up to a full
			// heartbeat (plus two send/reply timeouts) for the next register.
			_ = ws.Close()
			if !n.closing.Load() {
				go n.pokeControlReconnect()
			}
			return
		}
		n.controlRxAt.Store(time.Now().UnixNano())
		if frame.Event == "topology" {
			var t topology
			if err := json.Unmarshal(frame.Body, &t); err != nil {
				n.logf("invalid pushed topology: %v", err)
			} else {
				n.applyTopology(t)
			}
			continue
		}
		if frame.Event == "symmetric_scan" {
			var event struct {
				PeerID    string `json:"peer_node_id"`
				SessionID string `json:"session_id"`
				Endpoint  string `json:"endpoint"`
			}
			if err := json.Unmarshal(frame.Body, &event); err != nil {
				n.logf("invalid symmetric scan event: %v", err)
			} else {
				go n.handleSymmetricScanEvent(event.PeerID, event.SessionID, event.Endpoint)
			}
			continue
		}
		if frame.Event == "symmetric_scan_ack" {
			var event struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(frame.Body, &event) == nil {
				n.symmetricMu.Lock()
				waiter := n.symmetricAckWaiters[event.SessionID]
				n.symmetricMu.Unlock()
				if waiter != nil {
					select {
					case waiter <- struct{}{}:
					default:
					}
				}
			}
			continue
		}
		if frame.Event == "update" {
			// The coordinator wants this node to download a new binary and
			// restart into it. Handled in a goroutine so the control loop
			// keeps servicing hole-punching traffic during the download.
			go n.handleUpdateEvent(frame.Body)
			continue
		}
		select {
		case replies <- frame:
		default:
			n.logf("unexpected control-plane reply discarded")
		}
	}
}
func (n *node) pokeControlReconnect() {
	var jitter [2]byte
	if _, err := rand.Read(jitter[:]); err == nil {
		time.Sleep(time.Duration(binary.BigEndian.Uint16(jitter[:])%2000) * time.Millisecond)
	}
	if n.closing.Load() {
		return
	}
	n.controlMu.Lock()
	alive := n.control != nil
	n.controlMu.Unlock()
	if alive {
		return // a concurrent request already reconnected
	}
	if err := n.register(); err != nil {
		n.logf("control reconnect after disconnect failed: %v", err)
	}
}
func (n *node) request(method, path string, in, out any) error {
	var body json.RawMessage
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = b
	}
	n.controlCall.Lock()
	defer n.controlCall.Unlock()
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		n.controlMu.Lock()
		_, err := n.connectControl()
		if err != nil {
			n.controlMu.Unlock()
			last = err
			continue
		}
		ws, replies := n.control, n.controlReply
		// A request that timed out may still deliver its reply later. Without
		// draining, the next request would consume that stale response and
		// act on a body/status that belongs to an earlier operation.
	drain:
		for {
			select {
			case <-replies:
			default:
				break drain
			}
		}
		frame := controlFrame{Method: method, Path: path, Body: body}
		_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Send(ws, frame); err != nil {
			n.controlMu.Unlock()
			last = err
		} else {
			_ = ws.SetWriteDeadline(time.Time{})
			n.controlMu.Unlock()
			responseTimer := time.NewTimer(10 * time.Second)
			select {
			case reply := <-replies:
				if !responseTimer.Stop() {
					<-responseTimer.C
				}
				if reply.Status < 200 || reply.Status > 299 {
					return fmt.Errorf("control plane: status %d: %s", reply.Status, reply.Error)
				}
				if out == nil {
					return nil
				}
				return json.Unmarshal(reply.Body, out)
			case <-responseTimer.C:
				last = errors.New("control websocket response timed out")
				// Frames are still arriving, so the coordinator is slow (for
				// example waiting on the single SQLite writer) rather than
				// unreachable. Keep the socket so the retry reuses it;
				// reconnecting here dropped healthy connections and turned one
				// slow reply into a reconnect and endpoint-refresh storm.
				if time.Since(time.Unix(0, n.controlRxAt.Load())) < 5*time.Second {
					continue
				}
			}
		}
		n.controlMu.Lock()
		if n.control == ws {
			_ = n.control.Close()
			n.control = nil
		}
		n.controlMu.Unlock()
	}
	return fmt.Errorf("control websocket request: %w", last)
}
func (n *node) refreshEndpointAfterControlReconnect() {
	n.refreshEndpointAttempt(1)
}
func (n *node) monitorControl(ctx context.Context) {
	ticker := time.NewTicker(controlCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		n.controlMu.Lock()
		connected := n.control != nil
		n.controlMu.Unlock()
		if !connected {
			continue
		}
		if time.Since(time.Unix(0, n.controlRxAt.Load())) < controlStaleTimeout {
			continue
		}
		n.logf("control channel silent for %s; forcing reconnect", controlStaleTimeout)
		n.controlMu.Lock()
		if n.control != nil {
			_ = n.control.Close()
			n.control = nil
		}
		n.controlMu.Unlock()
	}
}
