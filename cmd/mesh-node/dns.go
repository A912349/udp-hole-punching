package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

const (
	meshDNSFallback      = "127.0.0.1:5353"
	meshDNSVirtualPrefix = "10.77."
)

func dnsQuestion(packet []byte) (string, int, bool) {
	if len(packet) < 17 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return "", 0, false
	}
	labels, p := []string{}, 12
	for p < len(packet) && packet[p] != 0 {
		l := int(packet[p])
		p++
		if l == 0 || p+l > len(packet) {
			return "", 0, false
		}
		labels = append(labels, string(packet[p:p+l]))
		p += l
	}
	if p+5 > len(packet) {
		return "", 0, false
	}
	return strings.ToLower(strings.Join(labels, ".")), p + 5, binary.BigEndian.Uint16(packet[p+1:p+3]) == 1
}

func dnsAnswer(query []byte, questionEnd int, ip net.IP) []byte {
	out := append([]byte(nil), query[:questionEnd]...)
	binary.BigEndian.PutUint16(out[2:4], 0x8180)
	binary.BigEndian.PutUint16(out[6:8], 1)
	out = append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
	out = append(out, ip.To4()...)
	return out
}

func systemResolver() string {
	return platformSystemResolver()
}

// resolverFromResolvConf returns an upstream resolver, ignoring the address
// range owned by the mesh. A previous mesh-node may have installed its mesh
// address in resolv.conf; using that address as an upstream would make normal
// DNS queries recurse through another mesh-node instance.
func resolverFromResolvConf(text string) string {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || f[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(f[1])
		if ip == nil || isMeshDNSAddress(ip) {
			continue
		}
		return net.JoinHostPort(ip.String(), "53")
	}
	return ""
}

func isMeshDNSAddress(ip net.IP) bool {
	ip = ip.To4()
	return ip != nil && strings.HasPrefix(ip.String(), meshDNSVirtualPrefix)
}

func (n *node) meshDNSIP(name string) net.IP {
	name = strings.TrimSuffix(strings.ToLower(name), ".mesh")
	n.mu.RLock()
	defer n.mu.RUnlock()
	var match *peer
	for id, p := range n.dir {
		for _, record := range p.DNSRecords {
			if name == strings.ToLower(record.Name) {
				return net.ParseIP(record.VirtualIP)
			}
		}
		if name == strings.ToLower(p.Name) || name == id {
			match = p
			break
		}
		if len(name) >= 8 && strings.HasPrefix(id, name) {
			if match != nil {
				return nil
			}
			match = p
		}
	}
	if match == nil {
		return nil
	}
	return net.ParseIP(match.MeshIP)
}

func (n *node) serveDNS(ctx context.Context) {
	listener, dnsTarget, err := n.openDNSListener()
	if err != nil {
		n.logf("DNS disabled: %v", err)
		return
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	upstream := systemResolver()
	n.logf("DNS listening on %s, upstream %s", listener.LocalAddr(), upstream)
	go n.serveDNSListener(ctx, listener, upstream)
	if err := configureSystemDNS(n.c.tun, n.c.meshIP, dnsTarget); err != nil {
		n.logf("automatic DNS integration unavailable: %v (configure resolver to use %s)", err, dnsTarget)
	}
}

// openDNSListener prefers the node's unique mesh address. The old design also
// claimed 127.0.0.1:53 and a shared 127.0.0.1:5353 socket, which caused noisy
// bind failures whenever another resolver or another mesh-node was present on
// the same host. A loopback listener is only a fallback when the mesh address
// cannot be bound, and its port is allowed to move if 5353 is occupied.
func (n *node) openDNSListener() (net.PacketConn, string, error) {
	if n.c.meshIP != "" {
		address := net.JoinHostPort(n.c.meshIP, "53")
		listener, err := net.ListenPacket("udp4", address)
		if err == nil {
			return listener, address, nil
		}
		n.logf("DNS mesh listener %s unavailable: %v; trying local fallback", address, err)
	}

	listener, err := net.ListenPacket("udp4", meshDNSFallback)
	if err != nil {
		n.logf("DNS local fallback %s unavailable: %v; using an ephemeral port", meshDNSFallback, err)
		listener, err = net.ListenPacket("udp4", "127.0.0.1:0")
	}
	if err != nil {
		return nil, "", err
	}
	return listener, dnsTargetForListener(listener.LocalAddr()), nil
}

func dnsTargetForListener(address net.Addr) string {
	host, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	if host == "127.0.0.1" {
		return host + "#" + port
	}
	return address.String()
}

func (n *node) serveDNSListener(ctx context.Context, c net.PacketConn, upstream string) {
	buf := make([]byte, 4096)
	for {
		size, client, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:size]...)
		go func() {
			name, end, isA := dnsQuestion(query)
			if isA {
				if ip := n.meshDNSIP(name); ip != nil {
					_, _ = c.WriteTo(dnsAnswer(query, end, ip), client)
					return
				}
			}
			u, err := net.DialTimeout("udp", upstream, 2*time.Second)
			if err != nil {
				return
			}
			defer u.Close()
			_ = u.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = u.Write(query); err != nil {
				return
			}
			response := make([]byte, 4096)
			l, err := u.Read(response)
			if err == nil {
				_, _ = c.WriteTo(response[:l], client)
			}
		}()
	}
}
