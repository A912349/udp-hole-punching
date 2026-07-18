package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"time"
)

const meshDNSFallback = "127.0.0.1:5353"

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
	b, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
				return net.JoinHostPort(f[1], "53")
			}
		}
	}
	return "1.1.1.1:53"
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
	addresses := []string{"127.0.0.1:53"}
	if n.c.meshIP != "" {
		addresses = append(addresses, net.JoinHostPort(n.c.meshIP, "53"))
	}
	addresses = append(addresses, meshDNSFallback)
	listeners := make([]net.PacketConn, 0, len(addresses))
	for _, address := range addresses {
		c, err := net.ListenPacket("udp4", address)
		if err != nil {
			n.logf("DNS listener %s unavailable: %v", address, err)
			continue
		}
		listeners = append(listeners, c)
	}
	if len(listeners) == 0 {
		n.logf("DNS disabled: no listen address available")
		return
	}
	defer func() {
		for _, c := range listeners {
			c.Close()
		}
	}()
	go func() {
		<-ctx.Done()
		for _, c := range listeners {
			c.Close()
		}
	}()
	upstream := systemResolver()
	for _, listener := range listeners {
		n.logf("DNS listening on %s, upstream %s", listener.LocalAddr(), upstream)
		go n.serveDNSListener(ctx, listener, upstream)
	}
	if err := configureSystemDNS(n.c.tun, n.c.meshIP); err != nil {
		n.logf("automatic DNS integration unavailable: %v (configure resolver to use %s)", err, n.c.meshIP)
	}
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
