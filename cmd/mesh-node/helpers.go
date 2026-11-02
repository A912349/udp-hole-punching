package main

import (
	"runtime"
	"os"
	"os/exec"
	"log"
	"strings"
	"net/url"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	_ "net/http/pprof"
	"strconv"
	"time"

)

func stunEndpoint(c *net.UDPConn, onPacket func([]byte, *net.UDPAddr), bootstrap ...string) (string, string, error) {
	// STUN shares the node's UDP socket with the receive loop. Always restore
	// the socket deadline so a probe cannot leave the data plane with a stale
	// two-second read timeout.
	defer c.SetReadDeadline(time.Time{})
	servers := []string{
		"stun.nextcloud.com:3478",
		"stun.miwifi.com:3478",
		"stun.sipgate.net:3478",
		"stun.zadarma.com:3478",
		"stun.ipfire.org:3478",
	}
	type resolvedServer struct {
		address *net.UDPAddr
		err     error
	}
	resolved := make(chan resolvedServer, len(servers))
	for _, server := range servers {
		go func(server string) {
			address, err := resolveMeshUDPAddr(server, bootstrap...)
			resolved <- resolvedServer{address: address, err: err}
		}(server)
	}
	pending := make(map[[12]byte]struct{}, len(servers))
	resolveFailures := 0
	writeFailures := 0
	for range servers {
		result := <-resolved
		if result.err != nil {
			resolveFailures++
			continue
		}
		var transaction [12]byte
		if _, err := rand.Read(transaction[:]); err != nil {
			continue
		}
		request := make([]byte, 20)
		binary.BigEndian.PutUint16(request, 1)
		binary.BigEndian.PutUint32(request[4:], 0x2112A442)
		copy(request[8:], transaction[:])
		if _, err := c.WriteToUDP(request, result.address); err == nil {
			pending[transaction] = struct{}{}
		} else {
			writeFailures++
		}
	}
	if len(pending) == 0 {
		return "", "", fmt.Errorf("no STUN server could be contacted (resolved=%d/%d, write failures=%d)", len(servers)-resolveFailures, len(servers), writeFailures)
	}

	// Send all probes before waiting. The previous sequential implementation
	// could spend three seconds on every unavailable server, delaying startup
	// and network recovery by up to nine seconds.
	_ = c.SetReadDeadline(time.Now().Add(stunProbeTimeout))
	mapped := make([]string, 0, 2)
	buffer := make([]byte, 2048)
	for len(pending) > 0 && len(mapped) < 2 {
		length, address, err := c.ReadFromUDP(buffer)
		if err != nil {
			break
		}
		if length < 20 {
			if onPacket != nil {
				onPacket(append([]byte(nil), buffer[:length]...), address)
			}
			continue
		}
		var transaction [12]byte
		copy(transaction[:], buffer[8:20])
		if _, ok := pending[transaction]; !ok {
			if onPacket != nil {
				onPacket(append([]byte(nil), buffer[:length]...), address)
			}
			continue
		}
		if endpoint, ok := stunMappedEndpoint(buffer[:length], transaction); ok {
			delete(pending, transaction)
			mapped = append(mapped, endpoint)
		}
	}
	if len(mapped) == 0 {
		return "", "", errors.New("no STUN server responded")
	}
	if len(mapped) == 1 || mapped[0] == mapped[1] {
		return mapped[0], "cone", nil
	}
	return mapped[0], "symmetric", nil
}
func stunMappedEndpoint(response []byte, transaction [12]byte) (string, bool) {
	if len(response) < 20 || binary.BigEndian.Uint16(response) != 0x0101 ||
		binary.BigEndian.Uint32(response[4:8]) != 0x2112A442 || !bytes.Equal(response[8:20], transaction[:]) {
		return "", false
	}
	for offset := 20; offset+4 <= len(response); {
		typ, size := binary.BigEndian.Uint16(response[offset:]), int(binary.BigEndian.Uint16(response[offset+2:]))
		end := offset + 4 + size
		if end > len(response) {
			return "", false
		}
		value := response[offset+4 : end]
		if typ == 0x0020 && len(value) >= 8 && value[1] == 1 {
			port := binary.BigEndian.Uint16(value[2:4]) ^ 0x2112
			ip := binary.BigEndian.Uint32(value[4:8]) ^ 0x2112A442
			return fmt.Sprintf("%d.%d.%d.%d:%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port), true
		}
		offset += 4 + (size+3)&^3
	}
	return "", false
}
func resolveMeshUDPAddr(address string, bootstrap ...string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.ResolveUDPAddr("udp4", address)
	}
	// Prefer the platform resolver with an explicit udp4 network. This avoids
	// IPv6 answers and is more reliable on minimal Linux/container images where
	// the custom resolver has no usable nameserver configuration.
	if len(bootstrap) == 0 {
		if resolved, resolveErr := net.ResolveUDPAddr("udp4", address); resolveErr == nil && resolved.IP.To4() != nil {
			return resolved, nil
		}
	}
	if resolved, resolveErr := resolveUDPAddrWithResolver(address, meshResolver(bootstrap...)); resolveErr == nil {
		return resolved, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := meshResolver().LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, raw := range ips {
		if ip := net.ParseIP(raw).To4(); ip != nil {
			p, err := net.LookupPort("udp", port)
			if err != nil {
				return nil, err
			}
			return &net.UDPAddr{IP: ip, Port: p}, nil
		}
	}
	return nil, errors.New("DNS returned no IPv4 address")
}
func resolveUDPAddrWithResolver(address string, resolver *net.Resolver) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	for _, raw := range ips {
		if ip := net.ParseIP(raw).To4(); ip != nil {
			return &net.UDPAddr{IP: ip, Port: p}, nil
		}
	}
	return nil, errors.New("DNS returned no IPv4 address")
}

func (n *node) debugStartupNetwork() {
	n.logf("debug startup: server=%s bind=%s udp=%s role=%s nat=%s tun=%s auto_tun=%t", n.c.server, n.c.bind, n.conn.LocalAddr(), n.c.role, n.c.nat, n.c.tun, n.c.autoTUN)
	interfaces, err := net.Interfaces()
	if err != nil {
		n.logf("debug network interfaces: %v", err)
	} else {
		for _, iface := range interfaces {
			addrs, addrErr := iface.Addrs()
			if addrErr != nil {
				n.logf("debug interface %s flags=%s addresses unavailable: %v", iface.Name, iface.Flags, addrErr)
				continue
			}
			n.logf("debug interface %s index=%d flags=%s mtu=%d addresses=%v", iface.Name, iface.Index, iface.Flags, iface.MTU, addrs)
		}
	}
	if u, err := url.Parse(strings.TrimRight(n.c.server, "/")); err != nil {
		n.logf("debug coordinator URL parse failed: %v", err)
	} else {
		host := u.Hostname()
		n.logf("debug coordinator scheme=%s host=%s port=%s", u.Scheme, host, u.Port())
		if host != "" {
			addresses, resolveErr := meshResolver().LookupHost(context.Background(), host)
			if resolveErr != nil {
				n.logf("debug DNS coordinator %s failed: %v", host, resolveErr)
			} else {
				n.logf("debug DNS coordinator %s -> %v", host, addresses)
			}
		}
	}
	for _, stun := range []string{"stun.nextcloud.com:3478", "stun.miwifi.com:3478", "stun.sipgate.net:3478"} {
		addresses, resolveErr := meshResolver().LookupHost(context.Background(), strings.TrimSuffix(strings.Split(stun, ":")[0], "]"))
		if resolveErr != nil {
			n.logf("debug DNS STUN %s failed: %v", stun, resolveErr)
		} else {
			n.logf("debug DNS STUN %s -> %v", stun, addresses)
		}
	}
}
func (n *node) logf(f string, a ...any) { log.Printf("[%s] %s", n.id.ID[:8], fmt.Sprintf(f, a...)) }
func (n *node) debugf(f string, a ...any) {
	if n.c.debug {
		n.logf(f, a...)
	}
}
func (n *node) resolve(value string) (string, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.dir[value] != nil {
		return value, nil
	}
	var a []string
	for id := range n.dir {
		if strings.HasPrefix(id, value) {
			a = append(a, id)
		}
	}
	if len(a) == 1 {
		return a[0], nil
	}
	return "", errors.New("unknown or ambiguous node ID")
}
func androidRuntime() bool {
	if runtime.GOOS == "android" {
		return true
	}
	// Android binaries are often built as linux/arm64 for Termux/Magisk.
	// Detect the platform by the Android property service in that case.
	if _, err := os.Stat("/system/bin/getprop"); err == nil {
		return true
	}
	if _, err := exec.LookPath("getprop"); err == nil {
		return true
	}
	return false
}
