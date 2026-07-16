// Command punch-client preserves the stand-alone UDP hole-punching experiment.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const cookie uint32 = 0x2112A442

func main() {
	relay := flag.String("relay", "http://94.159.96.158:8001", "legacy rendezvous URL")
	session := flag.String("session", "", "session ID")
	flag.Parse()
	if *session == "" {
		fmt.Fprint(os.Stderr, "Session ID: ")
		fmt.Fscan(os.Stdin, session)
	}
	if *session == "" {
		fatal("session ID is required")
	}
	c, e := net.ListenUDP("udp4", &net.UDPAddr{})
	if e != nil {
		fatal(e.Error())
	}
	defer c.Close()
	external, nat, e := stun(c)
	if e != nil {
		fatal(e.Error())
	}
	fmt.Printf("external endpoint %s; NAT: %s\n", external, nat)
	peer, e := rendezvous(*relay, *session, nat, external)
	if e != nil {
		fatal(e.Error())
	}
	fmt.Printf("peer (%s): %s\n", peer.nat, peer.endpoint)
	a, e := net.ResolveUDPAddr("udp", peer.endpoint)
	if e != nil {
		fatal(e.Error())
	}
	if nat == "cone" {
		if e = punchCone(c, a); e != nil {
			fatal(e.Error())
		}
	} else {
		if e = punchBurst(a); e != nil {
			fatal(e.Error())
		}
		return
	}
	chat(c, a)
}

type rendezvousReply struct {
	Status string `json:"status"`
	Peer   string `json:"peer"`
	NAT    string `json:"peer_nat_type"`
}
type peerInfo struct{ endpoint, nat string }

func rendezvous(base, session, nat, external string) (peerInfo, error) {
	id := make([]byte, 4)
	rand.Read(id)
	b, _ := json.Marshal(map[string]string{"session": session, "id": nat + "-" + hex.EncodeToString(id), "external": external, "nat_type": nat})
	r, e := http.Post(strings.TrimRight(base, "/")+"/register", "application/json", bytes.NewReader(b))
	if e != nil {
		return peerInfo{}, e
	}
	r.Body.Close()
	if r.StatusCode/100 != 2 {
		return peerInfo{}, errors.New("rendezvous registration failed")
	}
	u := fmt.Sprintf("%s/wait?session=%s&id=%s-%s&timeout=60", strings.TrimRight(base, "/"), session, nat, hex.EncodeToString(id))
	r, e = http.Get(u)
	if e != nil {
		return peerInfo{}, e
	}
	defer r.Body.Close()
	var x rendezvousReply
	if json.NewDecoder(r.Body).Decode(&x) != nil || r.StatusCode != 200 || x.Status != "ready" {
		return peerInfo{}, errors.New("rendezvous timeout")
	}
	return peerInfo{x.Peer, x.NAT}, nil
}
func stun(c *net.UDPConn) (string, string, error) {
	servers := []string{"stun.nextcloud.com:3478", "stun.miwifi.com:3478", "stun.sipgate.net:3478"}
	var got []string
	for _, server := range servers {
		a, e := net.ResolveUDPAddr("udp", server)
		if e != nil {
			continue
		}
		var tx [12]byte
		rand.Read(tx[:])
		q := make([]byte, 20)
		binary.BigEndian.PutUint16(q, 1)
		binary.BigEndian.PutUint32(q[4:], cookie)
		copy(q[8:], tx[:])
		c.SetReadDeadline(time.Now().Add(4 * time.Second))
		c.WriteToUDP(q, a)
		b := make([]byte, 2048)
		l, _, e := c.ReadFromUDP(b)
		if e != nil || l < 20 || !bytes.Equal(b[8:20], tx[:]) {
			continue
		}
		for p := 20; p+4 <= l; {
			t, n := binary.BigEndian.Uint16(b[p:]), int(binary.BigEndian.Uint16(b[p+2:]))
			if p+4+n > l {
				break
			}
			v := b[p+4 : p+4+n]
			if t == 0x0020 && len(v) >= 8 && v[1] == 1 {
				port := binary.BigEndian.Uint16(v[2:4]) ^ uint16(cookie>>16)
				ip := binary.BigEndian.Uint32(v[4:8]) ^ cookie
				got = append(got, fmt.Sprintf("%d.%d.%d.%d:%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port))
				break
			}
			p += 4 + (n+3)&^3
		}
		if len(got) == 2 {
			if got[0] == got[1] {
				return got[0], "cone", nil
			}
			return got[0], "symmetric", nil
		}
	}
	if len(got) > 0 {
		return got[0], "cone", nil
	}
	return "", "", errors.New("no STUN server responded")
}
func punchCone(c *net.UDPConn, a *net.UDPAddr) error {
	done := make(chan *net.UDPAddr, 1)
	go func() {
		b := make([]byte, 64)
		for {
			l, x, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			if string(b[:l]) == "cone_punch" {
				c.WriteToUDP([]byte("HELLO_CONE"), x)
			}
			if string(b[:l]) == "HELLO_CONE" || string(b[:l]) == "HELLO_CONE_ACK" {
				c.WriteToUDP([]byte("HELLO_CONE_ACK"), x)
				done <- x
				return
			}
		}
	}()
	for start := a.Port - 1000; start <= 65535; start += 3000 {
		for p := max(1, start); p <= min(65535, start+2999); p++ {
			c.WriteToUDP([]byte("cone_punch"), &net.UDPAddr{IP: a.IP, Port: p})
		}
		select {
		case x := <-done:
			*a = *x
			return nil
		case <-time.After(800 * time.Millisecond):
		}
	}
	return errors.New("all UDP ports scanned without handshake")
}
func punchBurst(a *net.UDPAddr) error {
	for i := 0; i < 500; i++ {
		c, e := net.ListenUDP("udp4", &net.UDPAddr{})
		if e != nil {
			continue
		}
		c.WriteToUDP([]byte("burst_punch"), a)
		c.SetReadDeadline(time.Now().Add(45 * time.Second))
		b := make([]byte, 64)
		_, peer, e := c.ReadFromUDP(b)
		if e == nil {
			c.WriteToUDP([]byte("HELLO_MOBILE"), peer)
			chat(c, peer)
			return nil
		}
		c.Close()
	}
	return errors.New("symmetric burst timed out")
}
func chat(c *net.UDPConn, a *net.UDPAddr) {
	go func() {
		b := make([]byte, 65535)
		for {
			l, p, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			if string(b[:l]) != "KEEPALIVE" {
				fmt.Printf("\n[%s] %s\n> ", p, string(b[:l]))
			}
		}
	}()
	go func() {
		for range time.Tick(15 * time.Second) {
			c.WriteToUDP([]byte("KEEPALIVE"), a)
		}
	}()
	s := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !s.Scan() {
			return
		}
		x := s.Bytes()
		if len(x) == 0 {
			return
		}
		c.WriteToUDP(x, a)
	}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func fatal(s string) { fmt.Fprintln(os.Stderr, "error:", s); os.Exit(1) }

var _ = io.EOF
