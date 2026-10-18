package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

// benchTUN counts delivered packets instead of writing to a kernel device so
// the benchmark measures the full userspace data plane without kernel TUN I/O.
type benchTUN struct{ delivered atomic.Int64 }

func (t *benchTUN) Read([]byte) (int, error)    { return 0, nil }
func (t *benchTUN) Write(p []byte) (int, error) { t.delivered.Add(1); return len(p), nil }
func (t *benchTUN) Close() error                { return nil }

func benchMeshIP(n *node) netip.Addr {
	v := n.meshIPv4.Load()
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// newBenchNode builds a minimal node with the pieces the fast data plane uses.
func newBenchNode(id *protocol.Identity, tun *benchTUN, meshIP netip.Addr, conn *net.UDPConn) *node {
	decoded, _ := hex.DecodeString(id.ID)
	var idBinary [16]byte
	copy(idBinary[:], decoded)
	n := &node{
		c:            config{role: "client", bind: "127.0.0.1"},
		id:           id,
		idBinary:     idBinary,
		key:          make([]byte, 32),
		conn:         conn,
		dir:          map[string]*peer{},
		neighbors:    map[string]*peer{},
		routes:       map[string]string{},
		meshNodes:    map[netip.Addr]string{},
		fastSeen:     make(map[[12]byte]struct{}, fastSeenCapacity),
		fastSeenRing: make([][12]byte, 0, fastSeenCapacity),
		sharedKeys:   map[string]cachedKey{},
		tun:          tun,
		startedAt:    time.Now(),
	}
	var as4 [4]byte = meshIP.As4()
	n.meshIPv4.Store(binary.BigEndian.Uint32(as4[:]))
	n.sendPool.New = func() any { return make([]byte, maxFastFrame) }
	return n
}

// wireNodes makes a and b direct neighbors with a precomputed shared cipher.
func wireNodes(ctx context.Context, a, b *node, addrA, addrB *net.UDPAddr) {
	key, _ := protocol.SharedKey(a.id.Private, b.id.Public)
	aead, _ := protocol.NewAEAD(key)
	aNonces, _ := protocol.NewNonceSequence()
	bNonces, _ := protocol.NewNonceSequence()

	wire := func(self, other *node, otherAddr *net.UDPAddr, nonces *protocol.NonceSequence) {
		var peerID [16]byte
		decoded, _ := hex.DecodeString(other.id.ID)
		copy(peerID[:], decoded)
		self.dir[other.id.ID] = &peer{ID: other.id.ID, Public: other.id.Public, last: otherAddr, lastRX: time.Now()}
		self.neighbors[other.id.ID] = &peer{ID: other.id.ID, last: otherAddr, lastRX: time.Now()}
		self.routes[other.id.ID] = other.id.ID
		self.meshNodes[benchMeshIP(self)] = self.id.ID
		self.meshNodes[benchMeshIP(other)] = other.id.ID
		self.sharedKeys[other.id.ID] = cachedKey{
			public:  other.id.Public,
			key:     key,
			aead:    aead,
			nonces:  nonces,
			peerID:  peerID,
			sealAAD: []byte(self.id.ID + ":" + other.id.ID),
			openAAD: []byte(other.id.ID + ":" + self.id.ID),
		}
		self.startFastWorkers(ctx)
		self.startDeliverWorker(ctx)
	}
	wire(a, b, addrB, aNonces)
	wire(b, a, addrA, bNonces)
}

// BenchmarkTwoNodeDataPlane pumps fixed-size IP packets from node A through
// the real sendIP -> UDP -> fast() -> deliver pipeline into node B's TUN.
func BenchmarkTwoNodeDataPlane(b *testing.B) {
	for _, size := range []int{520, 1279} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			idA, _ := protocol.NewIdentity()
			idB, _ := protocol.NewIdentity()
			tunA := &benchTUN{}
			tunB := &benchTUN{}
			connA, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			connB, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			defer connA.Close()
			defer connB.Close()
			addrA := connA.LocalAddr().(*net.UDPAddr)
			addrB := connB.LocalAddr().(*net.UDPAddr)
			configureUDPSocket(connA)
			configureUDPSocket(connB)

			a := newBenchNode(idA, tunA, netip.AddrFrom4([4]byte{10, 77, 0, 5}), connA)
			nodeB := newBenchNode(idB, tunB, netip.AddrFrom4([4]byte{10, 77, 0, 6}), connB)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wireNodes(ctx, a, nodeB, addrA, addrB)

			// Receiver loop: real UDP reads feeding the fast-path queue.
			go func() {
				buf := make([]byte, 65536)
				for {
					length, address, err := connB.ReadFromUDP(buf)
					if err != nil {
						return
					}
					owned := make([]byte, length)
					copy(owned, buf[:length])
					nodeB.enqueueFast(owned, address)
				}
			}()

			packet := make([]byte, size)
			packet[0] = 0x45
			copy(packet[12:16], []byte{10, 77, 0, 5})
			copy(packet[16:20], []byte{10, 77, 0, 6})
			b.SetBytes(int64(size))
			b.ResetTimer()
			// Window the sender so queues stay below overload: we measure the
			// steady-state pipeline, not the drop policy. Allow small slack for
			// incidental kernel-level UDP loss under burst.
			sent := 0
			budget := b.N + b.N/100 + 128
			lastGot, lastProgress := int64(0), time.Now()
			for tunB.delivered.Load() < int64(b.N) {
				got := tunB.delivered.Load()
				if got != lastGot {
					lastGot, lastProgress = got, time.Now()
				}
				if time.Since(lastProgress) > 5*time.Second {
					b.Fatalf("stalled: sent=%d delivered=%d/%d queueDrops=%d deliveryDrops=%d",
						sent, got, b.N, nodeB.stats.queueDrops.Load(), nodeB.stats.deliveryDrops.Load())
				}
				if sent < budget && sent-int(got) < 256 {
					if a.sendIP(nodeB.id.ID, packet) {
						sent++
					}
					continue
				}
				time.Sleep(20 * time.Microsecond)
			}
			b.StopTimer()
			got := tunB.delivered.Load()
			if got < int64(b.N)*99/100 {
				b.Fatalf("delivered only %d of %d packets (sent=%d)", got, b.N, sent)
			}
			b.ReportMetric(float64(got)/b.Elapsed().Seconds(), "delivered-pps")
		})
	}
}
