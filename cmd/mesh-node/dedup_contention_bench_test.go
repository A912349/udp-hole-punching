package main

import (
	"crypto/rand"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"home-udp-mesh/internal/protocol"
)

// Two designs of the fast-path dedup, measured under identical concurrency:
//   - globalLock:  one mutex + map + sliding ring (pre-optimization design)
//   - sharded:     64 sharded mutexes/maps/rings (current design)
// This isolates the lock-contention cost of rememberFast() alone.

const shardCount = 64

type globalDedup struct {
	mu         sync.Mutex
	set        map[[12]byte]struct{}
	ring       [][12]byte
	next       int
	cap        int
}

type shardedDedup struct {
	mu         [shardCount]sync.Mutex
	set        [shardCount]map[[12]byte]struct{}
	ring       [shardCount][][12]byte
	next       [shardCount]int
	cap        int
}

func newGlobalDedup(cap int) *globalDedup {
	return &globalDedup{set: make(map[[12]byte]struct{}), cap: cap}
}
func newShardedDedup(cap int) *shardedDedup {
	return &shardedDedup{cap: cap}
}

func (d *globalDedup) remember(id [12]byte) {
	d.mu.Lock()
	if _, ok := d.set[id]; ok {
		d.mu.Unlock()
		return
	}
	if len(d.ring) < d.cap {
		d.ring = append(d.ring, id)
	} else {
		delete(d.set, d.ring[d.next])
		d.ring[d.next] = id
		d.next++
		if d.next == d.cap {
			d.next = 0
		}
	}
	d.set[id] = struct{}{}
	d.mu.Unlock()
}

func (d *shardedDedup) remember(id [12]byte) {
	var h uint32 = 2166136261
	for _, b := range id {
		h ^= uint32(b)
		h *= 16777619
	}
	si := int(h % shardCount)
	mu := &d.mu[si]
	mu.Lock()
	if d.set[si] == nil {
		d.set[si] = make(map[[12]byte]struct{}, d.cap)
	}
	if _, ok := d.set[si][id]; ok {
		mu.Unlock()
		return
	}
	ring := d.ring[si]
	if len(ring) < d.cap {
		d.ring[si] = append(ring, id)
	} else {
		delete(d.set[si], d.ring[si][d.next[si]])
		d.ring[si][d.next[si]] = id
		d.next[si]++
		if d.next[si] == d.cap {
			d.next[si] = 0
		}
	}
	d.set[si][id] = struct{}{}
	mu.Unlock()
}

// BenchmarkCryptoLookupContention compares the per-packet crypto lookup:
//   old: peerKey() RLock + peerCipher() second RLock  (2 RLocks, 2 call sites)
//   new: peerCrypto() single RLock                    (1 RLock)
// measured on a node with a warm cache (cache-hit path, the common case).
func BenchmarkCryptoLookupContention(b *testing.B) {
	id, _ := protocol.NewIdentity()
	pubID, _ := protocol.NewIdentity()
	n := newBenchNode(id, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), nil)
	n.dir[pubID.ID] = &peer{ID: pubID.ID, Public: pubID.Public}
	// Warm the cache so the benchmark exercises the cache-hit path only.
	if _, _, e := n.peerCrypto(pubID.ID); e != nil {
		b.Fatalf("warm failed: %v", e)
	}

	old := func(per int) {
		for i := 0; i < per; i++ {
			n.mu.RLock()
			_ = n.sharedKeys[pubID.ID].key
			n.mu.RUnlock()
			n.mu.RLock()
			_ = n.sharedKeys[pubID.ID].aead
			n.mu.RUnlock()
		}
	}
	new := func(per int) {
		for i := 0; i < per; i++ {
			_, _, _ = n.peerCrypto(pubID.ID)
		}
	}

	for _, d := range []struct {
		name string
		fn   func(int)
	}{
		{"old-2-locks", old},
		{"new-1-lock", new},
	} {
		for _, w := range []int{1, 8, 32, 64} {
			b.Run(d.name+"/w"+strconv.Itoa(w), func(b *testing.B) {
				per := b.N / w
				var wg sync.WaitGroup
				for g := 0; g < w; g++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						d.fn(per)
					}()
				}
				wg.Wait()
			})
		}
	}
}

// BenchmarkDedupContention compares both designs under the same concurrency.
func BenchmarkDedupContention(b *testing.B) {
	idPool := make([][12]byte, 8192)
	for i := range idPool {
		rand.Read(idPool[i][:])
		idPool[i][11] = byte(i)
		idPool[i][10] = byte(i >> 8)
	}
	cap := 10000 / shardCount // 156 per shard, total 9984

	for _, d := range []struct {
		name  string
		build func(cap int) func([12]byte)
	}{
		{"global", func(cap int) func([12]byte) {
			dg := newGlobalDedup(cap)
			return func(id [12]byte) { dg.remember(id) }
		}},
		{"sharded", func(cap int) func([12]byte) {
			ds := newShardedDedup(cap)
			return func(id [12]byte) { ds.remember(id) }
		}},
	} {
		for _, w := range []int{1, 8, 32, 64} {
			b.Run(d.name+"/w"+strconv.Itoa(w), func(b *testing.B) {
				fn := d.build(cap)
				var wg sync.WaitGroup
				per := b.N / w
				for g := 0; g < w; g++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := 0; i < per; i++ {
							fn(idPool[(g*7919 + i) % len(idPool)])
						}
					}()
				}
				wg.Wait()
			})
		}
	}
}
