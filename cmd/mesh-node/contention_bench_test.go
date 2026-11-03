package main

import (
	"crypto/rand"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"home-udp-mesh/internal/protocol"
)

// BenchmarkRememberFastContention hammers rememberFast() from many concurrent
// workers with distinct packet IDs (insert path, no eviction) to measure how
// the dedup lock scales: a single global lock serializes everyone, sharded
// locks let workers run in parallel.
func BenchmarkRememberFastContention(b *testing.B) {
	id, _ := protocol.NewIdentity()
	n := newBenchNode(id, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), nil)
	// Precompute distinct IDs so the benchmark only measures lock/insert cost.
	idPool := make([][12]byte, 4096)
	for i := range idPool {
		rand.Read(idPool[i][:])
		idPool[i][11] = byte(i)
		idPool[i][10] = byte(i >> 8)
	}
	for _, w := range []int{1, 8, 32, 64} {
		b.Run("w"+strconv.Itoa(w), func(b *testing.B) {
			var wg sync.WaitGroup
			per := b.N / w
			for g := 0; g < w; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					for i := 0; i < per; i++ {
						// wrap around the pool of distinct IDs
						idx := (g*1000 + i) % len(idPool)
						n.rememberFast(idPool[idx])
					}
				}(g)
			}
			wg.Wait()
		})
	}
}
