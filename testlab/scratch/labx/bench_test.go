package bench

import (
	"testing"
)

// Hot path stand-in for the data plane: scan the payload once.
func hot(a []byte) uint64 {
	var s uint64
	for i := 0; i < len(a); i++ {
		s += uint64(a[i]) * 3
	}
	return s
}

func cold(a []byte) uint64 {
	var s uint64
	for i := 0; i < len(a); i++ {
		s ^= uint64(a[i]) + 7
	}
	return s
}

func BenchmarkHotCold(b *testing.B) {
	a := make([]byte, 4096)
	acc := uint64(0)
	for i := 0; i < b.N; i++ {
		if (i % 3) != 0 {
			acc = hot(a)
		} else {
			acc = cold(a)
		}
	}
	_ = acc
}
