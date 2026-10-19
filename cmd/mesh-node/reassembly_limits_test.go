package main

// These tests cover reassembly limits behavior and regression cases.
import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func testFragment(index, count uint16, size int) []byte {
	fragment := make([]byte, 12+size)
	binary.BigEndian.PutUint16(fragment[8:10], index)
	binary.BigEndian.PutUint16(fragment[10:12], count)
	return fragment
}

// Measure complete two-fragment assembly, including its bounded delivery copy.
func BenchmarkReassemblyTwoFragments(b *testing.B) {
	n := &node{
		reassembly:    make(map[string]*reassembly),
		deliverQueues: []chan deliverFrame{make(chan deliverFrame, 1)},
	}
	n.deliverPool.New = func() any { return make([]byte, maxTUN) }
	first, second := testFragment(0, 2, 600), testFragment(1, 2, 600)
	now := time.Now()
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.acceptIPFragmentAt("source", first, now)
		n.acceptIPFragmentAt("source", second, now)
		frame := <-n.deliverQueues[0]
		n.deliverPool.Put(frame.data[:maxTUN])
	}
}

func TestReassemblyAcceptsExactMTUOutOfOrder(t *testing.T) {
	n := &node{
		reassembly:    make(map[string]*reassembly),
		deliverQueues: []chan deliverFrame{make(chan deliverFrame, 1)},
	}
	n.deliverPool.New = func() any { return make([]byte, maxTUN) }
	first := testFragment(0, 2, 600)
	second := testFragment(1, 2, maxTUN-600)
	first[12] = 0x45
	second[12] = 42
	now := time.Now()
	n.acceptIPFragmentAt("source", second, now)
	n.acceptIPFragmentAt("source", first, now)
	if len(n.reassembly) != 0 {
		t.Fatal("completed assembly retained")
	}
	select {
	case frame := <-n.deliverQueues[0]:
		want := append(append([]byte(nil), first[12:]...), second[12:]...)
		if !bytes.Equal(frame.data, want) {
			t.Fatal("incorrect assembled payload")
		}
	default:
		t.Fatal("valid exact-MTU assembly was not delivered")
	}
}

func TestReassemblyRejectsOversizedFragment(t *testing.T) {
	n := &node{reassembly: make(map[string]*reassembly)}
	n.acceptIPFragmentAt("source", testFragment(0, 2, maxTUN+1), time.Now())
	if len(n.reassembly) != 0 {
		t.Fatal("oversized fragment retained in reassembly")
	}
}

func TestReassemblyRejectsOversizedTotal(t *testing.T) {
	n := &node{reassembly: make(map[string]*reassembly)}
	now := time.Now()
	n.acceptIPFragmentAt("source", testFragment(0, 3, maxTUN-1), now)
	if len(n.reassembly) != 1 {
		t.Fatal("valid incomplete fragment rejected")
	}
	n.acceptIPFragmentAt("source", testFragment(1, 3, 2), now)
	if len(n.reassembly) != 0 {
		t.Fatal("assembly exceeding maxTUN retained")
	}
}

func TestReassemblyDuplicateDoesNotReplaceOrRefresh(t *testing.T) {
	n := &node{reassembly: make(map[string]*reassembly)}
	now := time.Now()
	first := testFragment(0, 2, 20)
	first[12] = 42
	n.acceptIPFragmentAt("source", first, now)
	n.acceptIPFragmentAt("source", testFragment(0, 2, 30), now.Add(time.Second))
	for _, state := range n.reassembly {
		if len(state.chunks[0]) != 20 || state.chunks[0][0] != 42 {
			t.Fatal("duplicate replaced stored fragment")
		}
		if !state.receivedAt.Equal(now) {
			t.Fatal("duplicate extended reassembly lifetime")
		}
	}
	// Repeated duplicates must not keep the original assembly alive forever.
	n.acceptIPFragmentAt("other", testFragment(0, 2, 20), now.Add(10500*time.Millisecond))
	if len(n.reassembly) != 1 {
		t.Fatal("expired assembly kept alive by duplicate")
	}
}
