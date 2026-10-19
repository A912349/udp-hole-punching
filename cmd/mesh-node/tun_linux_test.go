//go:build linux

package main

// These tests cover tun linux behavior and regression cases.
import (
	"bytes"
	"os"
	"testing"
)

func TestLinuxTUNCachedDescriptor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	r := &linuxTUNDevice{file: reader, fd: int(reader.Fd())}
	w := &linuxTUNDevice{file: writer, fd: int(writer.Fd())}
	want := []byte("native TUN descriptor payload")
	if n, err := writeTUN(w, want); err != nil || n != len(want) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	got := make([]byte, len(want))
	if n, err := readTUN(r, got); err != nil || n != len(want) {
		t.Fatalf("read: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read %q, want %q", got, want)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readTUN(r, got); err == nil {
		t.Fatal("read succeeded after Close")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := writeTUN(w, want); err == nil {
		t.Fatal("write succeeded after Close")
	}
}

// Compare the old per-packet Fd path with the native cached descriptor.
// A pipe isolates descriptor overhead without requiring root or a real TUN;
// it does not measure tunnel throughput or kernel network processing.
func BenchmarkLinuxTUNDescriptor(b *testing.B) {
	for _, cached := range []bool{false, true} {
		name := "per_packet_Fd"
		if cached {
			name = "cached_Fd"
		}
		b.Run(name, func(b *testing.B) {
			reader, writer, err := os.Pipe()
			if err != nil {
				b.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			var r, w tunDevice = reader, writer
			if cached {
				r = &linuxTUNDevice{file: reader, fd: int(reader.Fd())}
				w = &linuxTUNDevice{file: writer, fd: int(writer.Fd())}
			}
			payload := make([]byte, maxTUN)
			buffer := make([]byte, maxTUN)
			b.SetBytes(maxTUN)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if n, err := writeTUN(w, payload); err != nil || n != len(payload) {
					b.Fatalf("write: %d %v", n, err)
				}
				if n, err := readTUN(r, buffer); err != nil || n != len(buffer) {
					b.Fatalf("read: %d %v", n, err)
				}
			}
		})
	}
}
