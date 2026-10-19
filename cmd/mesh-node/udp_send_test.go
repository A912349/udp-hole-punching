package main

import (
	"errors"
	"io"
	"testing"
)

type batchWriteResult struct {
	sent int
	err  error
}
type scriptedBatchWriter struct {
	results []batchWriteResult
	calls   [][]byte
}

func (w *scriptedBatchWriter) write(batch []outboundDatagram) (int, error) {
	ids := make([]byte, len(batch))
	for i := range batch {
		ids[i] = batch[i].data[0]
	}
	w.calls = append(w.calls, ids)
	if len(w.results) == 0 {
		panic("unexpected extra write")
	}
	result := w.results[0]
	w.results = w.results[1:]
	return result.sent, result.err
}

func TestWriteUDPBatch(t *testing.T) {
	failed := errors.New("socket failed")
	tests := []struct {
		name    string
		results []batchWriteResult
		sent    int
		err     error
		calls   int
	}{
		{"complete", []batchWriteResult{{3, nil}}, 3, nil, 1},
		{"partial", []batchWriteResult{{1, nil}, {1, nil}, {1, nil}}, 3, nil, 3},
		{"zero progress", []batchWriteResult{{0, nil}}, 0, io.ErrNoProgress, 1},
		{"error after progress", []batchWriteResult{{1, nil}, {1, failed}}, 2, failed, 2},
		{"invalid count", []batchWriteResult{{4, nil}}, 0, io.ErrShortWrite, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &scriptedBatchWriter{results: tt.results}
			batch := []outboundDatagram{{data: []byte{0}}, {data: []byte{1}}, {data: []byte{2}}}
			sent, err := writeUDPBatch(w, batch)
			if sent != tt.sent || !errors.Is(err, tt.err) {
				t.Fatalf("got (%d,%v), want (%d,%v)", sent, err, tt.sent, tt.err)
			}
			if len(w.calls) != tt.calls {
				t.Fatalf("calls = %d, want %d", len(w.calls), tt.calls)
			}
			if tt.name == "partial" {
				for i, call := range w.calls {
					if len(call) != 3-i || call[0] != byte(i) {
						t.Fatalf("retry duplicated or skipped packets: %v", w.calls)
					}
				}
			}
		})
	}
}
