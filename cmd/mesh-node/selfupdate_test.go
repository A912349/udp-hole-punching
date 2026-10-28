package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPickUpdateSourcePrefersStoredBinary(t *testing.T) {
	arch := runtime.GOOS + "/" + runtime.GOARCH
	n := &node{c: config{server: "http://coord.example:8001"}}
	ev := updateEvent{
		Binaries: map[string]updateBinaryRef{
			arch: {Path: "/v1/update/binaries/linux%2Farm64", SHA256: "abc", Size: 10},
		},
		URLs: map[string]string{arch: "https://github.com/example/mesh-node-arm64"},
	}
	src, ok := n.pickUpdateSource(ev)
	if !ok {
		t.Fatal("expected a source")
	}
	if src.url != "http://coord.example:8001/v1/update/binaries/linux%2Farm64" {
		t.Fatalf("stored binary path must resolve against the coordinator, got %q", src.url)
	}
	if src.sha256 != "abc" || src.expected != 10 {
		t.Fatalf("checksum/size not carried over: %+v", src)
	}
}

func TestPickUpdateSourceFallsBackToLink(t *testing.T) {
	arch := runtime.GOOS + "/" + runtime.GOARCH
	n := &node{c: config{server: "http://coord.example:8001"}}
	ev := updateEvent{URLs: map[string]string{arch: " https://example.com/mesh-node-mipsle "}}
	src, ok := n.pickUpdateSource(ev)
	if !ok || src.url != "https://example.com/mesh-node-mipsle" {
		t.Fatalf("expected trimmed link fallback, got %+v ok=%v", src, ok)
	}
	if _, ok := n.pickUpdateSource(updateEvent{}); ok {
		t.Fatal("no source must be found without any matching entry")
	}
}

func TestDownloadUpdateVerifiesAndReplaces(t *testing.T) {
	payload := []byte(strings.Repeat("MESHNODE", 4096)) // 32 KiB
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])

	var hitAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mesh-Token") != "tok-123" {
			hitAuth = true
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	n := &node{c: config{server: srv.URL, token: "tok-123"}}
	// The download lands next to the running test executable.
	tmp, written, err := n.downloadUpdate(updateSource{url: srv.URL + "/bin", sha256: good, expected: int64(len(payload))})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer os.Remove(tmp)
	if written != int64(len(payload)) {
		t.Fatalf("written = %d, want %d", written, len(payload))
	}
	if hitAuth {
		t.Fatal("network token must be sent on binary downloads")
	}
	got, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("downloaded content mismatch")
	}
	// The temp file must be a sibling of the executable so the later rename
	// stays within one filesystem.
	exe, _ := os.Executable()
	if filepath.Dir(tmp) != filepath.Dir(exe) {
		t.Fatalf("temp dir = %s, want %s", filepath.Dir(tmp), filepath.Dir(exe))
	}
}

func TestDownloadUpdateRejectsCorruption(t *testing.T) {
	payload := []byte("legitimate payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(append(payload, []byte("+injected")...))
	}))
	defer srv.Close()

	n := &node{c: config{server: srv.URL}}
	if _, _, err := n.downloadUpdate(updateSource{url: srv.URL + "/bin", sha256: "deadbeef"}); err == nil {
		t.Fatal("sha256 mismatch must fail the download")
	}
	if _, _, err := n.downloadUpdate(updateSource{url: srv.URL + "/bin", expected: int64(len(payload))}); err == nil {
		t.Fatal("size mismatch must fail the download")
	}
	// No leftover temp files may survive a rejected download.
	exe, _ := os.Executable()
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".mesh-node-update-*"))
	if len(matches) != 0 {
		t.Fatalf("temp files leaked: %v", matches)
	}
}
