package main

// Self-update: the coordinator pushes an "update" control event carrying a
// per-architecture source (a binary stored on the coordinator or a download
// link). The node downloads the matching build, verifies it, swaps it in at
// the SAME executable path and restarts. Because the path never changes,
// systemd units, OpenWrt init scripts, Windows HKCU Run entries and every
// other autostart mechanism keep working without re-registration.

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	updateDownloadTimeout = 15 * time.Minute
	updateMaxBinaryBytes  = 512 << 20
)

// updateEvent mirrors the server's updateSources payload.
type updateEvent struct {
	Binaries map[string]updateBinaryRef `json:"binaries,omitempty"`
	URLs     map[string]string          `json:"urls,omitempty"`
}

// updateBinaryRef describes one binary stored on the coordinator.
type updateBinaryRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type updateSource struct {
	url      string
	sha256   string
	expected int64
}

// pickUpdateSource selects the entry for this platform. Uploaded coordinator
// binaries win over external links. Relative paths ("path" without a scheme)
// are resolved against the coordinator the node is already talking to, so
// updates work unchanged behind reverse proxies and port mappings.
func (n *node) pickUpdateSource(ev updateEvent) (updateSource, bool) {
	arch := runtime.GOOS + "/" + runtime.GOARCH
	if b, ok := ev.Binaries[arch]; ok && b.Path != "" {
		src := updateSource{sha256: b.SHA256, expected: b.Size}
		if strings.HasPrefix(b.Path, "/") {
			src.url = strings.TrimRight(n.c.server, "/") + b.Path
		} else {
			src.url = b.Path
		}
		return src, true
	}
	if u, ok := ev.URLs[arch]; ok && strings.TrimSpace(u) != "" {
		return updateSource{url: strings.TrimSpace(u)}, true
	}
	return updateSource{}, false
}

// handleUpdateEvent runs the whole update cycle. Any failure is reported back
// to the coordinator so it shows up in the admin panel; success reports
// "restarting" right before the process image is replaced.
func (n *node) handleUpdateEvent(body []byte) {
	var ev updateEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		n.logf("self-update: malformed command: %v", err)
		return
	}
	// One-shot helper invocations (--call) must not self-update mid-request.
	if n.c.call != "" || n.closing.Load() {
		return
	}
	if !n.updating.CompareAndSwap(false, true) {
		n.logf("self-update already in progress; ignoring repeated command")
		return
	}
	defer n.updating.Store(false)
	arch := runtime.GOOS + "/" + runtime.GOARCH
	src, ok := n.pickUpdateSource(ev)
	if !ok {
		n.logf("self-update skipped: coordinator has no binary for %s", arch)
		n.reportUpdateStatus(arch, "failed", "no update binary published for "+arch)
		return
	}
	exe, err := executablePath()
	if err != nil {
		n.logf("self-update failed: resolve executable: %v", err)
		n.reportUpdateStatus(arch, "failed", "resolve executable: "+err.Error())
		return
	}
	n.logf("self-update: downloading %s", displayURL(src.url))
	tmp, written, err := n.downloadUpdate(src)
	if err != nil {
		n.logf("self-update failed: %v", err)
		n.reportUpdateStatus(arch, "failed", err.Error())
		return
	}
	n.logf("self-update: %d bytes verified; replacing %s and restarting", written, exe)
	n.reportUpdateStatus(arch, "restarting", fmt.Sprintf("%d bytes downloaded", written))
	// Give the status report a moment to reach the coordinator before the
	// process image (and its sockets) is replaced.
	time.Sleep(time.Second)
	if err := swapAndRestart(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		n.logf("self-update failed: %v", err)
		n.reportUpdateStatus(arch, "failed", err.Error())
	}
}

// downloadUpdate streams the new binary into a temporary file next to the
// executable (same filesystem, so the later rename is atomic). Size and
// SHA-256 are verified whenever the coordinator announced them.
func (n *node) downloadUpdate(src updateSource) (string, int64, error) {
	req, err := http.NewRequest(http.MethodGet, src.url, nil)
	if err != nil {
		return "", 0, err
	}
	if n.c.token != "" {
		req.Header.Set("X-Mesh-Token", n.c.token)
	}
	client := &http.Client{Timeout: updateDownloadTimeout, Transport: n.updateTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("download returned status %s", resp.Status)
	}
	limit := int64(updateMaxBinaryBytes)
	if src.expected > 0 {
		if src.expected > updateMaxBinaryBytes {
			return "", 0, errors.New("announced binary size is too large")
		}
		limit = src.expected + (1 << 20)
	}
	exe, err := executablePath()
	if err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".mesh-node-update-")
	if err != nil {
		return "", 0, fmt.Errorf("create temp file next to executable: %w", err)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(resp.Body, limit))
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", 0, fmt.Errorf("download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", 0, err
	}
	if src.expected > 0 && written != src.expected {
		_ = os.Remove(tmp.Name())
		return "", 0, fmt.Errorf("size mismatch: got %d bytes, expected %d", written, src.expected)
	}
	if src.sha256 != "" && !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), src.sha256) {
		_ = os.Remove(tmp.Name())
		return "", 0, errors.New("sha256 mismatch: downloaded binary does not match the announced build")
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		_ = os.Remove(tmp.Name())
		return "", 0, err
	}
	return tmp.Name(), written, nil
}

// updateTransport mirrors the control-plane TLS settings so a coordinator
// with a private CA (or a skipped verification) also accepts its download
// endpoint.
func (n *node) updateTransport() *http.Transport {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if pool, err := controlCertPool(n.c.controlCA); err == nil && pool != nil {
		tlsConfig.RootCAs = pool
	}
	if n.c.controlInsecure {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:  15 * time.Second,
			Resolver: meshResolver(),
		}).DialContext,
	}
}

// reportUpdateStatus posts progress to the coordinator over the existing
// control channel; it is best-effort and must never block the update.
func (n *node) reportUpdateStatus(arch, status, detail string) {
	var out struct{}
	body := map[string]string{"node_id": n.id.ID, "goarch": arch, "status": status, "detail": detail}
	if err := n.request("POST", "/v1/update-status", body, &out); err != nil {
		n.logf("update status report failed: %v", err)
	}
}

// executablePath resolves the running binary (following symlinks) so the
// replacement targets the real installed file and autostart paths stay valid.
func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// displayURL hides query strings (which may carry tokens) from the log.
func displayURL(raw string) string {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i] + "?..."
	}
	return raw
}
