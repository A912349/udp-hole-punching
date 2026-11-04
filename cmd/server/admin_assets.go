package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"hash/crc32"
	"strconv"
	"strings"
	"sync"
)

// Pre-gzipped copy of an embedded admin asset, keyed by URL path. Assets ship
// inside the binary, so their bytes never change while a server runs; caching
// one copy lets repeat requests revalidate with 304 instead of refetching up
// to ~62 KB of raw admin.js on every reload.
type assetVariant struct {
	etag string
	// gzip-compressed body bytes, empty when compression would not pay off.
	gz []uint8
}

// gzipSink is the in-memory sink gzip.NewWriter compresses into.
type gzipSink struct {
	// accumulates compressed bytes.
	buf bytes.Buffer
}

func (w *gzipSink) Write(p []uint8) (int, error) {
	return w.buf.Write(p)
}

var (
	assetMu sync.Mutex
	// pre-gzipped admin assets keyed by URL path.
	assetCache = map[string]assetVariant{}
)

// embeddedAsset returns the pre-gzipped variant and content ETag for an
// embedded asset, building them once on first use under the mutex.
func embeddedAsset(name string, raw string) assetVariant {
	assetMu.Lock()
	defer assetMu.Unlock()
	asset, ok := assetCache[name]
	if ok {
		return asset
	}
	ck := crc32.ChecksumIEEE([]uint8(raw))
	etag := "\"" + strconv.FormatUint(uint64(ck), 16) + "-" + strconv.FormatUint(uint64(len(raw)), 16) + "\""
	sink := &gzipSink{}
	comp := gzip.NewWriter(sink)
	_, _ = comp.Write([]uint8(raw))
	_ = comp.Close()
	asset.etag = etag
	asset.gz = sink.buf.Bytes()
	// Fall back to raw transfer when gzip does not actually shrink the body.
	if sink.buf.Len() >= len(raw) {
		asset.gz = []uint8("")
	}
	assetCache[name] = asset
	return asset
}

// Short must-revalidate window rather than far-future expiry: if the server
// binary is updated, its new asset bytes show up within a minute, while
// unchanged repeat visits still transfer nothing via ETag revalidation.
var cachePolicy = "public, max-age=60, must-revalidate"

// writeAsset serves one embedded admin asset with conditional-GET support:
// matching If-None-Match answers 304, gzip-capable clients get the
// pre-compressed bytes, everyone else the raw text. All responses carry a
// stable content ETag (CRC-32 of bytes plus length) so an asset that is
// unchanged across a server update still revalidates.
func writeAsset(w http.ResponseWriter, r *http.Request, name string, raw string, ctype string) {
	asset := embeddedAsset(name, raw)
	// Conditional GET: the cached copy matches, so send only the 304 status.
	// RFC 9110 keeps the body empty here; the cache merges the headers below
	// onto the stored copy.
	none := r.Header.Get("If-None-Match")
	if none == "*" || none == asset.etag {
		w.Header().Set("ETag", asset.etag)
		w.Header().Set("Cache-Control", cachePolicy)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	 w.Header().Set("Content-Type", ctype)
	w.Header().Set("ETag", asset.etag)
	w.Header().Set("Cache-Control", cachePolicy)
	// Pre-gzip: saves roughly 70% of the admin asset bytes on first load.
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && len(asset.gz) > 0 {
	 w.Header().Set("Content-Encoding", "gzip")
	 w.Header().Set("Vary", "Accept-Encoding")
	_, _ = w.Write(asset.gz)
	 return
	}
	// Plain-text fallback still gets the ETag, so later reloads revalidate.
	_, _ = io.WriteString(w, raw)
}
