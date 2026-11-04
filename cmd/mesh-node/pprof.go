package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"

	_ "net/http/pprof"
)

// startPprof is the only code that references net/http/pprof. Keep it in this
// dedicated file so build flavors can compile it out: OpenWrt (MIPS) builds
// swap pprof.go for pprof-openwrt.go.inactive (see the Makefile and CI) and
// leave zero references behind, so the profiler machinery is never linked
// into the router binary.
func (n *node) startPprof() error {
	if n.c.pprofListen == "" {
		return nil
	}
	// Enable contention profiles only for diagnostic runs. These profiles are
	// empty by default and are intentionally not enabled in normal operation.
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	host, _, err := net.SplitHostPort(n.c.pprofListen)
	if err != nil {
		return fmt.Errorf("invalid --pprof-listen: %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		// A public pprof endpoint would leak profiling and memory dumps of the
		// whole process to anyone on the internet.
		return errors.New("--pprof-listen must use localhost or a loopback IP")
	}
	go func() {
		n.logf("pprof available at http://%s/debug/pprof/", n.c.pprofListen)
		if err := http.ListenAndServe(n.c.pprofListen, nil); err != nil {
			n.logf("pprof listener stopped: %v", err)
		}
	}()
	return nil
}
