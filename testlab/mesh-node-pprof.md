# mesh-node CPU profile: where the data-plane time goes

This is the read-out of the profiles `testlab/` produces for `cmd/mesh-node`
(the mesh node, not the coordinator `cmd/server`). It answers one question for
every proposed optimization: what share of the packet cost can that change
possibly recover?

Profile with the pprof-lab tooling (`testlab/Makefile`) or directly:

    cd cmd/mesh-node
    go test -run '^$' -bench=TwoNodeDataPlane -benchtime=5s -cpuprofile=pb.pb.gz .
    gunzip pb.pb.gz > pb.pb          # then: go tool pprof -top pb.pb

Benchmarks referenced: `BenchmarkTwoNodeDataPlane` (sendIP -> kernel datagram
-> receiver loop -> `fast` -> TUN deliver), `BenchmarkHotPathCrypto`
(per-packet HMAC-SHA256 and ChaCha20-Poly1305 Seal at a representative 1279 B).

## Host profile (amd64, x8-64 SSE4.1 CPU, crypto = asm)

Measured on a Pentium 3558U-class CPU: no AVX2, no BMI2, no SHA-NI
(`cpu.X86.HasAVX2 = false`, `HasSSE41 = true`, `HasPCLMULQDQ = true`).
The bench runs `net.UDPConn.WriteToUDP`/`ReadFromUDP`, i.e. one
`sendto`/`recvfrom` per datagram; the mesh's own send path batches with
`WriteBatch` (sendmmsg), which the bench does not exercise.

Self-time shares of the data-plane profile (top entries):

    internal/runtime/syscall.Syscall6                        48.84%
    chacha20poly1305.chacha20Poly1305Seal (asm)              10.43%
    chacha20poly1305.chacha20Poly1305Open (asm)              10.12%
    runtime.selectgo                                          3.52%
    runtime.memmove                                           1.20%
    runtime.nanotime                                          1.20%
    runtime.lock2                                             0.98%

Throughput measured separately for the crypto primitives at 1279 B:

    ChaCha20-Poly1305 Seal            3184 ns   401 MB/s
    HMAC-SHA256 (keepalive envelope) 14810 ns    86 MB/s
    full data-plane packet (520 B)   12637 ns
    full data-plane packet (1279 B)  17311 ns

Reading the table:

* Syscalls dominate this profile (48.84%) because the bench pays one
  `sendto` + one `recvfrom` per datagram. The mesh node itself amortizes sends
  with `sendmmsg` batches (batch size 32), so this share is a bench artifact,
  not the node's steady state. The same is not true of receives: each receive
  is one `recvfrom` per datagram on a single socket shared by all peers.
* Crypto is 20.55% of the sampled time, and it is *already assembly* on this
  ISA (x/crypto's amd64 ChaCha20-Poly1305, SSE4.1 + PCLMULQDQ path). It is
  about 40% of the non-syscall work: within userspace packet handling the AEAD
  pair is the single largest cost.
* Everything else (GC, memmove, selects, time, locks) is small: under 2% each.

## What the ceiling for a crypto rewrite is, per platform

x/crypto's `chacha20poly1305` package has assembly **only for amd64**. The
`chacha20` package has arm64/ppc64le/s390x keystream assembly, but the AEAD
package does not use it: on every other architecture the whole AEAD (stream
plus Poly1305 tag) is the generic Go implementation.

* x86 hosts (coordinator side, x86 mesh nodes): crypto = 20.55% of the
  profile and is already asm. A hand-written same-ISA rewrite or a Rust/FFI
  shim has at most a small factor of headroom against the existing asm: the
  measured ceiling for the best same-ISA assembly is a couple of tenths of the
  total, and a C/Rust shim brings that ceiling down (call overhead across an
  FFI boundary) while the whole crypto rewrite ceiling (~20% of samples, and
  that is for replacing asm with asm) argues for not touching it.
* Router nodes (OpenWrt, MIPS 1004Kc / mips32r2, soft-float) and other
  non-amd64 nodes: there is no AEAD asm at all, crypto runs as Go code
  (hundreds of MB/s slower), and crypto is most of the per-packet userspace
  cost. This is where a hand-written per-architecture
  `chacha20poly1305` assembly (ChaCha20 rounds + Poly1305 with 32x32->64
  multiply-add sequences on mips32r2, no SIMD needed) is the payoff, and it
  matches the pattern this project already uses for `syscall`
  architecture-specific assembly.
* Coordinator-side crypto (JSON/compact envelopes) is HMAC-SHA256 + AEAD on
  the host; on an x86 coordinator without SHA-NI that is 86 MB/s Go+asm.
  It is not on the mesh-node data plane, so it does not affect mesh
  throughput.

## How to get the router-side number (the one that decides)

The router profile is the number that matters for the router fleet; the host
profile above is not representative of it. On the router the
pprof endpoint has to be compiled in, so build the pprof-linked MIPS flavor
(`make mesh-node-pprof-on` keeps it) instead of the shrunken OpenWrt flavor:

    make mips GO=/usr/local/go/bin/go          # mipsle softfloat binary
    # then run the node binary with --pprof-listen localhost:9999

On the router (busybox `wget` works against the loopback endpoint):

    wget -q -O /tmp/node.pb 'http://localhost:9999/debug/pprof/profile?seconds=60'

Pull it back to the host and read it with the same tooling:

    go tool pprof -top -cum /tmp/node.pb

Read it for two numbers: the share of samples inside
`chacha20poly1305.chacha20poly1305_generic` (the Go AEAD path) and the share
inside the `syscall` glue. If the generic AEAD is more than a couple of tenths
of the node's samples, the asm lever for the router architecture is worth its
cost; if it is not, the lever is the syscall batching instead. The project's
own test vectors (`internal/protocol` tests, RFC 8439 vectors in x/crypto)
cover the crypto's correctness independent of which path is compiled in.

## Caveats

* These host shares were measured with the bench's unbatched send path;
  the production send path batches, which shrinks the syscall share and makes
  crypto a larger part of the remaining userspace cost.
* UPX-packed, stripped release binaries still profile fine (profiles carry
  addresses plus symbol names from the Go binary's own symbol table); compare
  shares, not absolute times, across build flavors.
* Soft-float MIPS (`GOMIPS=softfloat`) does not affect crypto, which is
  integer-only; it does affect any float-heavy code path, of which the AEAD
  has none.
