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

## Router profile (measured): where a router's time actually goes

Measured on the OpenWrt router in the fleet (Linux 6.6.86, mips32r2 little
endian, no FPU, ~116 MB of RAM with ~28 MB free, `/tmp` a 58 MB tmpfs). The
bench binary is the cross-compiled *test* build (`make mips` equivalent),
run in `/tmp`; kernel UDP worked there, so the bench exercises the same
data plane as the shipped binary.

Measured rates on the router (1279-byte payload, four worker threads):

    BenchmarkHotPathCrypto/HMAC-SHA256-per-packet    256317 ns   4.99 MB/s
    BenchmarkHotPathCrypto/ChaCha20-Poly1305-Seal    283040 ns   4.52 MB/s
    BenchmarkTwoNodeDataPlane/520                    506365 ns   1976 delivered-pps
    BenchmarkTwoNodeDataPlane/1279                   695945 ns   1437 delivered-pps

The same primitives on an x86 host measured 401 MB/s for the Seal, 12 637 ns
for the 520-byte packet and 17 311 ns for the 1279-byte packet. The router's
AEAD runs about eighty times slower than the host's assembly path, and a
router packet costs about forty times the host's packet cost at either size.

Self-time and cumulative shares of the router data-plane profile (13.44 s of
samples over 7.24 s of wall on four hardware threads):

    golang.org/x/crypto chacha20poly1305 Seal (cum)          23.36%
    golang.org/x/crypto chacha20poly1305 Open (cum)          17.56%
    golang.org/x/crypto chacha20 xorKeyStreamBlocks (cum)    21.65%
    golang.org/x/crypto chacha20 quarterRound (self)          6.85%
    golang.org/x/crypto poly1305 writeWithPadding (incl)     16.4%
    math/bits.Mul64 (self)                                    6.62%
    math/bits.RotateLeft32, math/bits.Add64 (self)            3.79, 3.35%
    internal/runtime/syscall.Syscall6 (self)                 16.00%
      of which sendto 1.81 s and recvfrom 0.30 s of 1.98 s RawSyscall6
    runtime._LostSIGPROFDuringAtomic64 (self)                 9.75%
    runtime GC, memmove, select, atomics                      a few % each

Reading:

* The AEAD pair (Seal on the sending side, Open on the receiving side) is
  **40.9% of the router's samples**, and it is entirely the generic Go path:
  `chacha20poly1305_noasm.go`, `chacha20.xorKeyStreamBlocksGeneric`,
  `poly1305.updateGeneric`. About a third is the ChaCha20 keystream
  (`quarterRound` is not inlined and `RotateLeft32` is a separate call frame),
  about a sixth is the Poly1305 tag (`writeWithPadding` plus `Mul64`).
* Kernel time is 16.00% and it is *send*: the bench's send path spends 1.81 s
  in `sendto` against 0.30 s in `recvfrom`, so batching on the mesh's own
  send path (`WriteBatch`, batch size 32) is where most of that 16% lives.
* `_LostSIGPROFDuringAtomic64` is the profiler's own bookkeeping for samples
  it could not take while an atomic64 sequence was running; it is not extra
  router cost, so subtract its 9.75% when judging anything else.

What a crypto rewrite can buy on the router, from these numbers:

* The AEAD is 40.9% of samples. A realistic overall AEAD speedup on mips32r2
  is 2 to 3 times, which takes 40.9% down to 14 to 20% and lifts router
  throughput by about 1.4 to 1.7 times. That is a real lever, and it is
  bounded: the other 43% (kernel send and receive, Go networking, GC, atomics)
  does not shrink.
* The portable first step is a vendored Go rewrite of the AEAD hot loop: one
  inlined quarter round instead of a call frame per round, several blocks in
  flight with the state kept in locals, rotations without the per-word
  `RotateLeft32` call, and the Poly1305 multiply in 32-bit limbs. It compiles
  for every architecture, so it helps every router at once, and its output can
  be checked against the RFC 8439 vectors and the project's own tests before
  shipping. Hand mips32r2 assembly is what adds the rest on top of it.
* A C/Rust shim is not a lever on x86 hosts: their crypto is already assembly,
  and the shim pays per-packet call overhead across an FFI boundary. On the
  router a shim would buy what assembly buys, but the OpenWrt lane cannot link
  or pack it (see the section below).

## How the router profile was taken (and how to repeat it)

Cross-compile the *test* binary for the router (same flags as `make mips`),
ship it over the LAN, run the benches there with a CPU profile, pull the
profile back, and read it with the same pprof tooling used for the host:

    CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
      $(GO) test -c -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o mesh-node-mips.test ./cmd/mesh-node
    # busybox on the router has no sftp-server: use scp -O (the old protocol)
    scp -O mesh-node-mips.test root@<router>:/tmp/
    ssh root@<router> "/tmp/mesh-node-mips.test -test.run='^\$' \
      -test.bench='TwoNodeDataPlane|HotPathCrypto' -test.benchtime=2s \
      -test.cpuprofile=/tmp/r.pb"
    scp -O root@<router>:/tmp/r.pb /tmp/ && gunzip -c /tmp/r.pb > r.pb.off
    $(GO) tool pprof -top -cum r.pb.off

Things worth keeping in the recipe rather than rediscovering: the router's
shell is busybox `ash` (no `nproc`, no `od`, no `wget -V`), its `scp` needs
`-O` because there is no sftp-server, the profile the test binary writes is
gzip-compressed (hence the `gunzip`), and the binary has to run out of `/tmp`
because `/tmp` is the only writable mount with room (a 9 MB binary against
58 MB of tmpfs, which leaves about 16 MB of RAM for the runtime).

The pprof-HTTP route (running the *program* with `--pprof-listen` and pulling
`/debug/pprof/profile`) stays available for a live router that is already
participating in a mesh, and it needs the pprof-linked MIPS flavor
(`make mesh-node-pprof-on`) because the shipped router binary has the endpoint
compiled out; that flavor is about 1.5 MB bigger, which matters on a router
with ~28 MB free.

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
