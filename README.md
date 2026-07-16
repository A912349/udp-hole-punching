# Home UDP Mesh (Go)

This is the Go implementation of the home UDP mesh. It contains a small HTTP
control plane, an encrypted UDP overlay node with Linux TUN support, and the
stand-alone UDP hole-punching experiment. The control plane never relays user
packets.

## Build

Install Go 1.22 or newer, then run:

```bash
go mod tidy
go build ./...
```

The commands are built as `server`, `mesh-node`, and `punch-client` (their
source is under `cmd/`). `modernc.org/sqlite` is a pure-Go SQLite driver, so a
C compiler is not required.

## Run the coordinator

```bash
export MESH_NETWORK_TOKEN='a-long-random-secret-of-at-least-24-characters'
./server
```

Useful optional environment variables are `MESH_DATABASE` (default
`mesh.db`), `MESH_PORT` (default `8001`), `MESH_IP_NETWORK` (default
`10.77.0.0/24`), `MESH_AUTO_SUPERPEERS`, and `MESH_NODE_TTL_SECONDS`.

## Run a node

```bash
./mesh-node \
  --server http://SERVER_IP:8001 \
  --network-token "$MESH_NETWORK_TOKEN" \
  --state-dir state-node
```

The node uses STUN to discover its public endpoint and classify the mapping.
For restricted or offline environments, provide both `--nat-type` and
`--public-endpoint HOST:PORT` explicitly. Each node needs its own state
directory because it holds its persistent X25519 identity.

Publish a one-shot TCP service:

```bash
./mesh-node --server http://SERVER_IP:8001 --network-token "$MESH_NETWORK_TOKEN" \
  --state-dir state-home --service web=127.0.0.1:8080
```

Call it from another node (the destination can be a unique node-ID prefix):

```bash
cat request.bin | ./mesh-node --server http://SERVER_IP:8001 \
  --network-token "$MESH_NETWORK_TOKEN" --state-dir state-client \
  --call NODE_ID:web > response.bin
```

## Security and compatibility

The data plane authenticates UDP envelopes with HMAC-SHA-256, uses X25519 key
agreement, and encrypts end-to-end data with ChaCha20-Poly1305. The identity
file format and JSON packet format intentionally remain compatible with the
previous implementation, so a node can reuse an existing `identity.json`.

The service transport remains request/response rather than a reliable TCP
tunnel: it is appropriate for small requests and short HTTP responses, not
for SSH, RDP, or long streams.
