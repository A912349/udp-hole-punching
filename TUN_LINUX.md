# Linux TUN IPv4 smoke test

This is the first IP data-plane layer. It carries IPv4 packets between mesh
node addresses only; it does not yet route LAN prefixes or provide reliable
delivery and fragmentation.

## Requirements

- Run the updated `server.py` once so it adds the `mesh_ip` database column.
- The coordinator assigns and persists a unique mesh IPv4 address for every
  node identity. A manual `--mesh-ip` is optional only when a fixed address is
  required.
- Run `mesh_node.py` as root, or grant it `CAP_NET_ADMIN`, to create `/dev/net/tun`.
- Use Linux on both endpoints. Android/Termux needs a later `VpnService` layer.

The default private overlay subnet is `10.77.0.0/24`. The assigned address is
printed as `mesh IP ...` at node startup.

## Start the home node

In one terminal, start the node. The process creates `mesh0` and must remain
running:

```bash
sudo python3 mesh_node.py \
  --server http://COORDINATOR_IP:8001 \
  --network-token 'change-this-to-a-long-random-secret-12345' \
  --role client \
  --nat-type auto \
  --state-dir state-home \
  --tun-name mesh0 \
  --tun-auto-configure
```

`--tun-auto-configure` brings up the device, applies the coordinator lease, and
adds only the `10.77.0.0/24` route. It does not replace the Internet default
route. If you omit this flag, configure the device manually:

```bash
sudo ip link set dev mesh0 mtu 1075 up
sudo ip addr add ASSIGNED_MESH_IP/24 dev mesh0
```

## Start the second Linux node

Start it with its own identity directory and overlay address:

```bash
sudo python3 mesh_node.py \
  --server http://COORDINATOR_IP:8001 \
  --network-token 'change-this-to-a-long-random-secret-12345' \
  --role client \
  --nat-type auto \
  --state-dir state-linux-client \
  --tun-name mesh0 \
  --tun-auto-configure
```

Configure its interface in another terminal:

```bash
sudo ip link set dev mesh0 mtu 1075 up
sudo ip addr add ASSIGNED_MESH_IP/24 dev mesh0
```

After both nodes have refreshed topology, test the overlay:

```bash
ping -I mesh0 PEER_ASSIGNED_MESH_IP
```

Expected node logs include `TUN IPv4 ...` on the sending node and `TUN IPv4
delivered ...` on the receiving node. ICMP replies should traverse the same
mesh route in reverse.

## Current boundaries

- One `mesh_ip` represents one node; the coordinator rejects duplicate
  addresses.
- IPv4 packets up to 1075 bytes use one compact binary encrypted UDP frame
  (at most 1196 bytes on the wire). This fast data plane requires the updated
  `mesh_node.py` on both endpoints and every forwarding superpeer.
- This version still has no retransmission, congestion control, or routing of
  local LAN prefixes. Keep it for ping and small UDP/TCP smoke tests until the
  reliable transport layer is added.
