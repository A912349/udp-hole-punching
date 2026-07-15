# Linux TUN IPv4 smoke test

This is the first IP data-plane layer. It carries IPv4 packets between mesh
node addresses only; it does not yet route LAN prefixes or provide reliable
delivery and fragmentation.

## Requirements

- Run the updated `server.py` once so it adds the `mesh_ip` database column.
- Assign a unique mesh IPv4 address to every participating node.
- Run `mesh_node.py` as root, or grant it `CAP_NET_ADMIN`, to create `/dev/net/tun`.
- Use Linux on both endpoints. Android/Termux needs a later `VpnService` layer.

The examples use the private overlay subnet `10.77.0.0/24`:

```text
home node:    10.77.0.10
mobile Linux: 10.77.0.20
```

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
  --mesh-ip 10.77.0.10 \
  --tun-name mesh0
```

In a second terminal on the same machine, configure the device:

```bash
sudo ip link set dev mesh0 mtu 1200 up
sudo ip addr add 10.77.0.10/24 dev mesh0
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
  --mesh-ip 10.77.0.20 \
  --tun-name mesh0
```

Configure its interface in another terminal:

```bash
sudo ip link set dev mesh0 mtu 1200 up
sudo ip addr add 10.77.0.20/24 dev mesh0
```

After both nodes have refreshed topology, test the overlay:

```bash
ping -I mesh0 10.77.0.10
```

Expected node logs include `TUN IPv4 ...` on the sending node and `TUN IPv4
delivered ...` on the receiving node. ICMP replies should traverse the same
mesh route in reverse.

## Current boundaries

- One `mesh_ip` represents one node; the coordinator rejects duplicate
  addresses.
- Only IPv4 packets no larger than 1200 bytes are accepted.
- This version has no fragmentation, retransmission, congestion control, or
  routing of local LAN prefixes. Keep it for ping and small UDP/TCP smoke
  tests until the reliable transport layer is added.
