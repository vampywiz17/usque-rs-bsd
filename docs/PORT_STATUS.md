# Port status

## Scope

This artifact is native-TUN-only. Everything unrelated to the `nativetun` path was removed.

## Kept

- Cloudflare registration API ported to Rust.
- MASQUE key enrollment API ported to Rust.
- `config.json` fields needed by native TUN preserved.
- Native TUN mode implemented with `tun-rs`.
- QUIC/HTTP3 MASQUE `cf-connect-ip` tunnel implemented with `quiche`.
- H3 DATAGRAM encoding implemented as `varint(flow_id) + varint(context_id=0) + IP packet`.
- IPv4 TTL / IPv6 hop-limit decrement and basic checksum handling implemented.
- Basic ICMP Packet Too Big generation included for datagram send errors.
- Configurable, inactivity-aware RFC 9000 QUIC PING keepalive included
  (`25s` by default, `0s` disables it).
- Bounded reusable upload buffer pool included (`1024` buffers by default).
- FreeBSD UDP send/receive batching included with native
  `sendmmsg`/`recvmmsg` (`32` packets per syscall by default).
- Outbound batches retain quiche's per-packet pacing deadline.
- UDP receive/send buffers start from the kernel default and adapt independently
  toward the configured target through verified `SO_RCVBUF`/`SO_SNDBUF`
  operations; OS limits are retained without changing global sysctls.
- Full Cloudflare MASQUE peer/address/port list is retained at enrollment.
  Reconnects rotate across API-provided ports and IPv4/IPv6 endpoints while
  preserving peer-specific certificate pins.
- Legacy configurations remain supported; their endpoint port defaults to 443.
- The MASQUE wire format remains unchanged; batching is below QUIC at the UDP
  socket boundary.
- Reconnect loop and connect/disconnect hooks included.
- Optional Mesh node role is separated from the original client role and uses
  the existing standards-based MASQUE/TUN data plane.
- Mesh mode is route-neutral: it does not manage routes, forwarding, NAT or
  firewall policy.
- Mesh mode proactively maintains its Edge session without waiting for routed
  TUN traffic; client mode retains its existing on-demand reconnect policy.
- Cloudflare rejects truthful FreeBSD Connector enrollment, so the experimental
  mode requires an explicit acknowledgement before sending the isolated
  `linux` enrollment platform claim. Runtime identity remains FreeBSD.
- Mesh startup validates the account-scoped registration once and fails closed
  for a rejected or expired registration instead of starting an untracked
  session.
- Client and Mesh roles share the same truthful device-state and native FreeBSD
  host telemetry reporter. Mesh additionally sends quiche path statistics over
  its established H3 session.
- Separate configs and interface names allow an egress client tunnel and an
  ingress Mesh tunnel to run simultaneously under administrator-owned routing.
- Live validation completed for Connector registration, account-scoped config
  retrieval, route-free eager MASQUE establishment, assigned IPv4/IPv6 Mesh
  addresses, PMTUD, idle keepalive and bidirectional IP forwarding. An earlier
  dashboard `Online` observation has not been reproducible: current sessions
  are present as registered Mesh-profile Devices and report truthful device
  state, but are absent from the WARP Connector connections API and therefore
  remain `Down` in the Mesh dashboard. Mesh must be treated as experimental and
  incomplete until that edge-association difference is identified.

## Removed

- SOCKS5 mode.
- HTTP proxy mode.
- L4 SOCKS mode.
- L4 HTTP proxy mode.
- Port forwarding mode.
- CLI placeholder commands for the above modes.
- HTTP/2 fallback flag and endpoint handling.

## Build verification requested

Run this on a Rust host:

```bash
cargo check
cargo build --release
```

Then test:

```bash
./target/release/usque-nativetun register --accept-tos
sudo ./target/release/usque-nativetun nativetun --interface-name usque0
```

Optional experimental Mesh verification uses a separate config:

```bash
./target/release/usque-nativetun --config /path/to/mesh.json mesh-register \
  --token-file /path/to/mesh-node.token --accept-tos \
  --acknowledge-linux-platform-claim
sudo ./target/release/usque-nativetun --config /path/to/mesh.json mesh-node \
  --interface-name tun1
```
