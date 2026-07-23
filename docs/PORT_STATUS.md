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
- Reconnect loop and connect/disconnect hooks included.

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
