# usque-rs-bsd

Experimental BSD port of [Diniboy1123/usque-rs](https://github.com/Diniboy1123/usque-rs), focused initially on FreeBSD.

The project provides a native TUN tunnel for Cloudflare WARP's MASQUE/CONNECT-IP protocol. It uses [`tun-rs`](https://crates.io/crates/tun-rs) for the tunnel interface and Cloudflare [`quiche`](https://github.com/cloudflare/quiche) for QUIC and HTTP/3.

> [!WARNING]
> This is early porting work and has not yet been comprehensively tested across BSD releases or network configurations. Expect breaking changes and use it at your own risk.

## Current scope

- Native TUN mode only
- FreeBSD as the primary target
- Cloudflare registration and MASQUE key enrollment
- QUIC/HTTP/3 MASQUE `cf-connect-ip` tunnel
- IPv4 and IPv6 packet handling
- Reconnect and connect/disconnect hooks
- FreeBSD-oriented upload tuning

Proxy modes, port forwarding and HTTP/2 fallback are currently out of scope. See [the port status](docs/PORT_STATUS.md) for details.

## FreeBSD build

Install the required build tools:

```sh
pkg install -y rust cmake ninja pkgconf git ca_root_nss
```

Build the release binary:

```sh
sh ./scripts/build-freebsd.sh
```

Or run Cargo directly:

```sh
cargo build --release
```

The resulting binary is `target/release/usque-nativetun`.

## Registration

Create the `config.json` file required by native TUN mode:

```sh
./target/release/usque-nativetun register --accept-tos
```

The generated configuration contains credentials. Do not publish or commit it.

## Run

The tunnel interface requires elevated privileges:

```sh
ifconfig tun0 destroy 2>/dev/null || true

RUST_LOG=info ./target/release/usque-nativetun nativetun \
  --config ./config.json \
  --interface-name tun0 \
  --always-reconnect
```

The application configures interface addresses and MTU, but does not manage the system's routing policy. Routes must be configured separately for the intended setup.

## FreeBSD-tuned defaults

| Parameter | Default | Notes |
| --- | ---: | --- |
| `--mtu` | `1200` | Reduced loss and jitter on the tested MASQUE path |
| `--initial-packet-size` | `1250` | Leaves room for QUIC/MASQUE overhead |
| `--tx-queue-len` | `8192` | Decouples the TUN reader from QUIC pacing |
| `--tx-burst-packets` | `256` | Stable upload-performance compromise |
| `--packet-buffer-pool-size` | `1024` | Reusable upload buffers; clamped to `1..16384` and bounds the effective TX queue |
| `--udp-batch-size` | `32` | FreeBSD `sendmmsg`/`recvmmsg` batch size; clamped to `1..64` |
| `--keepalive-period` | `25s` | Sends an RFC 9000 QUIC PING after network inactivity; use `0s` to disable |

Optional tuning example:

```sh
RUST_LOG=info ./target/release/usque-nativetun nativetun \
  --config ./config.json \
  --interface-name tun0 \
  --always-reconnect \
  --disable-quic-pacing \
  --udp-socket-buffer 16777216
```

Congestion-control experiments:

```text
--cc cubic --initial-cwnd-packets 32
--cc bbr2_gcongestion --initial-cwnd-packets 32
--cc reno --initial-cwnd-packets 32
```

If `bbr2_gcongestion` is rejected, use `cubic` or `reno`.

## Implementation notes

- `quiche` is pinned to `0.29.2` with the `gcongestion` feature.
- Idle connections are kept alive with an RFC 9000 QUIC PING. This preserves
  the outer UDP/NAT mapping without injecting synthetic ICMP traffic into the
  native TUN interface.
- The FreeBSD hot path batches already-produced QUIC UDP datagrams with
  `sendmmsg` and drains them with `recvmmsg`, reducing kernel/userspace
  transitions without changing MASQUE framing. A packet is batched only after
  its quiche pacing deadline, so the syscall optimization does not bypass QUIC
  congestion-control timing.
- The TUN reader uses a bounded reusable buffer pool. Because quiche owns its
  internal DATAGRAM queue, the pooled buffer is copied once with
  `Connection::dgram_send()` and immediately returned to the pool. This trades
  one small bounded copy for eliminating a heap allocation per IP packet.
- `tun-rs` remains on its supported native FreeBSD async path. Its
  `recv_multiple`/`send_multiple`, GRO and offload APIs are Linux-only and are
  intentionally not emulated here.
- The FreeBSD raw TUN direction is documented but is not enabled by default; `tun-rs` remains the production backend.
- See [FreeBSD raw TUN notes](docs/FREEBSD_RAW_TUN_NOTES.md) for the current design considerations.

## Development status

The immediate goal is to establish a reliable FreeBSD baseline:

1. Verify reproducible release builds.
2. Test registration and reconnect behavior.
3. Validate IPv4/IPv6 routing and MTU handling.
4. Benchmark upload and download throughput.
5. Evaluate support for additional BSD systems.

Useful checks:

```sh
cargo check
cargo build --release
```

## Acknowledgements

This project is derived from the upstream [usque-rs](https://github.com/Diniboy1123/usque-rs) project and builds on Cloudflare's open-source [quiche](https://github.com/cloudflare/quiche) library.

It is an independent community project and is not affiliated with or endorsed by Cloudflare.

## License

Licensed under the MIT License. See [LICENSE.md](LICENSE.md).
