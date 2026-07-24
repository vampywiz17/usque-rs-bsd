# usque-rs-bsd

Experimental BSD port of [Diniboy1123/usque-rs](https://github.com/Diniboy1123/usque-rs), focused initially on FreeBSD.

The project provides a native TUN tunnel for Cloudflare WARP's MASQUE/CONNECT-IP protocol. It uses [`tun-rs`](https://crates.io/crates/tun-rs) for the tunnel interface and Cloudflare [`quiche`](https://github.com/cloudflare/quiche) for QUIC and HTTP/3.

> [!WARNING]
> This is early porting work and has not yet been comprehensively tested across BSD releases or network configurations. Expect breaking changes and use it at your own risk.

## Current scope

- Native TUN mode only
- FreeBSD as the primary target
- Cloudflare registration and MASQUE key enrollment
- Stable FreeBSD device identity and MASQUE-native registration metadata
- Cloudflare device orchestration status for TunnelOnly/MASQUE sessions
- QUIC/HTTP/3 MASQUE `cf-connect-ip` tunnel
- RFC 8899 DPLPMTUD with dynamic native TUN MTU updates
- IPv4 and IPv6 packet handling
- Reconnect and connect/disconnect hooks
- FreeBSD-oriented upload tuning

Proxy modes, port forwarding and HTTP/2 fallback are currently out of scope. See [the port status](docs/PORT_STATUS.md) for details.

## Differences from upstream `usque-rs`

This section is the maintained record of intentional differences from
[Diniboy1123/usque-rs](https://github.com/Diniboy1123/usque-rs). It must be
updated whenever this port gains a feature, compatibility change or material
bug fix that is not present upstream.

| Area | Upstream implementation | This FreeBSD port |
| --- | --- | --- |
| Platform and TUN backend | Linux-only `tun` plus `rtnetlink` | Native FreeBSD support through the public `tun-rs` API |
| QUIC stack | `quiche` 0.22 with fixed 1350-byte UDP payloads | Pinned `quiche` 0.29.3 with RFC 8899 DPLPMTUD |
| TUN MTU | Fixed at 1280 | Starts conservatively and follows quiche's writable DATAGRAM capacity up to the configured ceiling |
| Registration | Legacy API host, synthetic Android metadata and an initial WireGuard key | Current device orchestration host, direct P-256 MASQUE enrollment and truthful FreeBSD metadata |
| Device monitoring | No Cloudflare device-state integration | Truthful device-state heartbeat with the real MASQUE lifecycle, quiche path statistics and native FreeBSD interface, CPU, memory and filesystem metrics |
| Device identity | Random serial on each registration | Privacy-preserving stable serial and persisted name, OS, model, manufacturer and client version |
| Endpoint handling | One selected address, fixed port 443 | Retains all API-provided peers, ports, IPv4/IPv6 endpoints and peer-specific pins, with ordered fallback |
| Idle handling | Timeout processing only | Periodic RFC 9000 QUIC PING keepalive without synthetic inner-tunnel traffic |
| Reconnection | Triggered primarily by outbound traffic | Optional continuous reconnect plus connect/disconnect hooks |
| FreeBSD performance | Not applicable | Bounded reusable packet buffers, paced TX bursts, `sendmmsg`/`recvmmsg`, socket-buffer tuning and configurable congestion control/initial CWND |
| Certificate pinning | May continue when a peer certificate is unavailable | Fails closed unless insecure mode is explicitly requested |

The project deliberately remains tunnel-only. It does not take ownership of
routes, DNS, firewall policy, proxying or split-tunnel rules; those belong to
the FreeBSD host and, in the intended deployment, OPNsense. Compatibility work
aims to use standards-compliant Cloudflare, quiche and `tun-rs` behavior with
truthful metadata, not to impersonate another operating system or client.

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

## Cloudflare device monitoring

Native TUN mode uses Cloudflare's separate, out-of-tunnel HTTPS orchestration
connection to report the real MASQUE session lifecycle. It sends an immediate
update on connect/disconnect and a 60-second heartbeat while running, using
`Connected`/`Disconnected`, `tunnel_only` and `masque` values from the current
Cloudflare One Client device-state contract. Reporting failures are logged but
never terminate or reconnect the QUIC tunnel.

Each heartbeat reports cumulative packet, byte, loss, retransmission and RTT
statistics directly from quiche's active QUIC path. Native FreeBSD collectors use
`getifaddrs`, interface counters, `sysctl` and `statvfs` to report the active
interface type and addresses, network throughput, CPU and memory utilization,
available memory and root-filesystem usage. Cloudflare percentage fields retain
the contract's 0-to-1 scale and network rates are bytes per second.

Metrics that cannot be measured truthfully with a supported FreeBSD or quiche API
are omitted rather than sent as zero. This currently includes peer-side
downstream loss/retransmission, public ISP and gateway addresses, Wi-Fi and
battery data, per-application resource usage and disk I/O rates.

## FreeBSD-tuned defaults

| Parameter | Default | Notes |
| --- | ---: | --- |
| `--connect-port` | `0` | Uses Cloudflare's API-provided endpoint ports; legacy configs fall back to `443`. A non-zero value overrides every endpoint port |
| `--ipv6` | off | Prefers an IPv6 MASQUE endpoint while retaining IPv4 as fallback |
| `--mtu` | `1200` | Safe initial TUN MTU used while PMTUD is running |
| `--max-tun-mtu` | `1280` | Native-compatible inner IP MTU ceiling; may be overridden for experiments |
| `--initial-packet-size` | `1472` | Maximum QUIC UDP payload probed by DPLPMTUD |
| `--pmtud-max-probes` | `3` | RFC 8899 probe failure threshold |
| `--pmtud-revalidate-period` | `10m` | Rechecks a completed PMTU; `0s` disables periodic revalidation |
| `--initial-cwnd-packets` | `32` | Faster startup without the latency penalty seen at larger packet sizes |
| `--tx-queue-len` | `8192` | Decouples the TUN reader from QUIC pacing |
| `--tx-burst-packets` | `16` | Keeps upload latency low without reducing measured throughput |
| `--packet-buffer-pool-size` | `1024` | Reusable upload buffers; clamped to `1..16384` and bounds the effective TX queue |
| `--udp-batch-size` | `32` | FreeBSD `sendmmsg`/`recvmmsg` batch size; clamped to `1..64` |
| `--keepalive-period` | `25s` | Periodically schedules an RFC 9000 QUIC PING to preserve QUIC and outbound UDP/NAT state; use `0s` to disable |

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

- `quiche` is pinned to `0.29.3` with the `gcongestion` feature. PMTUD uses
  `Config::discover_pmtu`, `Connection::pmtu` and
  `Connection::revalidate_pmtu`. The TUN MTU is derived from quiche's actual
  writable DATAGRAM capacity and applied through `tun-rs::set_mtu`; no
  private QUIC or platform-specific MTU probing is used.
- New registrations use a P-256/SPKI key and MASQUE metadata from the first
  API request. Device name, FreeBSD version, model and a privacy-preserving
  stable serial are persisted in `config.json`. The serial is a SHA-256
  digest prefix of the system UUID or host ID, not the raw hardware value.
- The default orchestration SNI is `api.devices.cloudflare.com`, used by
  Cloudflare One Client 2026.6 and later. The compatible registration path
  remains configurable with `USQUE_API_URL` and `USQUE_API_VERSION` because
  Cloudflare does not publish the client-side registration wire API.
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
- New registrations retain every Cloudflare MASQUE peer, IPv4/IPv6 address,
  endpoint hostname, port and peer-specific pin. Reconnects rotate through the
  ordered endpoint list. Existing configurations remain valid and use port 443
  when they do not contain an API port list.
- Endpoint fallback is transport-only. DNS policy, routing and firewall state
  remain owned by the host FreeBSD system.
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

## Disclaimer

Please do not use this project for abuse. Abusive use harms Cloudflare, risks
sanctions against this project, and may make the service less accessible to
everyone. You are solely responsible for how you use this software and for
complying with Cloudflare's terms and all applicable laws.

This project implements properties of Cloudflare's clients and wire contracts
only where they are required for protocol compatibility, interoperability and
connection stability. It is not intended to be indistinguishable from an
official client and does not attempt to conceal its identity. In particular,
device-state and monitoring data sent to Cloudflare are truthful: the client
identifies the platform as FreeBSD, uses this project's own version identity,
and derives connection status, tunnel mode, tunnel type, colocation, latency
and loss data from the real system and MASQUE session state. It does not
fabricate telemetry or report itself as an official Cloudflare client.
Cloudflare can distinguish and restrict this implementation at any time.

This software is provided as-is, without warranties or guarantees. Its authors
are not responsible for account sanctions, service interruption, data loss, or
damage to systems or networks resulting from its use. Although the project is
developed with security in mind, it is an independent hobby and research
project, not a professionally audited security product. Use it at your own
risk.

Responsible security reports are welcome. Please open an issue containing only
your contact details and a brief, non-sensitive summary so that the full
findings can be coordinated in private. Do not publish exploit details before
there has been reasonable time to investigate and fix the issue.

**This project is not affiliated with, endorsed by, or reviewed by Cloudflare,
Inc. It is an independent research project. Cloudflare WARP, WARP+, 1.1.1.1,
Cloudflare Access, Cloudflare Gateway and Cloudflare One are
[Cloudflare trademarks and wordmarks](https://www.cloudflare.com/trademark/).**

## Acknowledgements

This project is derived from the upstream [usque-rs](https://github.com/Diniboy1123/usque-rs) project and builds on Cloudflare's open-source [quiche](https://github.com/cloudflare/quiche) library.

It is an independent community project and is not affiliated with or endorsed by Cloudflare.

## License

Licensed under the MIT License. See [LICENSE.md](LICENSE.md).
