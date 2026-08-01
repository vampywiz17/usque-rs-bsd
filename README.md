# usque-rs-bsd

Experimental BSD port of [Diniboy1123/usque-rs](https://github.com/Diniboy1123/usque-rs), focused initially on FreeBSD.

The project provides a native TUN tunnel for Cloudflare WARP's MASQUE/CONNECT-IP protocol. It uses [`tun-rs`](https://crates.io/crates/tun-rs) for the tunnel interface and Cloudflare [`quiche`](https://github.com/cloudflare/quiche) for QUIC and HTTP/3.

> [!WARNING]
> This is early porting work and has not yet been comprehensively tested across BSD releases or network configurations. Expect breaking changes and use it at your own risk.

This is an independent interoperability project. Cloudflare has not authorized,
endorsed or reviewed this client, and no claim is made that its undocumented
client endpoints are public or supported APIs. Before using or contributing,
read the [legal and interoperability notice](LEGAL.md), the maintained
[protocol-source record](PROTOCOL_SOURCES.md), and the
[contribution requirements](CONTRIBUTING.md).

## Current scope

- Native TUN mode only
- FreeBSD as the primary target
- Cloudflare registration and MASQUE key enrollment
- Optional, experimental and unsupported FreeBSD Mesh node mode
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
| TUN MTU and IPv6 | Fixed at 1280 | Starts conservatively, follows quiche's writable DATAGRAM capacity up to the configured ceiling, and activates IPv6 only at the RFC 8200 minimum MTU |
| Registration | Legacy API host, synthetic Android metadata and an initial WireGuard key | Current device orchestration host, direct P-256 MASQUE enrollment and truthful FreeBSD metadata |
| Device monitoring | No Cloudflare device-state integration | Truthful device-state heartbeat with the real MASQUE lifecycle, quiche path statistics and target-gated native FreeBSD interface, CPU, memory and filesystem metrics |
| Device identity | Random serial on each registration | Privacy-preserving stable serial and persisted name, OS, model, manufacturer and client version |
| Endpoint handling | One selected address, fixed port 443 | Retains all API-provided peers, ports, IPv4/IPv6 endpoints and peer-specific pins, with ordered fallback |
| Mesh node | Not present | Explicitly optional route-neutral Mesh node mode using the Connector token flow, continuous Edge-session maintenance and one standards-compliant activation packet using Cloudflare's 1.1.1.1 service by default with Mesh-only overrides; FreeBSD enrollment requires a prominently disclosed `linux` platform compatibility claim because Cloudflare rejects `freebsd` |
| Idle handling | Timeout processing only | Periodic RFC 9000 QUIC PING keepalive without synthetic inner-tunnel traffic, plus a finite Mesh-only QUIC idle timeout for dead-peer detection |
| Reconnection | Triggered primarily by outbound traffic | Optional continuous reconnect plus connect/disconnect hooks; quiche `Finished`/`Reset` events on the RFC 9484 CONNECT-IP request stream terminate the session and invoke automatic endpoint rotation/reconnect |
| FreeBSD performance | Not applicable | Bounded reusable packet buffers, paced TX bursts, `sendmmsg`/`recvmmsg`, adaptive and verified per-socket buffer sizing, and configurable congestion control/initial CWND |
| Certificate pinning | May continue when a peer certificate is unavailable | Fails closed unless insecure mode is explicitly requested |
| Build profiles | Single development path | Maximum-runtime `release` profile with fat LTO and one codegen unit, plus a non-LTO `fast-release` profile with parallel code generation for faster iterative FreeBSD builds |
| Verification | Build and unit tests | CI formatting and warnings-as-errors Clippy gates plus an operator-run FreeBSD QUIC/CONNECT-IP connection stress harness for client and Mesh roles |

The project deliberately remains tunnel-only. It does not take ownership of
routes, DNS, firewall policy, proxying or split-tunnel rules; those belong to
the FreeBSD host and, in the intended deployment, OPNsense. Compatibility work
aims to use standards-compliant Cloudflare, quiche and `tun-rs` behavior with
truthful runtime identity and telemetry. The experimental Mesh enrollment
exception is documented separately below: it claims `linux` only because the
Connector endpoint rejects FreeBSD, never claims to be an official client, and
requires explicit operator acknowledgement.

## FreeBSD build

Install the required build tools:

```sh
pkg install -y rust cmake ninja pkgconf git ca_root_nss
```

Build the deployment binary with maximum runtime optimization (fat LTO and one
code-generation unit):

```sh
sh ./scripts/build-freebsd.sh
```

Or run Cargo directly:

```sh
cargo build --release
```

The resulting binary is `target/release/usque-nativetun`.

For faster edit/build/test cycles, use the separate optimized development
profile:

```sh
USQUE_BUILD_PROFILE=fast-release sh ./scripts/build-freebsd.sh

# Or directly:
cargo build --profile fast-release
```

Its binary is `target/fast-release/usque-nativetun`. The fast profile omits
LTO, uses moderate optimization, and enables parallel code generation to
shorten linking. It is intended for functional testing. Use the default
`release` profile for deployment and performance measurements; its
runtime-oriented settings remain unchanged.

## Registration

Create the `config.json` file required by native TUN mode:

```sh
./target/release/usque-nativetun register --accept-tos
```

For browser-assisted or other automated Cloudflare Access enrollment, keep the
short-lived JWT out of the process argument list:

```sh
chmod 600 /absolute/path/enrollment.jwt
./target/release/usque-nativetun \
  --config /absolute/path/client.json register \
  --jwt-file /absolute/path/enrollment.jwt --accept-tos
```

On Unix the JWT path must be absolute, owned by the effective user, refer directly
to a regular file, and deny all group/other access. The resulting
credential-bearing configuration is also restricted to mode `0600`. The legacy
`--jwt` option remains available for interactive compatibility, but automation
should use `--jwt-file`.

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

## Experimental Mesh node mode: unsupported platform warning

> [!CAUTION]
> Cloudflare documents Mesh nodes for specific Linux distributions only. Its
> Connector enrollment endpoint rejected the truthful `freebsd` value with
> `invalid device operating system for warp connector device registration`.
> This experimental mode therefore sends the platform value `linux` during
> enrollment even though the host is FreeBSD. This is a deliberate compatibility
> claim, not a statement that the host is Linux and not a claim that this
> project is an official Cloudflare client.

This exception may violate Cloudflare terms, an account agreement, policy or
future enforcement rule. Cloudflare may detect the mismatch and may reject the
registration, disable the node, restrict or suspend service, revoke credentials,
or suspend or terminate the associated account without notice. The operator
accepts all such risk. To the maximum extent permitted by applicable law, the
authors and contributors accept no liability for account sanctions, loss of
service, loss of data, financial loss, business interruption or any other
consequence caused by enabling or using this mode. Read [LEGAL.md](LEGAL.md)
before proceeding.

The registration command refuses to continue without the long, explicit
acknowledgement flag. Keep the dashboard-generated token outside the repository
and owner-readable only:

```sh
chmod 600 /home/freebsd/mesh-node.token

./target/release/usque-nativetun \
  --config /home/freebsd/mesh-node.json \
  mesh-register \
  --token-file /home/freebsd/mesh-node.token \
  --accept-tos \
  --acknowledge-linux-platform-claim
```

Run the separately registered node with the optional `mesh-node` command:

```sh
sudo ./target/release/usque-nativetun \
  --config /home/freebsd/mesh-node.json \
  mesh-node \
  --interface-name tun1
```

Mesh mode always establishes and maintains its Cloudflare Edge session, even
when no route has produced an initial TUN packet. This is intentional connector
lifecycle behavior and does not add or alter any route. `--always-reconnect`
remains optional for client mode and is redundant in Mesh mode.

Cloudflare does not expose an ingress connector in its connections API until
the new CONNECT-IP session has carried an inner IP packet. A route-neutral
connector cannot receive the first dashboard-routed packet while it is absent
from that API. The `mesh-node` command therefore sends one minimal activation
packet after every successful CONNECT-IP response. No config edit is required:
the default target is Cloudflare's `1.1.1.1` service.

Override the target for one invocation with the Mesh-only option:

```sh
sudo ./target/release/usque-nativetun \
  --config /home/freebsd/mesh-node.json \
  mesh-node \
  --interface-name tun1 \
  --activation-probe-target 2606:4700:4700::1111
```

A persistent override can instead be stored as
`mesh_node.activation_probe_target` in the config. Selection order is CLI
override, persisted config override, then `1.1.1.1`. The selected target must
use the same address family as an assigned Mesh address.

The program sends one valid ICMP Echo Request (or ICMPv6 Echo Request) through
the normal RFC 9484 CONNECT-IP/HTTP/3 DATAGRAM path per new session. Failure is
logged without tearing down an otherwise healthy tunnel. Activation never runs
in `nativetun` client mode and does not create routes, change firewall policy,
send a status override, or call another Cloudflare API.

The runtime MASQUE user agent remains truthful
(`usque-nativetun/<version> (FreeBSD; MeshNode; MASQUE)`). The generated
configuration records both `native_platform: "FreeBSD"` and
`registration_platform_claim: "linux"`; it does not retain the Connector
token or tunnel secret. Both roles use the same truthful device-state reporter
for observed lifecycle, host and quiche metrics. Mesh adds the Connector-only
`POST /h3-stats` request on the existing HTTP/3 connection every 15 seconds.

Mesh startup performs one authenticated account-scoped registration/config
read. A rejected or expired registration stops startup instead of creating an
untracked Edge session.

> [!WARNING]
> Current Mesh status remains experimental and unsupported by Cloudflare on
> FreeBSD. Authorized A/B tests confirmed that registration, telemetry and an
> idle MASQUE session alone leave the connections API empty and the dashboard
> `Down`; the first real inner IP packet creates the connection and changes the
> dashboard to `Up`. Bidirectional forwarding to a dashboard-published route
> also succeeded. Long-run testing then captured the exact failure: after 4
> hours 35 minutes Cloudflare reset the original CONNECT-IP request stream with
> HTTP/3 `H3_NO_ERROR` (`0x100`) while the underlying QUIC connection remained
> open. RFC 9484 ties tunnel lifetime to that request stream, so the data plane
> was already closed even though the old implementation continued reporting a
> locally connected transport. The protocol pump now treats quiche
> `Event::Finished` and `Event::Reset` on that specific stream as session
> termination; the existing supervisor reconnects and the new session sends
> its one-time activation packet. Auxiliary H3 requests such as `/h3-stats`
> remain isolated and cannot trigger a false tunnel reconnect. The finite QUIC
> idle timeout remains useful for an actually unresponsive peer, but was not
> sufficient for this clean application-stream closure. This recovery adds
> neither a periodic inner-tunnel heartbeat nor another API call.
> Release-build tests activated the API from zero connections with both IPv4
> and IPv6 targets and without adding a route to either destination.

### Deployment roles

1. `nativetun` is the egress role. OPNsense may route selected LAN traffic
   into this TUN so clients behind the firewall reach the Internet through
   Cloudflare.
2. `mesh-node` is the ingress role. OPNsense may publish selected internal
   networks so authorized remote Cloudflare Mesh devices can reach them through
   this TUN.

The roles use separate configuration files and interface names, and may run
simultaneously. The program creates and configures each TUN interface only. It
never creates Cloudflare routes, FreeBSD routes, forwarding policy, NAT or
firewall rules. Those remain the explicit responsibility of the FreeBSD
administrator or a future OPNsense plugin. Legacy client configurations remain
compatible.

## Cloudflare device monitoring

Both the `nativetun` egress role and the `mesh-node` ingress role use
Cloudflare's separate, out-of-tunnel HTTPS orchestration connection to report
their real MASQUE session lifecycle. They send updates for observed
connect/disconnect events and a 60-second heartbeat, using
`Connected`/`Disconnected`, `tunnel_only` and `masque` values from the
current Cloudflare One Client device-state contract. A Mesh registration or
authorization failure stops Mesh startup; later reporting failures are logged
but never terminate or reconnect a healthy QUIC tunnel.

Each heartbeat reports cumulative packet, byte, loss, retransmission and RTT
statistics directly from quiche's active QUIC path. Native FreeBSD collectors use
`getifaddrs`, interface counters, `sysctl` and `statvfs` to report the active
interface type and addresses, network throughput, CPU and memory utilization,
available memory and root-filesystem usage. Cloudflare percentage fields retain
the contract's 0-to-1 scale and network rates are bytes per second.

The undocumented device-state request shape and field behavior were inferred
from network traffic generated by the official client on an account and device
the maintainer was authorized to use, then checked against truthful dashboard
output and public Cloudflare device models. No Cloudflare proprietary source
code is included, and Cloudflare has not approved this integration.

Metrics that cannot be measured truthfully with a supported FreeBSD or quiche API
are omitted rather than sent as zero. This currently includes peer-side
downstream loss/retransmission, public ISP and gateway addresses, Wi-Fi and
battery data, per-application resource usage and disk I/O rates.
The native collector is compile-time gated to FreeBSD; verification builds on
other operating systems retain the wire contract but return an empty snapshot.

## FreeBSD-tuned defaults

| Parameter | Default | Notes |
| --- | ---: | --- |
| `--connect-port` | `0` | Uses Cloudflare's API-provided endpoint ports; legacy configs fall back to `443`. A non-zero value overrides every endpoint port |
| `--ipv6` | off | Prefers an IPv6 MASQUE endpoint while retaining IPv4 as fallback |
| `--mtu` | `1200` | Safe initial TUN MTU used while PMTUD is running |
| `--max-tun-mtu` | `1500` | Administrative inner-IP ceiling; the effective MTU remains bounded by quiche's discovered DATAGRAM capacity |
| `--initial-packet-size` | `1472` | Maximum QUIC UDP payload probed by DPLPMTUD |
| `--pmtud-max-probes` | `3` | RFC 8899 probe failure threshold |
| `--pmtud-revalidate-period` | `10m` | Rechecks a completed PMTU; `0s` disables periodic revalidation |
| `--initial-cwnd-packets` | `32` | Faster startup without the latency penalty seen at larger packet sizes |
| `--tx-queue-len` | `8192` | Decouples the TUN reader from QUIC pacing |
| `--tx-burst-packets` | `16` | Keeps upload latency low without reducing measured throughput |
| `--packet-buffer-pool-size` | `1024` | Reusable upload buffers; clamped to `1..16384` and bounds the effective TX queue |
| `--udp-batch-size` | `32` | FreeBSD `sendmmsg`/`recvmmsg` batch size; clamped to `1..64` |
| `--udp-socket-buffer` | `8388608` | Desired per-direction growth target. Each new socket starts from the OS default, grows adaptively, verifies the effective `SO_RCVBUF`/`SO_SNDBUF` value and retains the largest accepted size |
| `--keepalive-period` | `25s` | Periodically schedules an RFC 9000 QUIC PING to preserve QUIC and outbound UDP/NAT state; use `0s` to disable |
| `--max-idle-timeout` | `90s` | Mesh-only QUIC dead-peer timeout. Missing peer activity closes the stale session so the supervisor can reconnect; `0s` disables detection |

Socket-buffer negotiation is local and per socket: it never changes
`kern.ipc.maxsockbuf` or any other system-wide setting. If the kernel rejects
the requested target, the log reports the original default, requested target
and largest effective size. Receive and send limits are negotiated
independently on every connection and reconnect, so the same binary adapts to
both stock FreeBSD/OPNsense limits and explicitly tuned hosts.

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
- With PMTUD enabled, IPv6 assignment is deferred until the discovered inner
  MTU is at least the RFC 8200 minimum of 1280 bytes. The address is added and
  removed through tun-rs's native address APIs as path capacity changes or a
  connection moves to an unvalidated path. IPv4 remains available on smaller
  paths, matching Cloudflare One Client's documented PMTUD behavior. With
  `--no-iproute2`, address lifecycle remains the host administrator's
  responsibility as requested by that option.
- Oversized inner packets receive ICMPv4 Fragmentation Needed or ICMPv6 Packet
  Too Big with the current effective TUN MTU, including packets queued before
  a downward PMTU change.
- New registrations use a P-256/SPKI key and MASQUE metadata from the first
  API request. Device name, FreeBSD version, model and a privacy-preserving
  stable serial are persisted in `config.json`. The serial is a SHA-256
  digest prefix of the system UUID or host ID, not the raw hardware value. The
  registration workflow was inherited from the MIT-licensed upstream
  `usque-rs` project and subsequently adapted here for current MASQUE enrollment
  and truthful FreeBSD metadata; this port did not originate that workflow.
- Mesh registration uses the Connector token and account-specific
  `/v1/accounts/{account_tag}/warp_connector` enrollment contract, decodes both
  direct and Cloudflare `result` response envelopes, then fetches the generated
  tunnel configuration through
  `/v1/accounts/{account_tag}/reg/{registration_id}` with the registration
  bearer token. The request uses P-256 MASQUE keys and actual host name, model,
  OS version and stable serial, but sends `type: "linux"` because Cloudflare
  rejects FreeBSD for this Linux-only resource. This isolated exception requires
  explicit CLI acknowledgement, is persisted as metadata in the Mesh config and
  is never reused for the runtime user agent or client telemetry.
- The default orchestration SNI is `api.devices.cloudflare.com`, used by
  Cloudflare One Client 2026.6 and later. The compatible registration path
  remains configurable with `USQUE_API_URL` and `USQUE_API_VERSION` because
  Cloudflare does not publish the complete client-side registration wire API.
  Public Cloudflare documentation confirms the orchestration SNI and several
  registration models, but not the complete enrollment and device-state
  request contracts used by this project.
- Idle connections are kept alive with an RFC 9000 QUIC PING. This preserves
  the outer UDP/NAT mapping without injecting synthetic ICMP traffic into the
  native TUN interface.
- Mesh sessions use a finite, configurable quiche `max_idle_timeout` (90
  seconds by default). If peer activity ceases, the standard QUIC timeout path
  closes the stale session and the Mesh supervisor reconnects. Client mode
  retains its previous unlimited idle timeout and does not accept the Mesh-only
  option.
- RFC 9484 ties an IP tunnel to its CONNECT-IP request stream. The runtime
  retains that stream ID and treats quiche HTTP/3 `Finished` or `Reset`
  events on it as authoritative tunnel closure, even if the underlying QUIC
  connection remains open. The reconnect supervisor then establishes a new
  QUIC/H3/CONNECT-IP session. Completion of unrelated request streams is
  ignored for tunnel lifetime, and non-`Done` H3 polling errors also fail the
  session closed instead of continuing with invalid HTTP/3 state.
- The FreeBSD hot path batches already-produced QUIC UDP datagrams with
  `sendmmsg` and drains them with `recvmmsg`, reducing kernel/userspace
  transitions without changing MASQUE framing. A packet is batched only after
  its quiche pacing deadline, so the syscall optimization does not bypass QUIC
  congestion-control timing.
- UDP receive and send buffers are negotiated independently through socket2's
  public `SO_RCVBUF`/`SO_SNDBUF` APIs before bind/connect. The implementation
  reads the kernel default, probes upward to the configured target, verifies
  every accepted value with `getsockopt`, and performs a bounded 64 KiB-granular
  refinement when a limit is encountered. Failure is non-fatal and preserves
  the last accepted or kernel-default value; no global kernel setting is changed.
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

## Versioning

Formal release tracking starts with version `0.8.0`. This project follows
[Semantic Versioning](https://semver.org/): feature releases increment the
minor version, compatible fixes increment the patch version, and breaking
changes increment the major version after `1.0.0`. Before `1.0.0`, a minor
release may contain a documented breaking change while the interfaces are
still experimental.

Release notes are maintained in [CHANGELOG.md](CHANGELOG.md). A version is not
considered released merely because `Cargo.toml` changed; releases are identified
by an annotated Git tag matching the package version, for example `v0.8.0`.

Useful checks:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check
cargo test
cargo build --release
```

GitHub Actions runs formatting, Clippy with warnings denied, a debug build and
the complete test suite for every push and pull request targeting `main`.

Repeated live QUIC/HTTP/3 CONNECT-IP establishment can be verified on FreeBSD
without changing routes or firewall policy:

```sh
sudo ./scripts/stress-connect.sh --mode client --config ./config.json
sudo ./scripts/stress-connect.sh --mode mesh --config ./mesh.json
```

See [Connection stress test](docs/CONNECTION_STRESS_TEST.md) for safety
properties, options and result interpretation.

## Disclaimer

Please do not use this project for abuse. Abusive use harms Cloudflare, risks
sanctions against this project, and may make the service less accessible to
everyone. You are solely responsible for how you use this software and for
complying with Cloudflare's terms and all applicable laws.

Cloudflare has not granted this project written permission to use undocumented
client endpoints. Publication of this repository does not grant users any
license to Cloudflare's proprietary software, services, APIs, trademarks or
other intellectual property. The project does not bypass authentication,
authorization, service limits, account restrictions or technical protection
measures. The sole platform exception is the prominently disclosed
`linux` value used for optional FreeBSD Mesh enrollment after explicit
operator acknowledgement; it must not be used to evade any further Cloudflare
block or enforcement action. See [LEGAL.md](LEGAL.md) for the complete notice.

This project implements properties of Cloudflare's clients and wire contracts
only where they are required for protocol compatibility, interoperability and
connection stability. It is not intended to be indistinguishable from an
official client and does not attempt to conceal its identity. Device-state and
monitoring data sent by both roles are truthful: each identifies the platform
as FreeBSD, uses this project's own version identity, and derives values from
the real system and MASQUE session. Mesh additionally reports the real quiche
path statistics required by its Connector session. Only the Mesh enrollment
platform field is the documented `linux` compatibility claim described above;
that value is not reused as runtime identity or telemetry. The project never
reports itself as an official Cloudflare client. Cloudflare can distinguish and
restrict this implementation at any time.

This software is provided as-is, without warranties or guarantees. Its authors
and contributors are not responsible, to the maximum extent permitted by
applicable law, for account warnings, credential revocation, node disabling,
service restrictions, suspension or termination, service interruption, data
loss, financial loss, business interruption, or damage to systems or networks
resulting from use of the software or the Mesh platform compatibility claim.
Although the project is developed with security in mind, it is an independent
hobby and research project, not a professionally audited security product. Use
it entirely at your own risk.

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

The client registration workflow was inherited from upstream. The device-state
telemetry contract added by this port was inferred from authorized observation
of official-client network traffic and is documented in
[PROTOCOL_SOURCES.md](PROTOCOL_SOURCES.md). The current maintainers cannot
independently attest to every research method used before the upstream code was
inherited.

It is an independent community project and is not affiliated with or endorsed by Cloudflare.

## License

Licensed under the MIT License. See [LICENSE.md](LICENSE.md).
