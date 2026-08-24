# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Formal release tracking starts with version 0.8.0; earlier development remains
available in the Git history.

## [Unreleased]

## [0.8.4] - 2026-08-24

### Added

- Once-per-minute, read-only QUIC path diagnostics for long-running tunnel
  analysis: the active UDP/path tuple, validation state, RTT, CWND, delivery
  rate, PMTU, PTO, loss/retransmission, DATAGRAM and byte counters, cumulative
  in-flight duration, and the pacing waits actually applied by the UDP batch
  sender.
- Diagnostics use only public quiche statistics and never invent unavailable
  instantaneous bytes-in-flight or pacing-rate values. They do not change
  client or Mesh transport behavior.

### Changed

- Bound QUIC-to-TUN DATAGRAM draining to 32 packets per packet-pump iteration,
  allowing upstream TUN, HTTP/3 and QUIC control work to run fairly during
  sustained downloads. The scheduler-only change preserves packet ordering,
  RFC 9484 framing, quiche flow control and congestion control.
- Added the cumulative `rxb` operational counter for iterations that reach
  the receive-drain budget, making the fairness behavior observable without
  changing tunnel traffic.
- Keep every API-advertised Cloudflare MASQUE endpoint while applying a stable
  priority: advertised port 443 first, advertised port 1701 last, and all
  other API ordering preserved.
- Rotate through ordered fallbacks only before CONNECT-IP establishment. When
  an established session ends, reconnect starts again from the preferred
  endpoint.

## [0.8.3] - 2026-08-09

### Fixed

- On the first process start after a known client-version change, refresh the
  existing Cloudflare device registration with the same device ID and P-256
  key, then persist the new version only after the update succeeds. This lets
  registration-backed device inventory catch up with the already-correct live
  telemetry and Mesh CONNECT version.
- The refresh is not sent on same-version starts, internal QUIC reconnects or
  configs without known registration-version history. A failed refresh does not
  block tunnel startup and is retried only on the next process start.
- Mesh refreshes preserve the explicit platform claim stored at registration;
  runtime user-agent and telemetry identity remain truthful FreeBSD data.

## [0.8.2] - 2026-08-09

### Fixed

- Live device-state telemetry, the native-TUN user agent, and the Mesh
  CONNECT-IP client-version header now report the running binary version
  instead of the historical version persisted at registration. Existing
  client and Mesh configurations update without re-registration or file edits.

### Added

- Optional egress-client enrollment from Cloudflare's documented Linux
  `mdm.xml` keys (`organization`, `auth_client_id`, and
  `auth_client_secret`) through `register --mdm-file`.
- A dedicated Cloudflare Access enrollment exchange: service-token credentials
  are sent only to `https://<organization>.cloudflareaccess.com/warp`, redirects
  are not followed, and only an origin-bound `com.cloudflare.warp://.../auth`
  callback JWT is accepted for the existing device-registration request.
- Owner-only, non-symlink MDM file validation and tests proving service-token
  headers cannot reach the device-registration origin.

### Validated

- Authorized end-to-end testing on 2026-08-08 confirmed Access JWT issuance,
  non-interactive device registration, P-256 MASQUE key enrollment, CONNECT-IP
  establishment, truthful device-state authorization, dual-stack addressing,
  zero-loss IPv4/IPv6 ICMP, and HTTPS traffic through the egress tunnel.

## [0.8.1] - 2026-08-02

### Fixed

- Treat quiche HTTP/3 `Finished` and `Reset` events on the original
  CONNECT-IP request stream as the end of the RFC 9484 tunnel, allowing the
  existing supervisor to reconnect immediately instead of leaving a locally
  live but unusable session.
- Keep auxiliary HTTP/3 request-stream completion isolated from CONNECT-IP
  lifetime, so Mesh `/h3-stats` responses cannot cause false reconnects.
- Propagate non-`Done` HTTP/3 polling failures to the reconnect supervisor
  instead of logging and continuing with invalid H3 state.

The fix follows a captured long-run failure where Cloudflare reset CONNECT-IP
stream 0 with `H3_NO_ERROR` (`0x100`) after 4 hours 35 minutes while the
underlying QUIC connection remained open.

## [0.8.0] - 2026-08-01

### Added

- Mesh-only, configurable QUIC dead-peer detection through quiche's native
  `max_idle_timeout` transport parameter, with a 90-second default.
- Regression tests proving that normal client mode retains its previous
  unlimited idle timeout and rejects the Mesh-only CLI option.

### Changed

- Silent Mesh Edge-session loss now reaches the existing reconnect supervisor,
  which establishes a fresh CONNECT-IP session and sends its one-time activation
  packet without adding periodic inner-tunnel traffic or another API heartbeat.
