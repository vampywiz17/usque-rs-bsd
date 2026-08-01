# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Formal release tracking starts with version 0.8.0; earlier development remains
available in the Git history.

## [Unreleased]

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
