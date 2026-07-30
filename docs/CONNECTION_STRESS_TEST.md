# Connection stress test

`scripts/stress-connect.sh` repeatedly establishes and tears down the real
QUIC, HTTP/3 and CONNECT-IP session. It is intended to catch intermittent
handshake failures, `PROTOCOL_VIOLATION` errors and leaked test TUN interfaces.

This is an operator-run integration test, not a public CI job. It requires:

- FreeBSD with `ifconfig`;
- root access for native TUN creation;
- an already-built release binary;
- an existing, valid client or Mesh configuration;
- network access to the Cloudflare endpoints stored in that configuration.

The test does not register devices, modify the configuration, add routes or
change firewall policy. It passes `--no-iproute2`, creates one dedicated test
interface, and destroys that exact interface after every iteration. It refuses
to start an iteration if the requested interface already exists.

Normal client mode uses `--always-reconnect` so each iteration establishes a
session without requiring a routed packet. Mesh mode retains the production
Mesh behavior, including its single standards-compliant inner activation probe.
Normal truthful device-state reporting remains enabled in both modes, so the
test can create connection events and telemetry samples in the Cloudflare
dashboard.

## Examples

Build the production binary first:

```sh
cargo build --release
```

Run the default 50 IPv4-preferred client iterations:

```sh
sudo ./scripts/stress-connect.sh \
  --mode client \
  --config ./config.json
```

Run Mesh mode with its separate configuration:

```sh
sudo ./scripts/stress-connect.sh \
  --mode mesh \
  --config ./mesh.json
```

Prefer an IPv6 MASQUE endpoint, run 100 iterations and retain each established
connection for five seconds:

```sh
sudo ./scripts/stress-connect.sh \
  --mode client \
  --config ./config.json \
  --iterations 100 \
  --prefer-ipv6 \
  --hold-seconds 5
```

The default test interface is `tun99`. Override it only with a dedicated,
otherwise unused FreeBSD TUN name:

```sh
sudo ./scripts/stress-connect.sh \
  --mode mesh \
  --config ./mesh.json \
  --interface tun98
```

Each run creates a private log directory below `${TMPDIR:-/tmp}` and prints
its path. Logs are retained for diagnosis and can contain device identifiers or
endpoint addresses; handle them as private diagnostic data.

## Pass criteria

A clean run reports:

- every requested iteration connected;
- zero failed iterations;
- zero log occurrences of `PROTOCOL_VIOLATION`;
- no pre-existing or leftover test interface.

The test intentionally validates connection establishment and teardown rather
than throughput, routing or long-duration keepalive. Those remain separate live
tests so a failure can be attributed to the correct protocol layer.
