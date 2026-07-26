# Contributing

Contributions are welcome when they preserve the project's tunnel-only scope,
standards compliance, truthful runtime identity, the narrowly disclosed Mesh
platform exception and documented provenance.

Read [`LEGAL.md`](LEGAL.md) and [`PROTOCOL_SOURCES.md`](PROTOCOL_SOURCES.md)
before submitting a change involving Cloudflare behavior, registration,
telemetry, credentials, QUIC, HTTP/3 or MASQUE.

## Rights and provenance requirements

By contributing, you represent that you have the right to submit the material
under the project's MIT License. Do not submit:

- proprietary source or binary code from an official client;
- decompiled code or copied implementation expression;
- confidential or access-controlled documentation;
- credentials, tokens, private keys, device configurations or personal data;
- raw authenticated traffic captures;
- material obtained by bypassing authentication, authorization, service
  limits, account restrictions, security controls or technical protection
  measures; or
- a change intended to impersonate an official client or another device.

Public protocol facts and independently written interoperability code must be
clearly distinguished from copied implementation material. If you are not sure
that you have the right to contribute something, do not submit it.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` trailer certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add the trailer. The sign-off records that the
contributor created the change or otherwise has the right to submit it under
the indicated open-source license. It is a provenance record, not a guarantee
that a third party supports the resulting integration.

## Protocol and API changes

A change involving an endpoint, request field, protocol value or
official-client behavior must:

1. classify the source as public standard, public Cloudflare documentation,
   inherited behavior, or authorized observation;
2. update [`PROTOCOL_SOURCES.md`](PROTOCOL_SOURCES.md);
3. cite public sources and their access date when available;
4. state why undocumented behavior is necessary;
5. use only accounts, devices and credentials the researcher is authorized to
   use;
6. report this project's real platform, version and measured values, except for
   the single documented and explicitly acknowledged Mesh enrollment claim; and
7. include tests appropriate to the affected wire contract and failure path.

Public standards and documented APIs are preferred whenever they can provide
the required behavior. Do not work around an explicit Cloudflare block,
restriction or withdrawal of access.

Do not broaden or conceal the Mesh `type: "linux"` exception. Mesh changes
must preserve the explicit acknowledgement, the real FreeBSD identity in local
audit metadata, runtime identification and all device telemetry. Shared client
and Mesh metrics must come from the same truthful collectors; Mesh-only control
data must come from the real Connector session. A later Cloudflare rejection or
block must stop the operation rather than trigger identity fallback or evasion.

## Engineering requirements

- Use public, supported `quiche`, `tun-rs` and FreeBSD APIs.
- Preserve the separation between registration, orchestration, MASQUE control
  flow, UDP transport and native TUN handling.
- Do not make telemetry failure terminate or reconnect a healthy tunnel.
- Omit unavailable measurements instead of fabricating zero or official-client
  values.
- Update the README's “Differences from upstream” table for material behavior
  not present in `Diniboy1123/usque-rs`.
- Run formatting, unit tests and target-appropriate build checks.

## Security reports

Do not open a public issue containing credentials, private captures, personal
data or unpatched exploit details. Open an issue with contact information and a
non-sensitive summary so that private coordination can be arranged.
