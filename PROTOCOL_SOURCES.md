# Protocol source and provenance record

This record distinguishes public standards and APIs from inherited or
undocumented interoperability behavior. It should be updated whenever a new
endpoint, request field, protocol extension or official-client behavior is
implemented.

Last reviewed against the linked public sources: 2026-07-25.

"Documented" means that a public source describes the relevant behavior. It
does not mean that Cloudflare supports this third-party client. "Observed"
means behavior inferred during authorized use of an account and device; it does
not mean that Cloudflare has authorized the resulting integration.

| Area | Classification | Source and provenance |
| --- | --- | --- |
| QUIC transport and keepalive | Public standard and public library | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), implemented through Cloudflare's open-source [`quiche`](https://github.com/cloudflare/quiche) APIs |
| HTTP/3 Extended CONNECT | Public standard and public library | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114), [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) and `quiche::h3` |
| MASQUE CONNECT-IP framing | Public standard | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) |
| DPLPMTUD and dynamic tunnel MTU | Public standard, public library and public Cloudflare documentation | [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899), [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200), public `quiche`/`tun-rs` APIs and Cloudflare's [Path MTU Discovery](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/mdm-deployment/path-mtu-discovery/) behavior |
| Native TUN integration | Public library and operating-system APIs | Public [`tun-rs`](https://crates.io/crates/tun-rs) API and documented FreeBSD system interfaces |
| Orchestration SNI `api.devices.cloudflare.com` | Public Cloudflare documentation | [Cloudflare One Client firewall documentation](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/) and Cloudflare One Client changelog |
| Device and registration response models | Public Cloudflare API | [WARP registrations API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/devices/subresources/registrations/) and documented physical-device API models |
| Client registration workflow | Inherited, partially documented wire contract | Inherited from MIT-licensed [`Diniboy1123/usque-rs`](https://github.com/Diniboy1123/usque-rs), then adapted for P-256 MASQUE enrollment and truthful FreeBSD metadata. Public Cloudflare models corroborate several fields, but Cloudflare does not publish the complete client enrollment request contract. This port did not originate the workflow and cannot independently attest to every earlier research method. |
| Client API version and enrollment request path | Undocumented interoperability behavior | Retained for compatibility with the inherited registration workflow and later compatible orchestration changes. No claim of public API status or Cloudflare approval is made. |
| Cloudflare-specific `cf-connect-ip` request values | Inherited interoperability behavior | Present in the imported native MASQUE implementation and used only to establish the CONNECT-IP tunnel. Standards-compliant HTTP/3 and capsule handling remain delegated to `quiche`. |
| Device-state endpoint and payload | Observed undocumented interoperability behavior | Inferred from network traffic produced by an official client on the maintainer's authorized account/device, compared with that account's dashboard and public Cloudflare device models. Added by this FreeBSD port; not copied from Cloudflare source code and not represented as a public or supported API. |
| FreeBSD telemetry values | Locally measured | Derived from native FreeBSD interfaces and the active `quiche` connection. Missing measurements are omitted and official-client identity or values are not fabricated. |

## Development rules for undocumented behavior

Changes involving undocumented behavior must satisfy all of the following:

1. The change has a concrete interoperability or truthful reporting purpose.
2. The information source is recorded here and in the commit message.
3. Observation is performed only with an account, device and credentials the
   researcher is authorized to use.
4. No authentication, authorization, service limit, account restriction,
   security control or technical protection measure is bypassed.
5. No proprietary source or binary code, confidential document, credential,
   private key, reusable token, personal traffic capture or extracted asset is
   committed.
6. Values sent to Cloudflare describe this client and the real host/session;
   they must not impersonate an official client or another device.
7. An explicit Cloudflare restriction or block must not be circumvented.

Where a public standard or documented Cloudflare API can replace observed
behavior, the public mechanism is preferred. A public response model may be
used to validate field meaning, but it must not be presented as documentation
for an unpublished client request contract.

## Maintaining evidence

For each material protocol change, keep the following in the commit or issue
record without publishing secrets or personal data:

- the public documentation URLs and access date;
- the applicable RFC and library API;
- whether behavior was inherited, documented, or observed;
- the account/device authorization context in non-identifying terms;
- why the behavior is needed; and
- tests showing that reported values are truthful and that failure remains
  non-destructive.

Do not commit raw captures from authenticated sessions. A sanitized schema or
minimal field description is preferred when evidence must be recorded in the
repository.
