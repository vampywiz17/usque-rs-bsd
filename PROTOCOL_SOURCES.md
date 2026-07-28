# Protocol source and provenance record

This record distinguishes public standards and APIs from inherited or
undocumented interoperability behavior. It should be updated whenever a new
endpoint, request field, protocol extension or official-client behavior is
implemented.

Last reviewed against the linked public sources: 2026-07-29.

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
| Adaptive UDP socket buffers | Public library and operating-system APIs | Public [`socket2`](https://docs.rs/socket2/latest/socket2/struct.Socket.html) APIs for `SO_RCVBUF`/`SO_SNDBUF`, using `setsockopt` and `getsockopt` before bind/connect. Sizing is per socket, independently verified for receive/send, grows no further than the configured target and OS limit, never reduces a larger kernel default, and never changes a system-wide kernel setting. |
| Orchestration SNI `api.devices.cloudflare.com` | Public Cloudflare documentation | [Cloudflare One Client firewall documentation](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/) and Cloudflare One Client changelog |
| Device and registration response models | Public Cloudflare API | [WARP registrations API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/devices/subresources/registrations/) and documented physical-device API models |
| Client registration workflow | Inherited, partially documented wire contract | Inherited from MIT-licensed [`Diniboy1123/usque-rs`](https://github.com/Diniboy1123/usque-rs), then adapted for P-256 MASQUE enrollment and truthful FreeBSD metadata. Public Cloudflare models corroborate several fields, but Cloudflare does not publish the complete client enrollment request contract. This port did not originate the workflow and cannot independently attest to every earlier research method. |
| Client API version and enrollment request path | Undocumented interoperability behavior | Retained for compatibility with the inherited registration workflow and later compatible orchestration changes. No claim of public API status or Cloudflare approval is made. |
| Cloudflare-specific `cf-connect-ip` request values | Inherited interoperability behavior | Present in the imported native MASQUE implementation and used only to establish the CONNECT-IP tunnel. Standards-compliant HTTP/3 and capsule handling remain delegated to `quiche`. |
| Device-state endpoint and payload | Observed undocumented interoperability behavior | Inferred from network traffic produced by an official client on the maintainer's authorized account/device, compared with that account's dashboard and public Cloudflare device models. Added by this FreeBSD port; not copied from Cloudflare source code and not represented as a public or supported API. |
| FreeBSD telemetry values | Locally measured | Derived from native FreeBSD interfaces and the active `quiche` connection. Missing measurements are omitted and official-client identity or values are not fabricated. |
| Mesh resource provisioning | Public Cloudflare documentation and management API | Cloudflare's [Mesh get-started guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/get-started/) documents Connector creation, token provisioning and Linux-only supported operating systems. The [WARP Connector API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/warp_connector/) documents the account-scoped management resource. |
| Mesh Connector enrollment and config retrieval | Observed undocumented interoperability behavior with one disclosed platform exception | The account-scoped POST `/v1/accounts/{account_tag}/warp_connector`, compact Base64 token fields, Cloudflare `result` response envelope, and subsequent authenticated GET `/v1/accounts/{account_tag}/reg/{registration_id}?dex_tests_version=1` were independently inferred and validated during authorized use. Clean-room inspection of endpoint symbols and wire behavior from the SHA256-verified official Linux package `cloudflare-warp 2026.6.880.0` was used only to identify protocol facts; the temporary package was removed and no official source or binary code is included. A minimized request with truthful `freebsd` was rejected as an invalid Connector operating system. The optional implementation therefore sends `type: "linux"` only after explicit operator acknowledgement while preserving truthful FreeBSD runtime identity and local audit metadata. |
| Mesh data plane | Public standards and existing public-library path | Uses the same RFC 9484 CONNECT-IP, HTTP/3 DATAGRAM, `quiche` and `tun-rs` implementation as client mode. It adds no proprietary framing and deliberately leaves routes, forwarding, NAT and firewall policy to the administrator. |
| Mesh lifecycle and H3 path statistics | Observed Connector control behavior with public library measurements | Authorized comparison showed that a Mesh device uses the shared device-state lifecycle and `POST /h3-stats` on the existing H3 session at a 15-second cadence. Device and host values come from the same truthful FreeBSD/quiche collectors as client mode. The schema-version string and cumulative Connector values are serialized from quiche's active path statistics; response bodies are drained for H3 flow control but are neither interpreted nor logged. These truthful reports are orthogonal to data-plane activation and never fabricate a Mesh connection state. |
| Mesh session activation | Observed edge condition implemented only with public standards | Authorized A/B tests on the maintainer's account showed that registration, device-state, `/h3-stats` and idle CONNECT-IP leave the Connector connections API empty; the first inner IP packet creates the connection, after which QUIC keepalive preserves it. Reconnect requires another inner packet. The optional `activation_probe_target` therefore sends exactly one operator-addressed ICMP Echo Request or ICMPv6 Echo Request through the existing RFC 9484 HTTP/3 DATAGRAM path after each successful CONNECT-IP response. It adds no endpoint, proprietary field, route, status override or official-client claim, and is disabled by default and in client mode. |

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
6. Values sent to Cloudflare describe this client and the real host/session and
   must not impersonate an official client or another device. The sole exception
   is the documented, opt-in Mesh enrollment platform claim; actual FreeBSD
   identity remains recorded and truthful at runtime.
7. Authentication, authorization and later enforcement blocks must not be
   circumvented. The Linux-only Mesh platform claim is the sole documented
   compatibility exception and must never be expanded into identity evasion.

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
