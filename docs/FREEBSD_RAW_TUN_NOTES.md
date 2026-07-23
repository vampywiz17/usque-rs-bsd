# FreeBSD raw TUN notes

The current program keeps `tun-rs` as the production TUN implementation because it already creates and configures `tun0` correctly on FreeBSD in testing.

A FreeBSD raw TUN backend is possible, but it is risky to make it the default without direct testing:

- FreeBSD `tun(4)` supports writing exactly one packet per `write(2)` call.
- If `TUNSIFHEAD` is enabled, a 4-byte address-family header must be prepended to packets; otherwise written packets are assumed to be `AF_INET`, which is not sufficient for IPv6.
- Raw backend must therefore either enable `TUNSIFHEAD` and add/remove the 4-byte AF header, or split IPv4/IPv6 handling carefully.
- Raw backend would also need interface creation/configuration or would require a pre-created `/dev/tunN` + `ifconfig tunN` setup.

Because the measured bottleneck is asymmetric upload while download is already 200+ Mbit/s, replacing `tun-rs` is unlikely to be the first-order fix. The main path optimized in this build is the TUN -> MASQUE DATAGRAM -> quiche -> UDP send side.
