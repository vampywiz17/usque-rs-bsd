const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_TYPE_DEST_UNREACHABLE: u8 = 3;
const ICMP_CODE_FRAG_NEEDED: u8 = 4;
const ICMPV6_TYPE_PACKET_TOO_BIG: u8 = 2;

pub fn compose_icmp_too_large(packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => compose_ipv4_frag_needed(packet, mtu),
        6 => compose_ipv6_packet_too_big(packet, mtu),
        _ => None,
    }
}

fn compose_ipv4_frag_needed(packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if packet.len() < IPV4_HEADER_LEN {
        return None;
    }

    let src = &packet[12..16];
    let dst = &packet[16..20];
    let quote_len = packet
        .len()
        .min(576usize.saturating_sub(IPV4_HEADER_LEN + ICMP_HEADER_LEN));
    let total_len = IPV4_HEADER_LEN + ICMP_HEADER_LEN + quote_len;
    let mut out = vec![0u8; total_len];

    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[8] = 64;
    out[9] = 1;
    out[12..16].copy_from_slice(dst);
    out[16..20].copy_from_slice(src);

    out[20] = ICMP_TYPE_DEST_UNREACHABLE;
    out[21] = ICMP_CODE_FRAG_NEEDED;
    out[24..26].copy_from_slice(&mtu.to_be_bytes());
    out[28..28 + quote_len].copy_from_slice(&packet[..quote_len]);

    let ip_csum = checksum(&out[..IPV4_HEADER_LEN]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_csum = checksum(&out[IPV4_HEADER_LEN..]);
    out[22..24].copy_from_slice(&icmp_csum.to_be_bytes());
    Some(out)
}

fn compose_ipv6_packet_too_big(packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if packet.len() < IPV6_HEADER_LEN {
        return None;
    }

    let src = &packet[8..24];
    let dst = &packet[24..40];
    let quote_len = packet.len().min(1232);
    let payload_len = ICMP_HEADER_LEN + quote_len;
    let total_len = IPV6_HEADER_LEN + payload_len;
    let mut out = vec![0u8; total_len];

    out[0] = 0x60;
    out[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    out[6] = 58;
    out[7] = 64;
    out[8..24].copy_from_slice(dst);
    out[24..40].copy_from_slice(src);

    out[40] = ICMPV6_TYPE_PACKET_TOO_BIG;
    out[41] = 0;
    out[44..48].copy_from_slice(&(mtu as u32).to_be_bytes());
    out[48..48 + quote_len].copy_from_slice(&packet[..quote_len]);

    let icmp_csum = icmpv6_checksum(&out[8..24], &out[24..40], &out[40..]);
    out[42..44].copy_from_slice(&icmp_csum.to_be_bytes());
    Some(out)
}

fn checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = buf.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(src: &[u8], dst: &[u8], icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp);
    checksum(&pseudo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_frag_needed_quotes_packet_and_reports_mtu() {
        let mut packet = vec![0u8; 100];
        packet[0] = 0x45;
        packet[8] = 63;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);

        let reply = compose_icmp_too_large(&packet, 1280).unwrap();
        assert_eq!(&reply[12..16], &[198, 51, 100, 2]);
        assert_eq!(&reply[16..20], &[192, 0, 2, 1]);
        assert_eq!(reply[20], ICMP_TYPE_DEST_UNREACHABLE);
        assert_eq!(reply[21], ICMP_CODE_FRAG_NEEDED);
        assert_eq!(u16::from_be_bytes([reply[24], reply[25]]), 1280);
        assert_eq!(&reply[28..], packet.as_slice());
        assert!(reply.len() <= 576);
    }

    #[test]
    fn ipv6_packet_too_big_quotes_packet_and_reports_mtu() {
        let mut packet = vec![0u8; 1400];
        packet[0] = 0x60;
        packet[7] = 63;
        packet[8..24].copy_from_slice(&[0x20; 16]);
        packet[24..40].copy_from_slice(&[0x30; 16]);

        let reply = compose_icmp_too_large(&packet, 1280).unwrap();
        assert_eq!(&reply[8..24], &[0x30; 16]);
        assert_eq!(&reply[24..40], &[0x20; 16]);
        assert_eq!(reply[40], ICMPV6_TYPE_PACKET_TOO_BIG);
        assert_eq!(reply[41], 0);
        assert_eq!(
            u32::from_be_bytes([reply[44], reply[45], reply[46], reply[47]]),
            1280
        );
        assert_eq!(reply.len(), 1280);
        assert_eq!(&reply[48..], &packet[..1232]);
    }
}
