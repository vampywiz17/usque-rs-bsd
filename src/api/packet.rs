use thiserror::Error;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("empty packet")]
    Empty,
    #[error("unknown IP version: {0}")]
    UnknownVersion(u8),
    #[error("packet too short for IPv{version} header (got {len} bytes)")]
    TooShort { version: u8, len: usize },
    #[error("TTL/hop limit too small: {0}")]
    TtlExpired(u8),
}

#[inline]
pub fn ip_version(buf: &[u8]) -> u8 {
    buf[0] >> 4
}

pub fn prepare_outgoing(buf: &mut [u8]) -> Result<u8, PacketError> {
    if buf.is_empty() {
        return Err(PacketError::Empty);
    }

    match ip_version(buf) {
        4 => {
            if buf.len() < IPV4_HEADER_LEN {
                return Err(PacketError::TooShort {
                    version: 4,
                    len: buf.len(),
                });
            }
            let ttl = buf[8];
            if ttl <= 1 {
                return Err(PacketError::TtlExpired(ttl));
            }
            buf[8] -= 1;
            let checksum = calculate_ipv4_checksum(buf);
            buf[10..12].copy_from_slice(&checksum.to_be_bytes());
            Ok(4)
        }
        6 => {
            if buf.len() < IPV6_HEADER_LEN {
                return Err(PacketError::TooShort {
                    version: 6,
                    len: buf.len(),
                });
            }
            let hop_limit = buf[7];
            if hop_limit <= 1 {
                return Err(PacketError::TtlExpired(hop_limit));
            }
            buf[7] -= 1;
            Ok(6)
        }
        v => Err(PacketError::UnknownVersion(v)),
    }
}

pub fn validate_incoming(buf: &[u8]) -> Result<u8, PacketError> {
    if buf.is_empty() {
        return Err(PacketError::Empty);
    }
    match ip_version(buf) {
        4 => {
            if buf.len() < IPV4_HEADER_LEN {
                return Err(PacketError::TooShort {
                    version: 4,
                    len: buf.len(),
                });
            }
            Ok(4)
        }
        6 => {
            if buf.len() < IPV6_HEADER_LEN {
                return Err(PacketError::TooShort {
                    version: 6,
                    len: buf.len(),
                });
            }
            Ok(6)
        }
        v => Err(PacketError::UnknownVersion(v)),
    }
}

fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let ihl = ((header[0] & 0x0f) as usize) * 4;
    let len = ihl.min(header.len());
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < len {
        if i == 10 {
            i += 2;
            continue;
        }
        let word = if i + 1 < len {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += u32::from(word);
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(ttl: u8) -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(IPV4_HEADER_LEN as u16).to_be_bytes());
        packet[8] = ttl;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet
    }

    #[test]
    fn outgoing_ipv4_decrements_ttl_and_updates_checksum() {
        let mut packet = ipv4_packet(64);
        assert_eq!(prepare_outgoing(&mut packet).unwrap(), 4);
        assert_eq!(packet[8], 63);
        assert_eq!(
            u16::from_be_bytes([packet[10], packet[11]]),
            calculate_ipv4_checksum(&packet)
        );
    }

    #[test]
    fn outgoing_ipv6_decrements_hop_limit() {
        let mut packet = vec![0u8; IPV6_HEADER_LEN];
        packet[0] = 0x60;
        packet[7] = 64;
        assert_eq!(prepare_outgoing(&mut packet).unwrap(), 6);
        assert_eq!(packet[7], 63);
    }

    #[test]
    fn outgoing_packet_rejects_expired_hop_count() {
        let mut ipv4 = ipv4_packet(1);
        assert!(matches!(
            prepare_outgoing(&mut ipv4),
            Err(PacketError::TtlExpired(1))
        ));

        let mut ipv6 = vec![0u8; IPV6_HEADER_LEN];
        ipv6[0] = 0x60;
        ipv6[7] = 1;
        assert!(matches!(
            prepare_outgoing(&mut ipv6),
            Err(PacketError::TtlExpired(1))
        ));
    }

    #[test]
    fn packet_validation_rejects_empty_and_short_packets() {
        assert!(matches!(validate_incoming(&[]), Err(PacketError::Empty)));
        assert!(matches!(
            validate_incoming(&[0x45; IPV4_HEADER_LEN - 1]),
            Err(PacketError::TooShort { version: 4, len }) if len == IPV4_HEADER_LEN - 1
        ));
    }
}
