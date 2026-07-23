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
                return Err(PacketError::TooShort { version: 4, len: buf.len() });
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
                return Err(PacketError::TooShort { version: 6, len: buf.len() });
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
                return Err(PacketError::TooShort { version: 4, len: buf.len() });
            }
            Ok(4)
        }
        6 => {
            if buf.len() < IPV6_HEADER_LEN {
                return Err(PacketError::TooShort { version: 6, len: buf.len() });
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
