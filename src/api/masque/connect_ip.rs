//! Cloudflare's HTTP/3 CONNECT-IP DATAGRAM framing.
//!
//! The wire payload follows the HTTP Datagram layout used by RFC 9297 and
//! RFC 9484: Quarter Stream ID, Context ID, then the complete IP packet.
//! Cloudflare negotiates its compatible profile with `cf-connect-ip`; context
//! ID zero carries an uncompressed IP packet.

use anyhow::{anyhow, Result};
use octets::{Octets, OctetsMut};

pub(super) fn build_flow_prefix(flow_id: u64) -> Result<Vec<u8>> {
    let mut tmp = [0u8; 8];
    let mut b = OctetsMut::with_slice(&mut tmp);
    b.put_varint(flow_id)
        .map_err(|e| anyhow!("encode flow_id varint: {e}"))?;
    let len = b.off();
    let mut flow_prefix = Vec::with_capacity(len + 1);
    flow_prefix.extend_from_slice(&tmp[..len]);
    flow_prefix.push(0x00);
    Ok(flow_prefix)
}

pub(super) fn parse_datagram(dgram: &[u8], expected_flow_id: u64) -> Option<&[u8]> {
    let mut b = Octets::with_slice(dgram);
    let flow_id = b.get_varint().ok()?;
    if flow_id != expected_flow_id {
        return None;
    }
    let context_id = b.get_varint().ok()?;
    if context_id != 0 {
        return None;
    }
    let off = b.off();
    if off >= dgram.len() {
        return None;
    }
    Some(&dgram[off..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let len = {
            let mut b = OctetsMut::with_slice(&mut tmp);
            b.put_varint(val).unwrap();
            b.off()
        };
        tmp[..len].to_vec()
    }

    #[test]
    fn parses_valid_ip_datagram() {
        let mut d = encode_varint(4);
        d.extend_from_slice(&encode_varint(0));
        d.extend_from_slice(b"payload");
        assert_eq!(parse_datagram(&d, 4), Some(b"payload".as_ref()));
    }

    #[test]
    fn flow_prefix_contains_quarter_stream_id_and_zero_context() {
        let prefix = build_flow_prefix(64).unwrap();
        let mut expected = encode_varint(64);
        expected.extend_from_slice(&encode_varint(0));
        assert_eq!(prefix, expected);
    }

    #[test]
    fn rejects_another_request_stream() {
        let mut d = encode_varint(5);
        d.extend_from_slice(&encode_varint(0));
        d.extend_from_slice(b"payload");
        assert_eq!(parse_datagram(&d, 4), None);
    }

    #[test]
    fn rejects_unknown_context() {
        let mut d = encode_varint(4);
        d.extend_from_slice(&encode_varint(2));
        d.extend_from_slice(b"payload");
        assert_eq!(parse_datagram(&d, 4), None);
    }

    #[test]
    fn rejects_missing_ip_payload() {
        let mut d = encode_varint(4);
        d.extend_from_slice(&encode_varint(0));
        assert_eq!(parse_datagram(&d, 4), None);
    }
}
