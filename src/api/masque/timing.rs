//! QUIC keepalive and DPLPMTUD scheduling helpers.

use std::time::Duration;

pub(super) fn keepalive_remaining(
    period: Duration,
    since_last_probe: Duration,
) -> Option<Duration> {
    if period.is_zero() {
        None
    } else {
        Some(period.saturating_sub(since_last_probe))
    }
}

pub(super) fn pmtud_remaining(
    enabled: bool,
    period: Duration,
    since_last_probe: Duration,
) -> Option<Duration> {
    if !enabled || period.is_zero() {
        None
    } else {
        Some(period.saturating_sub(since_last_probe))
    }
}

pub(super) fn discovered_tun_mtu(
    conn: &quiche::Connection,
    masque_context_len: usize,
    maximum: u16,
) -> Option<u16> {
    conn.pmtu()?;
    let writable = conn.dgram_max_writable_len()?;
    let inner = writable.checked_sub(masque_context_len)?;
    Some(inner.min(usize::from(maximum)).min(usize::from(u16::MAX)) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_can_be_disabled() {
        assert_eq!(
            keepalive_remaining(Duration::ZERO, Duration::from_secs(60)),
            None
        );
    }

    #[test]
    fn keepalive_waits_only_for_remaining_probe_interval() {
        assert_eq!(
            keepalive_remaining(Duration::from_secs(25), Duration::from_secs(10)),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            keepalive_remaining(Duration::from_secs(25), Duration::from_secs(25)),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn pmtud_revalidation_can_be_disabled_independently() {
        assert_eq!(
            pmtud_remaining(true, Duration::ZERO, Duration::from_secs(60)),
            None
        );
        assert_eq!(
            pmtud_remaining(false, Duration::from_secs(600), Duration::from_secs(60)),
            None
        );
    }

    #[test]
    fn pmtud_revalidation_uses_remaining_period() {
        assert_eq!(
            pmtud_remaining(true, Duration::from_secs(600), Duration::from_secs(125)),
            Some(Duration::from_secs(475))
        );
        assert_eq!(
            pmtud_remaining(true, Duration::from_secs(600), Duration::from_secs(600)),
            Some(Duration::ZERO)
        );
    }
}
