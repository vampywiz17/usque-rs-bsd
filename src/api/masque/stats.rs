//! Tunnel packet counters and periodic operational logging.

use portable_atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct Stats {
    pub(super) tx_packets: AtomicU64,
    pub(super) rx_packets: AtomicU64,
    pub(super) tx_bytes: AtomicU64,
    pub(super) rx_bytes: AtomicU64,
    pub(super) dropped: AtomicU64,
    pub(super) quic_lost: AtomicU64,
    pub(super) quic_retrans: AtomicU64,
    pub(super) tx_queue_len: AtomicU64,
    pub(super) tx_backpressure: AtomicU64,
    pub(super) rx_drain_budget_hits: AtomicU64,
}

impl Stats {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            quic_lost: AtomicU64::new(0),
            quic_retrans: AtomicU64::new(0),
            tx_queue_len: AtomicU64::new(0),
            tx_backpressure: AtomicU64::new(0),
            rx_drain_budget_hits: AtomicU64::new(0),
        })
    }
}

pub(super) fn spawn_stats_task(stats: Arc<Stats>, start: Instant) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            tracing::info!(
                "connected={} tx={} ({}) rx={} ({}) drop={} txq={} bp={} rxb={} lost={} retrans={}",
                format_duration(start.elapsed()),
                stats.tx_packets.load(Ordering::Relaxed),
                format_bytes(stats.tx_bytes.load(Ordering::Relaxed)),
                stats.rx_packets.load(Ordering::Relaxed),
                format_bytes(stats.rx_bytes.load(Ordering::Relaxed)),
                stats.dropped.load(Ordering::Relaxed),
                stats.tx_queue_len.load(Ordering::Relaxed),
                stats.tx_backpressure.load(Ordering::Relaxed),
                stats.rx_drain_budget_hits.load(Ordering::Relaxed),
                stats.quic_lost.load(Ordering::Relaxed),
                stats.quic_retrans.load(Ordering::Relaxed),
            );
        }
    })
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_all_transport_counters_to_zero() {
        let stats = Stats::new();
        assert_eq!(stats.tx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 0);
        assert_eq!(stats.quic_lost.load(Ordering::Relaxed), 0);
        assert_eq!(stats.quic_retrans.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tx_queue_len.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tx_backpressure.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rx_drain_budget_hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn formats_counter_units_at_binary_boundaries() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1536 * 1024), "1.5 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn formats_session_duration_without_losing_components() {
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 00s");
        assert_eq!(format_duration(Duration::from_secs(3599)), "59m 59s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 00m 00s");
        assert_eq!(format_duration(Duration::from_secs(7384)), "2h 03m 04s");
    }
}
