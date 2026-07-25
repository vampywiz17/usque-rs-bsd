//! MASQUE endpoint rotation and reconnect supervision.

use super::{run_tunnel_session, MasqueConfig};
use crate::native_tun::TunRsDevice;
use anyhow::{anyhow, bail, Result};
use std::sync::Arc;

pub async fn maintain_native_tun(
    cfg: MasqueConfig,
    dev: Arc<TunRsDevice>,
    mtu: usize,
) -> Result<()> {
    let mut pending_pkt: Option<Vec<u8>> = None;
    let mut endpoint_index = 0usize;

    loop {
        dev.apply_path_mtu(
            cfg.path_mtu.initial_tun_mtu,
            cfg.path_mtu.tunnel_ipv6 && !cfg.path_mtu.enabled,
        )?;

        if !cfg.reconnect.always && pending_pkt.is_none() {
            tracing::info!("Tunnel idle. Waiting for outbound activity before reconnecting...");
            let mut wait_buf = vec![0u8; mtu + 128];
            let n = dev.recv_packet(&mut wait_buf).await?;
            if n == 0 {
                bail!("TUN device closed");
            }
            wait_buf.truncate(n);
            pending_pkt = Some(wait_buf);
            tracing::info!("Detected outbound activity ({n} bytes). Connecting...");
        }

        let endpoint = cfg
            .endpoints
            .get(endpoint_index)
            .ok_or_else(|| anyhow!("MASQUE endpoint list is empty"))?;
        tracing::info!(
            "Establishing MASQUE connection to {} ({}/{}){}",
            endpoint.addr,
            endpoint_index + 1,
            cfg.endpoints.len(),
            if endpoint.host.is_empty() {
                String::new()
            } else {
                format!(" for {}", endpoint.host)
            }
        );
        match run_tunnel_session(&cfg, endpoint, &dev, mtu, &mut pending_pkt).await {
            Ok(()) => tracing::warn!("MASQUE session ended. Reconnecting..."),
            Err(err) => tracing::warn!("MASQUE session failed: {err:#}. Reconnecting..."),
        }
        // A new endpoint is a new, unvalidated path. Withdraw IPv6 and return
        // to the conservative MTU before the reconnect delay so the host cannot
        // route packets using stale capacity from the previous QUIC path.
        dev.apply_path_mtu(
            cfg.path_mtu.initial_tun_mtu,
            cfg.path_mtu.tunnel_ipv6 && !cfg.path_mtu.enabled,
        )?;
        endpoint_index = (endpoint_index + 1) % cfg.endpoints.len();
        tokio::time::sleep(cfg.reconnect.delay).await;
    }
}
