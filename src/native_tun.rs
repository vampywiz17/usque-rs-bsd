use crate::api::tunnel::TunnelDevice;
use crate::config::AppConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub const IPV6_MIN_MTU: u16 = 1280;

#[derive(Debug, Clone)]
pub struct TunOptions {
    pub name: Option<String>,
    pub mtu: u16,
    pub configure_addresses: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub defer_ipv6: bool,
    pub persist: bool,
}

pub struct TunRsDevice {
    name: String,
    dev: AsyncDevice,
    mtu: AtomicU16,
    ipv6_address: Option<Ipv6Addr>,
    manage_ipv6: bool,
    ipv6_enabled: AtomicBool,
}

impl TunRsDevice {
    pub async fn recv_packet(&self, buf: &mut [u8]) -> Result<usize> {
        self.dev.recv(buf).await.context("tun-rs recv failed")
    }

    pub async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        self.dev.send(packet).await.context("tun-rs send failed")?;
        Ok(())
    }

    pub fn mtu(&self) -> Result<u16> {
        self.dev.mtu().context("tun-rs failed to read TUN MTU")
    }

    pub fn set_mtu(&self, mtu: u16) -> Result<()> {
        self.dev
            .set_mtu(mtu)
            .with_context(|| format!("tun-rs failed to set TUN MTU to {mtu}"))?;
        self.mtu.store(mtu, Ordering::Release);
        Ok(())
    }

    pub fn current_mtu(&self) -> u16 {
        self.mtu.load(Ordering::Acquire)
    }

    pub fn set_ipv6_enabled(&self, enabled: bool) -> Result<()> {
        let Some(address) = self.ipv6_address else {
            return Ok(());
        };
        if !self.manage_ipv6 || self.ipv6_enabled.load(Ordering::Acquire) == enabled {
            return Ok(());
        }

        if enabled {
            self.dev
                .add_address_v6(address, 128)
                .with_context(|| format!("tun-rs failed to add TUN IPv6 address {address}/128"))?;
        } else {
            self.dev
                .remove_address(IpAddr::V6(address))
                .with_context(|| format!("tun-rs failed to remove TUN IPv6 address {address}"))?;
        }
        self.ipv6_enabled.store(enabled, Ordering::Release);
        tracing::info!(
            "TUN IPv6 {}: {address}/128",
            if enabled { "enabled" } else { "disabled" }
        );
        Ok(())
    }

    pub fn apply_path_mtu(&self, mtu: u16, allow_ipv6: bool) -> Result<()> {
        let enable_ipv6 = allow_ipv6 && ipv6_path_supported(mtu);
        if !enable_ipv6 {
            self.set_ipv6_enabled(false)?;
        }
        if self.current_mtu() != mtu {
            self.set_mtu(mtu)?;
        }
        if enable_ipv6 {
            self.set_ipv6_enabled(true)?;
        }
        Ok(())
    }

    pub async fn create(cfg: &AppConfig, opts: TunOptions) -> Result<Arc<Self>> {
        let mut builder = DeviceBuilder::new().mtu(opts.mtu);
        let ipv6_address = opts
            .ipv6
            .then(|| cfg.ipv6.parse::<Ipv6Addr>())
            .transpose()
            .with_context(|| format!("invalid configured IPv6 address: {}", cfg.ipv6))?;
        let ipv6_initially_enabled =
            opts.configure_addresses && ipv6_address.is_some() && !opts.defer_ipv6;

        if let Some(name) = opts.name.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.name(name);
        }

        if opts.configure_addresses {
            if opts.ipv4 {
                builder = builder.ipv4(cfg.ipv4.as_str(), 32, None::<&str>);
            }
            if let Some(address) = ipv6_address.filter(|_| !opts.defer_ipv6) {
                builder = builder.ipv6(address, 128);
            }
        }

        let dev = builder
            .build_async()
            .context("failed to build tun-rs AsyncDevice")?;

        if opts.configure_addresses {
            // Linux exposes enabled(true) through tun-rs. On BSD/macOS/Windows,
            // the builder address setup is used where available; otherwise do
            // manual host-side ifconfig/netsh setup.
            #[cfg(target_os = "linux")]
            if let Err(err) = dev.enabled(true) {
                tracing::warn!(
                    "failed to set interface up via tun-rs: {err}; configure it manually if needed"
                );
            }
        } else {
            tracing::info!("Skipping address/link setup. Configure the TUN interface manually.");
            tracing::info!("Config IPv4: {}", cfg.ipv4);
            tracing::info!("Config IPv6: {}", cfg.ipv6);
        }

        if opts.persist {
            #[cfg(target_os = "linux")]
            dev.persist().context("failed to persist TUN interface")?;
            #[cfg(not(target_os = "linux"))]
            tracing::warn!("--persist is only supported on Linux by this port");
        }

        let name = dev
            .name()
            .unwrap_or_else(|_| opts.name.unwrap_or_else(|| "tun-rs".to_string()));
        Ok(Arc::new(Self {
            name,
            dev,
            mtu: AtomicU16::new(opts.mtu),
            ipv6_address,
            manage_ipv6: opts.configure_addresses,
            ipv6_enabled: AtomicBool::new(ipv6_initially_enabled),
        }))
    }
}

fn ipv6_path_supported(mtu: u16) -> bool {
    mtu >= IPV6_MIN_MTU
}

#[cfg(test)]
mod tests {
    use super::ipv6_path_supported;

    #[test]
    fn ipv6_requires_the_rfc_8200_minimum_link_mtu() {
        assert!(!ipv6_path_supported(1279));
        assert!(ipv6_path_supported(1280));
        assert!(ipv6_path_supported(1500));
    }
}

#[async_trait]
impl TunnelDevice for Arc<TunRsDevice> {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        self.recv_packet(buf).await
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        self.send_packet(packet).await
    }

    fn name(&self) -> &str {
        &self.name
    }
}
