use crate::api::tunnel::TunnelDevice;
use crate::config::AppConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;
use tun_rs::{AsyncDevice, DeviceBuilder};

#[derive(Debug, Clone)]
pub struct TunOptions {
    pub name: Option<String>,
    pub mtu: u16,
    pub configure_addresses: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub persist: bool,
}

pub struct TunRsDevice {
    name: String,
    dev: AsyncDevice,
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
            .with_context(|| format!("tun-rs failed to set TUN MTU to {mtu}"))
    }

    pub async fn create(cfg: &AppConfig, opts: TunOptions) -> Result<Arc<Self>> {
        let mut builder = DeviceBuilder::new().mtu(opts.mtu);

        if let Some(name) = opts.name.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.name(name);
        }

        if opts.configure_addresses {
            if opts.ipv4 {
                builder = builder.ipv4(cfg.ipv4.as_str(), 32, None::<&str>);
            }
            if opts.ipv6 {
                builder = builder.ipv6(cfg.ipv6.as_str(), 128);
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
        Ok(Arc::new(Self { name, dev }))
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
