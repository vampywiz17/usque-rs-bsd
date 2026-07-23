use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait TunnelDevice: Send + Sync {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize>;
    async fn write_packet(&self, packet: &[u8]) -> Result<()>;
    fn name(&self) -> &str;
}
