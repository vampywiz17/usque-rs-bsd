use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use std::{fs, net::{IpAddr, SocketAddr}};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub endpoint_pub_key: String,
    #[serde(default)]
    pub license: String,
    pub id: String,
    pub access_token: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| format!("failed to open config file {path}"))?;
        serde_json::from_str(&raw).with_context(|| format!("failed to decode config file {path}"))
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let raw = serde_json::to_string_pretty(self).context("failed to encode config")?;
        fs::write(path, raw).with_context(|| format!("failed to write config file {path}"))
    }

    pub fn get_ec_private_key(&self) -> Result<SecretKey> {
        let der = general_purpose::STANDARD
            .decode(&self.private_key)
            .context("failed to decode base64 private key")?;
        SecretKey::from_sec1_der(&der).context("failed to parse P-256 SEC1 private key")
    }

    pub fn get_ec_endpoint_public_key_der(&self) -> Result<Vec<u8>> {
        let pem = pem::parse(&self.endpoint_pub_key).context("failed to decode endpoint public key PEM")?;
        Ok(pem.contents().to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct EndpointAddr(pub SocketAddr);

impl std::fmt::Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn warn_insecure() {
    tracing::warn!("--insecure is set, endpoint certificate pinning is disabled. Do not use in production!");
}

pub fn select_endpoint_from_config(cfg: &AppConfig, use_ipv6: bool, port: u16) -> Result<EndpointAddr> {
    if use_ipv6 {
        parse_socket(&cfg.endpoint_v6, port).map(EndpointAddr)
    } else {
        parse_socket(&cfg.endpoint_v4, port).map(EndpointAddr)
    }
}

fn parse_socket(ip: &str, port: u16) -> Result<SocketAddr> {
    let ip: IpAddr = ip.parse().with_context(|| format!("invalid endpoint IP value {ip:?}"))?;
    Ok(SocketAddr::new(ip, port))
}

pub fn endpoint_v4_from_account_value(input: &str) -> String {
    input.strip_suffix(":0").unwrap_or(input).to_string()
}

pub fn endpoint_v6_from_account_value(input: &str) -> String {
    input
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix("]:0"))
        .unwrap_or(input)
        .to_string()
}
