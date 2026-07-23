use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr},
};

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
    /// Full MASQUE peer list returned by the Cloudflare registration API.
    /// Legacy configurations without this field continue to use the fields
    /// above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub masque_peers: Vec<MasquePeerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MasquePeerConfig {
    #[serde(default)]
    pub endpoint_v4: String,
    #[serde(default)]
    pub endpoint_v6: String,
    #[serde(default)]
    pub endpoint_host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub endpoint_pub_key: String,
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

}

#[derive(Debug, Clone)]
pub struct EndpointAddr(pub SocketAddr);

impl std::fmt::Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct MasqueEndpoint {
    pub addr: EndpointAddr,
    pub host: String,
    pub endpoint_pub_key_spki_der: Vec<u8>,
}

pub fn warn_insecure() {
    tracing::warn!("--insecure is set, endpoint certificate pinning is disabled. Do not use in production!");
}

/// Builds the ordered MASQUE endpoint list without taking over DNS, routing,
/// or firewall policy from the host BSD system.
///
/// `prefer_ipv6` changes ordering only: the other family remains available as
/// a connection fallback. `port_override == 0` uses the API-provided port list
/// and falls back to 443 when the API did not return one.
pub fn select_endpoints_from_config(
    cfg: &AppConfig,
    prefer_ipv6: bool,
    port_override: u16,
) -> Result<Vec<MasqueEndpoint>> {
    let legacy_peer;
    let peers: &[MasquePeerConfig] = if cfg.masque_peers.is_empty() {
        legacy_peer = MasquePeerConfig {
            endpoint_v4: cfg.endpoint_v4.clone(),
            endpoint_v6: cfg.endpoint_v6.clone(),
            endpoint_pub_key: cfg.endpoint_pub_key.clone(),
            ..Default::default()
        };
        std::slice::from_ref(&legacy_peer)
    } else {
        &cfg.masque_peers
    };

    let mut endpoints = Vec::new();
    let mut seen = HashSet::new();

    for peer in peers {
        let key = decode_endpoint_public_key(&peer.endpoint_pub_key)
            .context("failed to decode MASQUE peer endpoint public key")?;
        let ports: Vec<u16> = if port_override != 0 {
            vec![port_override]
        } else {
            let api_ports: Vec<u16> =
                peer.ports.iter().copied().filter(|port| *port != 0).collect();
            if api_ports.is_empty() {
                vec![443]
            } else {
                api_ports
            }
        };

        let families = if prefer_ipv6 {
            [
                peer.endpoint_v6.as_str(),
                peer.endpoint_v4.as_str(),
            ]
        } else {
            [
                peer.endpoint_v4.as_str(),
                peer.endpoint_v6.as_str(),
            ]
        };

        for address in families {
            if address.trim().is_empty() {
                continue;
            }
            for port in &ports {
                let socket = parse_socket(address, *port)?;
                if seen.insert((socket, key.clone())) {
                    endpoints.push(MasqueEndpoint {
                        addr: EndpointAddr(socket),
                        host: peer.endpoint_host.clone(),
                        endpoint_pub_key_spki_der: key.clone(),
                    });
                }
            }
        }
    }

    if endpoints.is_empty() {
        anyhow::bail!("Cloudflare configuration did not contain a usable MASQUE endpoint");
    }
    Ok(endpoints)
}

fn parse_socket(ip: &str, port: u16) -> Result<SocketAddr> {
    let normalized = ip
        .trim()
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(ip.trim());
    let ip: IpAddr = normalized
        .parse()
        .with_context(|| format!("invalid endpoint IP value {ip:?}"))?;
    Ok(SocketAddr::new(ip, port))
}

fn decode_endpoint_public_key(value: &str) -> Result<Vec<u8>> {
    let pem = pem::parse(value).context("failed to decode endpoint public key PEM")?;
    Ok(pem.contents().to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key_pem(marker: u8) -> String {
        pem::encode(&pem::Pem::new("PUBLIC KEY", vec![marker]))
    }

    #[test]
    fn endpoint_selection_uses_api_ports_and_family_preference() {
        let cfg = AppConfig {
            masque_peers: vec![MasquePeerConfig {
                endpoint_v4: "192.0.2.10".to_string(),
                endpoint_v6: "2001:db8::10".to_string(),
                endpoint_host: "masque.example".to_string(),
                ports: vec![443, 8443],
                endpoint_pub_key: test_public_key_pem(1),
            }],
            ..Default::default()
        };

        let endpoints = select_endpoints_from_config(&cfg, true, 0).unwrap();
        let addresses: Vec<SocketAddr> =
            endpoints.iter().map(|endpoint| endpoint.addr.0).collect();
        assert_eq!(
            addresses,
            vec![
                "[2001:db8::10]:443".parse().unwrap(),
                "[2001:db8::10]:8443".parse().unwrap(),
                "192.0.2.10:443".parse().unwrap(),
                "192.0.2.10:8443".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn endpoint_selection_supports_legacy_config_and_port_override() {
        let cfg = AppConfig {
            endpoint_v4: "192.0.2.20".to_string(),
            endpoint_v6: "2001:db8::20".to_string(),
            endpoint_pub_key: test_public_key_pem(2),
            ..Default::default()
        };

        let endpoints = select_endpoints_from_config(&cfg, false, 4443).unwrap();
        let addresses: Vec<SocketAddr> =
            endpoints.iter().map(|endpoint| endpoint.addr.0).collect();
        assert_eq!(
            addresses,
            vec![
                "192.0.2.20:4443".parse().unwrap(),
                "[2001:db8::20]:4443".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn endpoint_selection_defaults_to_443_and_removes_duplicate_ports() {
        let cfg = AppConfig {
            masque_peers: vec![
                MasquePeerConfig {
                    endpoint_v4: "192.0.2.30".to_string(),
                    ports: Vec::new(),
                    endpoint_pub_key: test_public_key_pem(3),
                    ..Default::default()
                },
                MasquePeerConfig {
                    endpoint_v4: "192.0.2.40".to_string(),
                    ports: vec![443, 0, 443],
                    endpoint_pub_key: test_public_key_pem(4),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let endpoints = select_endpoints_from_config(&cfg, false, 0).unwrap();
        let addresses: Vec<SocketAddr> =
            endpoints.iter().map(|endpoint| endpoint.addr.0).collect();
        assert_eq!(
            addresses,
            vec![
                "192.0.2.30:443".parse().unwrap(),
                "192.0.2.40:443".parse().unwrap(),
            ]
        );
    }
}
