use crate::models::DeviceIdentity;
use anyhow::{anyhow, Context, Result};
use chrono::Local;
use p256::pkcs8::EncodePublicKey;
use p256::SecretKey;
use rand_core::OsRng;
use ring::digest::{digest, SHA256};
use std::fs;
use std::process::Command;

/// Cloudflare One Client 2026.6 and later uses this orchestration SNI.
/// The registration path is the latest compatible public-client contract
/// known to this project; Cloudflare does not publish that private wire API.
pub const API_URL: &str = "https://api.devices.cloudflare.com";
pub const API_VERSION: &str = "v0a4471";
pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const DEFAULT_MODEL: &str = "FreeBSD";
pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";
pub const DEFAULT_LOCALE: &str = "en_US";

pub fn api_url() -> String {
    std::env::var("USQUE_API_URL").unwrap_or_else(|_| API_URL.to_string())
}

pub fn api_version() -> String {
    std::env::var("USQUE_API_VERSION").unwrap_or_else(|_| API_VERSION.to_string())
}

pub fn client_user_agent() -> String {
    format!(
        "usque-nativetun/{} (FreeBSD; TunnelOnly; MASQUE)",
        env!("CARGO_PKG_VERSION")
    )
}

pub fn detect_device_identity(
    requested_name: &str,
    requested_model: &str,
    locale: &str,
) -> DeviceIdentity {
    let name = non_empty(requested_name).unwrap_or_else(detect_hostname);
    let os_version = detect_os_version();
    let stable_source = detect_hardware_source().unwrap_or_else(|| format!("{name}\0{os_version}"));
    let serial_digest = digest(&SHA256, stable_source.as_bytes());
    let serial_number = hex::encode(&serial_digest.as_ref()[..16]);

    DeviceIdentity {
        name,
        device_type: "FreeBSD".to_string(),
        manufacturer: "FreeBSD Project".to_string(),
        model: non_empty(requested_model).unwrap_or_else(|| DEFAULT_MODEL.to_string()),
        os_version,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        serial_number,
        locale: non_empty(locale).unwrap_or_else(|| DEFAULT_LOCALE.to_string()),
    }
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    non_empty(&String::from_utf8_lossy(&output.stdout))
}

fn detect_hostname() -> String {
    command_output("hostname", &[])
        .or_else(|| std::env::var("HOSTNAME").ok().and_then(|v| non_empty(&v)))
        .or_else(|| {
            std::env::var("COMPUTERNAME")
                .ok()
                .and_then(|v| non_empty(&v))
        })
        .unwrap_or_else(|| "freebsd-device".to_string())
}

fn detect_os_version() -> String {
    command_output("freebsd-version", &["-u"])
        .or_else(|| command_output("uname", &["-K"]))
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

fn detect_hardware_source() -> Option<String> {
    command_output("kenv", &["-q", "smbios.system.uuid"]).or_else(|| {
        fs::read_to_string("/etc/hostid")
            .ok()
            .and_then(|v| non_empty(&v))
    })
}

pub fn time_as_cf_string_now() -> String {
    Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string()
}

pub fn generate_ec_key_pair() -> Result<(Vec<u8>, Vec<u8>)> {
    let secret = SecretKey::random(&mut OsRng);
    let private_der = secret
        .to_sec1_der()
        .context("failed to encode P-256 private key as SEC1 DER")?
        .to_vec();
    let public_der = secret
        .public_key()
        .to_public_key_der()
        .context("failed to encode P-256 public key as SPKI DER")?
        .as_bytes()
        .to_vec();
    Ok((private_der, public_der))
}

pub fn check_ifname(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("interface name cannot be empty"));
    }
    if name.len() >= 16 {
        tracing::warn!("interface name '{name}' is longer than 15 characters");
    }
    if name.chars().any(|c| c > '\u{7f}') {
        tracing::warn!("interface name contains non-ASCII character");
    }
    if name.chars().any(|c| c == '/' || c.is_whitespace()) {
        return Err(anyhow!(
            "interface name contains invalid character: '/' or whitespace"
        ));
    }
    Ok(())
}
