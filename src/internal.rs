use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Local;
use p256::pkcs8::EncodePublicKey;
use p256::SecretKey;
use rand_core::{OsRng, RngCore};

pub const API_URL: &str = "https://api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";
pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const DEFAULT_MODEL: &str = "PC";
pub const KEY_TYPE_WG: &str = "curve25519";
pub const TUN_TYPE_WG: &str = "wireguard";
pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";
pub const DEFAULT_LOCALE: &str = "en_US";

pub const DEFAULT_HEADERS: &[(&str, &str)] = &[
    ("User-Agent", "WARP for Android"),
    ("CF-Client-Version", "a-6.35-4471"),
    ("Content-Type", "application/json; charset=UTF-8"),
    ("Connection", "Keep-Alive"),
];

pub fn generate_random_android_serial() -> String {
    let mut serial = [0u8; 8];
    OsRng.fill_bytes(&mut serial);
    hex::encode(serial)
}

pub fn generate_random_wg_pubkey() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    general_purpose::STANDARD.encode(key)
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
        return Err(anyhow!("interface name contains invalid character: '/' or whitespace"));
    }
    Ok(())
}
