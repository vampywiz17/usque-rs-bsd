use crate::api::cloudflare;
use crate::internal;
use crate::models::{AccountData, ApiError, DeviceIdentity};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
/// Cloudflare's Connector enrollment currently accepts Linux but rejects
/// FreeBSD. Callers must require an explicit operator acknowledgement before
/// using this compatibility value.
pub const CONNECTOR_REGISTRATION_PLATFORM: &str = "linux";

/// Cloudflare calls this resource a WARP Connector in its public management
/// API. The project exposes it as a Mesh node to match the current product UI.
pub struct MeshNodeToken {
    encoded: String,
    account_tag: String,
    tunnel_id: String,
}

impl std::fmt::Debug for MeshNodeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshNodeToken")
            .field("encoded", &"<redacted>")
            .field("account_tag", &self.account_tag)
            .field("tunnel_id", &self.tunnel_id)
            .finish()
    }
}

#[derive(Deserialize)]
struct TokenPayload {
    #[serde(rename = "a", alias = "account_tag")]
    account_tag: String,
    #[serde(rename = "t", alias = "tunnel_id")]
    tunnel_id: String,
    #[serde(rename = "s", alias = "tunnel_secret")]
    tunnel_secret: String,
}

#[derive(Serialize)]
struct MeshRegistration<'a> {
    #[serde(rename = "type")]
    device_type: &'a str,
    model: &'a str,
    name: &'a str,
    key: String,
    key_type: &'static str,
    tunnel_type: &'static str,
    os_version: &'a str,
    serial_number: &'a str,
    warp_connector_token: &'a str,
    tos: String,
}

impl MeshNodeToken {
    pub fn read(path: &Path) -> Result<Self> {
        validate_private_file(path)?;
        let encoded = fs::read_to_string(path)
            .with_context(|| format!("failed to read Mesh node token file {}", path.display()))?;
        Self::parse(encoded.trim())
    }

    fn parse(encoded: &str) -> Result<Self> {
        if encoded.is_empty() {
            return Err(anyhow!("Mesh node token is empty"));
        }
        let decoded = decode_token(encoded).context("Mesh node token is not valid Base64")?;
        let payload: TokenPayload =
            serde_json::from_slice(&decoded).context("Mesh node token is not valid JSON")?;

        if payload.account_tag.len() != 32
            || !payload
                .account_tag
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(anyhow!("Mesh node token contains an invalid account tag"));
        }
        if !is_uuid_like(&payload.tunnel_id) {
            return Err(anyhow!("Mesh node token contains an invalid tunnel ID"));
        }
        let secret = decode_token(&payload.tunnel_secret)
            .context("Mesh node token contains an invalid tunnel secret")?;
        if secret.len() < 32 {
            return Err(anyhow!(
                "Mesh node tunnel secret is shorter than Cloudflare's documented minimum"
            ));
        }

        Ok(Self {
            encoded: encoded.to_string(),
            account_tag: payload.account_tag,
            tunnel_id: payload.tunnel_id,
        })
    }

    pub fn account_tag(&self) -> &str {
        &self.account_tag
    }

    pub fn tunnel_id(&self) -> &str {
        &self.tunnel_id
    }
}

pub async fn register(
    token: &MeshNodeToken,
    identity: &DeviceIdentity,
    public_key_der: &[u8],
) -> Result<AccountData> {
    let payload = MeshRegistration {
        device_type: CONNECTOR_REGISTRATION_PLATFORM,
        model: &identity.model,
        name: &identity.name,
        key: general_purpose::STANDARD.encode(public_key_der),
        key_type: internal::KEY_TYPE_MASQUE,
        tunnel_type: internal::TUN_TYPE_MASQUE,
        os_version: &identity.os_version,
        serial_number: &identity.serial_number,
        warp_connector_token: &token.encoded,
        tos: internal::time_as_cf_string_now(),
    };
    let url = format!(
        "{}/v1/accounts/{}/warp_connector",
        internal::api_url(),
        token.account_tag()
    );
    let response = cloudflare::client_headers(Client::new().post(url))
        .json(&payload)
        .send()
        .await
        .context("failed to send Mesh node registration")?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .context("failed to read Mesh node registration response")?;
    if status != StatusCode::OK {
        let api_error = serde_json::from_slice::<ApiError>(&body).unwrap_or_default();
        return Err(anyhow!(
            "failed to register Mesh node: {status}; API errors: {}",
            api_error.errors_as_string("; ")
        ));
    }
    let account = decode_account_data_response(&body)
        .context("failed to decode Mesh node registration response")?;
    if account.id.is_empty() || account.token.is_empty() {
        return Err(anyhow!(
            "Mesh node registration response omitted the registration ID or access token"
        ));
    }
    Ok(account)
}

/// Fetch the tunnel configuration created by Connector registration.
///
/// Connector registration is account-scoped and does not use the legacy
/// client key-enrollment PATCH route. The official client requests the
/// resulting registration config from this v1 account path.
pub async fn get_registration_config(
    account_tag: &str,
    registration_id: &str,
    access_token: &str,
) -> Result<AccountData> {
    let registration_id = normalize_registration_id(registration_id);
    let url = format!(
        "{}/v1/accounts/{}/reg/{}",
        internal::api_url(),
        account_tag,
        registration_id
    );
    let response = cloudflare::client_headers(Client::new().get(url))
        .bearer_auth(access_token)
        .query(&[("dex_tests_version", "1")])
        .send()
        .await
        .context("failed to fetch Mesh node registration config")?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .context("failed to read Mesh node registration config response")?;
    if status != StatusCode::OK {
        let api_error = serde_json::from_slice::<ApiError>(&body).unwrap_or_default();
        return Err(anyhow!(
            "failed to fetch Mesh node registration config: {status}; API errors: {}",
            api_error.errors_as_string("; ")
        ));
    }
    decode_account_data_response(&body)
        .context("failed to decode Mesh node registration config response")
}

fn decode_account_data_response(body: &[u8]) -> Result<AccountData> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("response was not valid JSON")?;
    let payload = match value {
        serde_json::Value::Object(mut object) => {
            if let Some(result) = object.remove("result") {
                result
            } else {
                serde_json::Value::Object(object)
            }
        }
        other => other,
    };
    serde_json::from_value(payload).context("response payload was not registration data")
}

fn normalize_registration_id(value: &str) -> &str {
    value.strip_prefix("t.").unwrap_or(value)
}

fn decode_token(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| general_purpose::URL_SAFE.decode(value))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
}

fn is_uuid_like(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn validate_private_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect Mesh node token file {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "Mesh node token path is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(anyhow!(
                "Mesh node token file must not be accessible by group or others (use chmod 600 {})",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn encoded_token(payload: serde_json::Value) -> String {
        general_purpose::STANDARD.encode(serde_json::to_vec(&payload).unwrap())
    }

    #[test]
    fn parses_current_compact_cloudflare_token() {
        let secret = general_purpose::STANDARD.encode([7_u8; 32]);
        let token = encoded_token(serde_json::json!({
            "a": "0123456789abcdef0123456789abcdef",
            "t": "12345678-1234-1234-1234-123456789abc",
            "s": secret,
        }));
        let parsed = MeshNodeToken::parse(&token).unwrap();
        assert_eq!(parsed.account_tag(), "0123456789abcdef0123456789abcdef");
        assert_eq!(parsed.tunnel_id(), "12345678-1234-1234-1234-123456789abc");
        assert!(!format!("{parsed:?}").contains(&token));
        assert!(format!("{parsed:?}").contains("<redacted>"));
    }

    #[test]
    fn accepts_descriptive_token_field_aliases() {
        let secret = general_purpose::URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let token = general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "account_tag": "fedcba9876543210fedcba9876543210",
                "tunnel_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "tunnel_secret": secret,
            }))
            .unwrap(),
        );
        assert!(MeshNodeToken::parse(&token).is_ok());
    }

    #[test]
    fn rejects_short_secret_and_malformed_identifiers() {
        let token = encoded_token(serde_json::json!({
            "a": "not-an-account",
            "t": "not-a-uuid",
            "s": general_purpose::STANDARD.encode([1_u8; 8]),
        }));
        assert!(MeshNodeToken::parse(&token).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_overly_permissive_token_file() {
        use std::os::unix::fs::PermissionsExt;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "secret").unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o644)).unwrap();
        let error = MeshNodeToken::read(file.path()).unwrap_err().to_string();
        assert!(error.contains("chmod 600"));
    }

    #[test]
    fn registration_payload_has_minimal_connector_shape_and_disclosed_platform() {
        let payload = MeshRegistration {
            device_type: CONNECTOR_REGISTRATION_PLATFORM,
            model: CONNECTOR_REGISTRATION_PLATFORM,
            name: "mesh-test",
            key: "public-key".to_string(),
            key_type: internal::KEY_TYPE_MASQUE,
            tunnel_type: internal::TUN_TYPE_MASQUE,
            os_version: "15.0",
            serial_number: "stable-test-serial",
            warp_connector_token: "<redacted-test-token>",
            tos: "2026-07-25T00:00:00Z".to_string(),
        };
        let value = serde_json::to_value(payload).unwrap();
        assert_eq!(value["type"], "linux");
        assert_eq!(value["model"], "linux");
        assert_eq!(value["os_version"], "15.0");
        assert_eq!(value["key_type"], internal::KEY_TYPE_MASQUE);
        assert_eq!(value["tunnel_type"], internal::TUN_TYPE_MASQUE);
        assert!(value.get("manufacturer").is_none());
        assert!(value.get("locale").is_none());
        assert!(value.get("install_id").is_none());
        assert!(value.get("fcm_token").is_none());
        assert_eq!(value.as_object().unwrap().len(), 10);
    }

    #[test]
    fn account_scoped_config_path_uses_bare_registration_uuid() {
        let uuid = "12345678-1234-1234-1234-123456789abc";
        assert_eq!(normalize_registration_id(uuid), uuid);
        assert_eq!(normalize_registration_id(&format!("t.{uuid}")), uuid);
    }

    #[test]
    fn decodes_direct_and_cloudflare_enveloped_registration_responses() {
        let direct = serde_json::json!({
            "id": "t.12345678-1234-1234-1234-123456789abc",
            "token": "access-token"
        });
        let enveloped = serde_json::json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": direct.clone()
        });
        let direct_decoded =
            decode_account_data_response(&serde_json::to_vec(&direct).unwrap()).unwrap();
        let envelope_decoded =
            decode_account_data_response(&serde_json::to_vec(&enveloped).unwrap()).unwrap();
        assert_eq!(direct_decoded.id, envelope_decoded.id);
        assert_eq!(direct_decoded.token, "access-token");
        assert_eq!(envelope_decoded.token, "access-token");
    }
}
