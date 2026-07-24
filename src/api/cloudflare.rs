use crate::internal;
use crate::models::{AccountData, ApiError, DeviceIdentity, DeviceUpdate, Registration};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use reqwest::{Client, RequestBuilder, StatusCode};

pub async fn register(
    identity: &DeviceIdentity,
    public_key_der: &[u8],
    jwt: Option<&str>,
    accept_tos: bool,
) -> Result<AccountData> {
    if !accept_tos {
        println!("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ");
        let mut response = String::new();
        std::io::stdin()
            .read_line(&mut response)
            .context("failed to read user input")?;
        if response.trim() != "y" {
            return Err(anyhow!("user did not accept TOS"));
        }
    }

    let data = Registration {
        key: general_purpose::STANDARD.encode(public_key_der),
        install_id: String::new(),
        fcm_token: String::new(),
        tos: internal::time_as_cf_string_now(),
        model: identity.model.clone(),
        serial_number: identity.serial_number.clone(),
        os_version: identity.os_version.clone(),
        key_type: internal::KEY_TYPE_MASQUE.to_string(),
        tunnel_type: internal::TUN_TYPE_MASQUE.to_string(),
        locale: identity.locale.clone(),
        device_type: identity.device_type.clone(),
        name: identity.name.clone(),
        manufacturer: identity.manufacturer.clone(),
    };

    let client = Client::new();
    let url = format!("{}/{}/reg", internal::api_url(), internal::api_version());
    let mut req = client_headers(client.post(url)).json(&data);
    if let Some(jwt) = jwt.filter(|s| !s.is_empty()) {
        req = req.header("CF-Access-Jwt-Assertion", jwt);
    }

    let resp = req
        .send()
        .await
        .context("failed to send register request")?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("failed to register: {}", resp.status()));
    }
    resp.json::<AccountData>()
        .await
        .context("failed to decode register response")
}

pub async fn enroll_key(
    account_data: &AccountData,
    public_key_der: &[u8],
    identity: &DeviceIdentity,
) -> std::result::Result<AccountData, EnrollFailure> {
    let update = DeviceUpdate {
        key: general_purpose::STANDARD.encode(public_key_der),
        key_type: internal::KEY_TYPE_MASQUE.to_string(),
        tunnel_type: internal::TUN_TYPE_MASQUE.to_string(),
        name: Some(identity.name.clone()),
        model: identity.model.clone(),
        serial_number: identity.serial_number.clone(),
        os_version: identity.os_version.clone(),
        locale: identity.locale.clone(),
        device_type: identity.device_type.clone(),
        manufacturer: identity.manufacturer.clone(),
    };

    let client = Client::new();
    let url = format!(
        "{}/{}/reg/{}",
        internal::api_url(),
        internal::api_version(),
        account_data.id
    );
    let mut req = client_headers(client.patch(url)).json(&update);
    req = req.header("Authorization", format!("Bearer {}", account_data.token));

    let resp = req
        .send()
        .await
        .map_err(|e| EnrollFailure::Transport(anyhow!("failed to send enroll request: {e}")))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| EnrollFailure::Transport(anyhow!("failed to read enroll response: {e}")))?;

    if status != StatusCode::OK {
        let api_err = serde_json::from_slice::<ApiError>(&body).unwrap_or_default();
        return Err(EnrollFailure::Api {
            status,
            api_error: api_err,
        });
    }

    serde_json::from_slice::<AccountData>(&body)
        .map_err(|e| EnrollFailure::Transport(anyhow!("failed to decode enroll response: {e}")))
}

/// Fetch the current registration and device policy through Cloudflare's
/// orchestration connection. This HTTPS request intentionally remains
/// independent from the MASQUE data plane.
pub async fn get_registration(registration_id: &str, access_token: &str) -> Result<AccountData> {
    let client = Client::new();
    let url = format!(
        "{}/{}/reg/{}",
        internal::api_url(),
        internal::api_version(),
        registration_id
    );
    let resp = client_headers(client.get(url))
        .bearer_auth(access_token)
        .send()
        .await
        .context("failed to fetch device registration")?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .context("failed to read device registration response")?;

    if status != StatusCode::OK {
        let api_err = serde_json::from_slice::<ApiError>(&body).unwrap_or_default();
        return Err(anyhow!(
            "failed to fetch device registration: {status}; API errors: {}",
            api_err.errors_as_string("; ")
        ));
    }

    serde_json::from_slice::<AccountData>(&body)
        .context("failed to decode device registration response")
}

pub(crate) fn client_headers(req: RequestBuilder) -> RequestBuilder {
    req.header("User-Agent", internal::client_user_agent())
        .header("CF-Client-Version", env!("CARGO_PKG_VERSION"))
        .header("Content-Type", "application/json; charset=UTF-8")
}

#[derive(Debug)]
pub enum EnrollFailure {
    Api {
        status: StatusCode,
        api_error: ApiError,
    },
    Transport(anyhow::Error),
}

impl std::fmt::Display for EnrollFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollFailure::Api { status, api_error } => write!(
                f,
                "failed to update: {status}; API errors: {}",
                api_error.errors_as_string("; ")
            ),
            EnrollFailure::Transport(err) => write!(f, "{err:#}"),
        }
    }
}

impl std::error::Error for EnrollFailure {}
