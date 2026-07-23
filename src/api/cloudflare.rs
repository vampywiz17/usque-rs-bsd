use crate::internal;
use crate::models::{AccountData, ApiError, DeviceUpdate, Registration};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use reqwest::{Client, StatusCode};

pub async fn register(model: &str, locale: &str, jwt: Option<&str>, accept_tos: bool) -> Result<AccountData> {
    if !accept_tos {
        println!("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ");
        let mut response = String::new();
        std::io::stdin().read_line(&mut response).context("failed to read user input")?;
        if response.trim() != "y" {
            return Err(anyhow!("user did not accept TOS"));
        }
    }

    let data = Registration {
        key: internal::generate_random_wg_pubkey(),
        install_id: String::new(),
        fcm_token: String::new(),
        tos: internal::time_as_cf_string_now(),
        model: model.to_string(),
        serial_number: internal::generate_random_android_serial(),
        os_version: String::new(),
        key_type: internal::KEY_TYPE_WG.to_string(),
        tunnel_type: internal::TUN_TYPE_WG.to_string(),
        locale: locale.to_string(),
    };

    let client = Client::new();
    let url = format!("{}/{}/reg", internal::API_URL, internal::API_VERSION);
    let mut req = client.post(url).json(&data);
    for &(k, v) in internal::DEFAULT_HEADERS {
        req = req.header(k, v);
    }
    if let Some(jwt) = jwt.filter(|s| !s.is_empty()) {
        req = req.header("CF-Access-Jwt-Assertion", jwt);
    }

    let resp = req.send().await.context("failed to send register request")?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("failed to register: {}", resp.status()));
    }
    resp.json::<AccountData>().await.context("failed to decode register response")
}

pub async fn enroll_key(account_data: &AccountData, public_key_der: &[u8], device_name: Option<&str>) -> std::result::Result<AccountData, EnrollFailure> {
    let update = DeviceUpdate {
        key: general_purpose::STANDARD.encode(public_key_der),
        key_type: internal::KEY_TYPE_MASQUE.to_string(),
        tunnel_type: internal::TUN_TYPE_MASQUE.to_string(),
        name: device_name.filter(|s| !s.is_empty()).map(|s| s.to_string()),
    };

    let client = Client::new();
    let url = format!("{}/{}/reg/{}", internal::API_URL, internal::API_VERSION, account_data.id);
    let mut req = client.patch(url).json(&update);
    for &(k, v) in internal::DEFAULT_HEADERS {
        req = req.header(k, v);
    }
    req = req.header("Authorization", format!("Bearer {}", account_data.token));

    let resp = req.send().await.map_err(|e| EnrollFailure::Transport(anyhow!("failed to send enroll request: {e}")))?;
    let status = resp.status();
    let body = resp.bytes().await.map_err(|e| EnrollFailure::Transport(anyhow!("failed to read enroll response: {e}")))?;

    if status != StatusCode::OK {
        let api_err = serde_json::from_slice::<ApiError>(&body).unwrap_or_default();
        return Err(EnrollFailure::Api { status, api_error: api_err });
    }

    serde_json::from_slice::<AccountData>(&body)
        .map_err(|e| EnrollFailure::Transport(anyhow!("failed to decode enroll response: {e}")))
}

#[derive(Debug)]
pub enum EnrollFailure {
    Api { status: StatusCode, api_error: ApiError },
    Transport(anyhow::Error),
}

impl std::fmt::Display for EnrollFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollFailure::Api { status, api_error } => write!(f, "failed to update: {status}; API errors: {}", api_error.errors_as_string("; ")),
            EnrollFailure::Transport(err) => write!(f, "{err:#}"),
        }
    }
}

impl std::error::Error for EnrollFailure {}
