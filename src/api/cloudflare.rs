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
        .header("CF-Client-Version", internal::CLIENT_VERSION)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DeviceIdentity;
    use serde_json::Value;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    static API_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct ApiUrlGuard(Option<OsString>);

    impl ApiUrlGuard {
        fn set(url: &str) -> Self {
            let previous = std::env::var_os("USQUE_API_URL");
            std::env::set_var("USQUE_API_URL", url);
            Self(previous)
        }
    }

    impl Drop for ApiUrlGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                std::env::set_var("USQUE_API_URL", previous);
            } else {
                std::env::remove_var("USQUE_API_URL");
            }
        }
    }

    fn request_is_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
            return false;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        request.len() >= header_end + content_length
    }

    fn serve_once(
        status: &'static str,
        body: &'static str,
    ) -> (String, mpsc::Receiver<Vec<u8>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !request_is_complete(&request) {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            request_tx.send(request).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        });
        (format!("http://{address}"), request_rx, handle)
    }

    fn request_parts(request: &[u8]) -> (String, Value) {
        let request = String::from_utf8(request.to_vec()).unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(body).unwrap()
        };
        (headers.to_ascii_lowercase(), body)
    }

    fn identity() -> DeviceIdentity {
        DeviceIdentity {
            name: "freebsd-test".into(),
            device_type: "FreeBSD".into(),
            manufacturer: "FreeBSD Project".into(),
            model: "FreeBSD".into(),
            os_version: "15.0".into(),
            client_version: internal::CLIENT_VERSION.into(),
            serial_number: "stable-serial".into(),
            locale: "en_US".into(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registration_requests_preserve_the_cloudflare_wire_contract() {
        let _lock = API_ENV_LOCK.lock().await;
        let public_key = [7_u8; 65];

        let (url, requests, server) =
            serve_once("200 OK", r#"{"id":"t.registration","token":"access"}"#);
        let _url = ApiUrlGuard::set(&url);
        let registered = register(&identity(), &public_key, Some("jwt-value"), true)
            .await
            .unwrap();
        assert_eq!(registered.id, "t.registration");
        let (headers, body) = request_parts(&requests.recv().unwrap());
        server.join().unwrap();
        assert!(headers.starts_with("post /v0a4471/reg http/1.1"));
        assert!(headers.contains("cf-access-jwt-assertion: jwt-value"));
        assert!(headers.contains("content-type: application/json; charset=utf-8"));
        assert_eq!(body["type"], "FreeBSD");
        assert_eq!(body["key_type"], internal::KEY_TYPE_MASQUE);
        assert_eq!(body["tunnel_type"], internal::TUN_TYPE_MASQUE);
        assert_eq!(body["key"], general_purpose::STANDARD.encode(public_key));

        let account = AccountData {
            id: "t.registration".into(),
            token: "access".into(),
            ..Default::default()
        };
        let (url, requests, server) =
            serve_once("200 OK", r#"{"id":"t.registration","token":"renewed"}"#);
        let _url = ApiUrlGuard::set(&url);
        let enrolled = enroll_key(&account, &public_key, &identity())
            .await
            .unwrap();
        assert_eq!(enrolled.token, "renewed");
        let (headers, body) = request_parts(&requests.recv().unwrap());
        server.join().unwrap();
        assert!(headers.starts_with("patch /v0a4471/reg/t.registration http/1.1"));
        assert!(headers.contains("authorization: bearer access"));
        assert_eq!(body["name"], "freebsd-test");
        assert_eq!(body["manufacturer"], "FreeBSD Project");

        let (url, requests, server) = serve_once(
            "403 Forbidden",
            r#"{"errors":[{"message":"enrollment denied"}]}"#,
        );
        let _url = ApiUrlGuard::set(&url);
        let error = enroll_key(&account, &public_key, &identity())
            .await
            .unwrap_err();
        requests.recv().unwrap();
        server.join().unwrap();
        match error {
            EnrollFailure::Api { status, api_error } => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(api_error.has_error_message("enrollment denied"));
            }
            EnrollFailure::Transport(error) => panic!("unexpected transport error: {error:#}"),
        }

        let (url, requests, server) =
            serve_once("200 OK", r#"{"id":"t.registration","token":"current"}"#);
        let _url = ApiUrlGuard::set(&url);
        let fetched = get_registration("t.registration", "access").await.unwrap();
        assert_eq!(fetched.token, "current");
        let (headers, _) = request_parts(&requests.recv().unwrap());
        server.join().unwrap();
        assert!(headers.starts_with("get /v0a4471/reg/t.registration http/1.1"));
        assert!(headers.contains("authorization: bearer access"));

        let (url, requests, server) = serve_once(
            "401 Unauthorized",
            r#"{"errors":[{"message":"expired token"}]}"#,
        );
        let _url = ApiUrlGuard::set(&url);
        let error = get_registration("t.registration", "expired")
            .await
            .unwrap_err()
            .to_string();
        requests.recv().unwrap();
        server.join().unwrap();
        assert!(error.contains("401 Unauthorized"));
        assert!(error.contains("expired token"));
    }
}
