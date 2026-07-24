use serde::{Deserialize, Serialize};

pub const INVALID_PUBLIC_KEY: &str = "Invalid public key";

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub name: String,
    pub device_type: String,
    pub manufacturer: String,
    pub model: String,
    pub os_version: String,
    pub client_version: String,
    pub serial_number: String,
    pub locale: String,
}

#[derive(Debug, Serialize)]
pub struct Registration {
    pub key: String,
    pub install_id: String,
    pub fcm_token: String,
    pub tos: String,
    pub model: String,
    pub serial_number: String,
    pub os_version: String,
    pub key_type: String,
    pub tunnel_type: String,
    pub locale: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub name: String,
    pub manufacturer: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceUpdate {
    pub key: String,
    pub key_type: String,
    pub tunnel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub model: String,
    pub serial_number: String,
    pub os_version: String,
    pub locale: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub manufacturer: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ApiError {
    #[serde(default)]
    pub result: serde_json::Value,
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub errors: Vec<ErrorInfo>,
    #[serde(default)]
    pub messages: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ErrorInfo {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

impl ApiError {
    pub fn errors_as_string(&self, separator: &str) -> String {
        self.errors
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join(separator)
    }

    pub fn has_error_message(&self, message: &str) -> bool {
        self.errors.iter().any(|e| e.message == message)
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AccountData {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "type")]
    pub account_data_type: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub key_type: String,
    #[serde(default, rename = "tunnel_type")]
    pub tun_type: String,
    #[serde(default)]
    pub account: Account,
    #[serde(default)]
    pub config: AccountConfig,
    #[serde(default)]
    pub warp_enabled: bool,
    #[serde(default)]
    pub waitlist_enabled: bool,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub tos: String,
    #[serde(default)]
    pub place: i64,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub install_id: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub fcm_token: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Account {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub account_type: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub managed: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub premium_data: i64,
    #[serde(default)]
    pub quota: i64,
    #[serde(default)]
    pub warp_plus: bool,
    #[serde(default)]
    pub referral_count: i64,
    #[serde(default)]
    pub referral_renewal_countdown: i64,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub license: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AccountConfig {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub interface: Interface,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Interface {
    #[serde(default)]
    pub addresses: Addresses,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Addresses {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Peer {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Endpoint,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Endpoint {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Policy {
    #[serde(default)]
    pub tunnel_protocol: String,
}
