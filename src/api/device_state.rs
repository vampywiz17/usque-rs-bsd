use crate::api::cloudflare;
use crate::config::AppConfig;
use crate::internal;
use anyhow::{anyhow, Context, Result};
use chrono::{SecondsFormat, Utc};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

const DEVICE_STATE_API_VERSION: &str = "v0";
const REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Handle for Cloudflare's HTTPS device-orchestration reporter.
///
/// The reporter is deliberately separate from the QUIC/MASQUE data plane.
/// Cloudflare's native client architecture uses an out-of-tunnel HTTPS
/// orchestration connection for device state, while quiche remains
/// responsible only for the standards-compliant QUIC tunnel.
#[derive(Clone)]
pub struct DeviceStateReporter {
    state_tx: watch::Sender<ConnectionState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    Disconnected,
    Connected { handshake_latency_ms: u64 },
}

#[derive(Clone)]
struct ReporterConfig {
    account_id: String,
    registration_id: String,
    access_token: String,
    doh_subdomain: String,
    profile_id: String,
    switch_locked: bool,
    always_on: bool,
    client_version: String,
}

#[derive(Serialize)]
struct DeviceStatePayload<'a> {
    timestamp: String,
    account_id: &'a str,
    status: &'static str,
    mode: &'static str,
    always_on: bool,
    reg_id: &'a str,
    doh_subdomain: &'a str,
    switch_locked: bool,
    client_version: &'a str,
    client_platform: &'static str,
    warp_metal: &'static str,
    warp_colo: &'static str,
    handshake_latency_ms: Option<u64>,
    estimated_loss: Option<f32>,
    tunnel_type: &'static str,
    interfaces: Vec<InterfaceInfo>,
    firewalls: BTreeMap<String, bool>,
    cpu_pct: f32,
    cpu_pct_by_app: Vec<AppCpuUsage>,
    ram_used_pct: f32,
    ram_used_pct_by_app: Vec<AppRamUsage>,
    ram_available_kb: u64,
    disk_usage_pct: f32,
    disk_read_bps: u64,
    disk_write_bps: u64,
    profile_id: &'a str,
}

#[derive(Serialize)]
struct InterfaceInfo {}

#[derive(Serialize)]
struct AppCpuUsage {}

#[derive(Serialize)]
struct AppRamUsage {}

impl DeviceStateReporter {
    pub async fn start(app_cfg: &AppConfig, always_on: bool) -> Result<Self> {
        let registration = cloudflare::get_registration(&app_cfg.id, &app_cfg.access_token).await?;
        let account_id = registration.account.id.trim().to_string();
        if account_id.is_empty() {
            return Err(anyhow!(
                "Cloudflare registration did not contain an account ID"
            ));
        }

        let registration_id = normalize_registration_id(&registration.id);
        if registration_id.is_empty() {
            return Err(anyhow!(
                "Cloudflare registration did not contain a registration ID"
            ));
        }

        let profile_id = if registration.policy.policy_id.trim().is_empty() {
            "default".to_string()
        } else {
            registration.policy.policy_id
        };
        let client_version = if app_cfg.device_identity.client_version.trim().is_empty() {
            env!("CARGO_PKG_VERSION").to_string()
        } else {
            app_cfg.device_identity.client_version.clone()
        };
        let cfg = ReporterConfig {
            doh_subdomain: format!("{account_id}.cloudflare-gateway.com"),
            account_id,
            registration_id,
            access_token: app_cfg.access_token.clone(),
            profile_id,
            switch_locked: registration.policy.switch_locked,
            always_on,
            client_version,
        };

        let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);
        tokio::spawn(run_reporter(cfg, state_rx));
        Ok(Self { state_tx })
    }

    pub fn connected(&self, handshake_latency: Duration) {
        let latency_ms = handshake_latency.as_millis().min(u128::from(u64::MAX)) as u64;
        self.state_tx.send_replace(ConnectionState::Connected {
            handshake_latency_ms: latency_ms,
        });
    }

    pub fn disconnected(&self) {
        self.state_tx.send_replace(ConnectionState::Disconnected);
    }
}

async fn run_reporter(cfg: ReporterConfig, mut state_rx: watch::Receiver<ConnectionState>) {
    let client = Client::new();
    let mut interval = tokio::time::interval(REPORT_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let state = *state_rx.borrow();
                report_current_state(&client, &cfg, state).await;
            }
            changed = state_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let state = *state_rx.borrow_and_update();
                report_current_state(&client, &cfg, state).await;
            }
        }
    }
}

async fn report_current_state(client: &Client, cfg: &ReporterConfig, state: ConnectionState) {
    if let Err(err) = send_device_state(client, cfg, state).await {
        // Device monitoring must never become a tunnel liveness dependency.
        tracing::warn!("failed to report Cloudflare device state: {err:#}");
    }
}

async fn send_device_state(
    client: &Client,
    cfg: &ReporterConfig,
    state: ConnectionState,
) -> Result<()> {
    let payload = build_payload(cfg, state);
    let url = format!(
        "{}/{}/accounts/{}/reg/{}/devicestate",
        internal::api_url(),
        DEVICE_STATE_API_VERSION,
        cfg.account_id,
        cfg.registration_id
    );
    let response = cloudflare::client_headers(client.post(url))
        .bearer_auth(&cfg.access_token)
        .json(&payload)
        .send()
        .await
        .context("device-state request failed")?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .context("failed to read device-state response")?;

    if status != StatusCode::OK {
        let detail = String::from_utf8_lossy(&body);
        return Err(anyhow!(
            "device-state API returned {status}: {}",
            detail.chars().take(512).collect::<String>()
        ));
    }

    tracing::debug!(
        status = payload.status,
        mode = payload.mode,
        tunnel_type = payload.tunnel_type,
        "reported Cloudflare device state"
    );
    Ok(())
}

fn build_payload(cfg: &ReporterConfig, state: ConnectionState) -> DeviceStatePayload<'_> {
    let (status, handshake_latency_ms, estimated_loss) = match state {
        ConnectionState::Disconnected => ("Disconnected", None, None),
        ConnectionState::Connected {
            handshake_latency_ms,
        } => ("Connected", Some(handshake_latency_ms), Some(0.0)),
    };

    DeviceStatePayload {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true),
        account_id: &cfg.account_id,
        status,
        mode: "tunnel_only",
        always_on: cfg.always_on,
        reg_id: &cfg.registration_id,
        doh_subdomain: &cfg.doh_subdomain,
        switch_locked: cfg.switch_locked,
        client_version: &cfg.client_version,
        client_platform: "freebsd",
        warp_metal: "none",
        warp_colo: "none",
        handshake_latency_ms,
        estimated_loss,
        tunnel_type: "masque",
        interfaces: Vec::new(),
        firewalls: BTreeMap::new(),
        // These fields are part of Cloudflare's current base device-state
        // contract. Hardware telemetry collection is intentionally deferred;
        // zero means no sample has been collected by this tunnel-only port.
        cpu_pct: 0.0,
        cpu_pct_by_app: Vec::new(),
        ram_used_pct: 0.0,
        ram_used_pct_by_app: Vec::new(),
        ram_available_kb: 0,
        disk_usage_pct: 0.0,
        disk_read_bps: 0,
        disk_write_bps: 0,
        profile_id: &cfg.profile_id,
    }
}

fn normalize_registration_id(value: &str) -> String {
    value
        .trim()
        .strip_prefix("t.")
        .unwrap_or(value.trim())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ReporterConfig {
        ReporterConfig {
            account_id: "account".into(),
            registration_id: "registration".into(),
            access_token: "secret".into(),
            doh_subdomain: "account.cloudflare-gateway.com".into(),
            profile_id: "default".into(),
            switch_locked: false,
            always_on: true,
            client_version: "0.7.0".into(),
        }
    }

    #[test]
    fn strips_teams_registration_prefix() {
        assert_eq!(
            normalize_registration_id("t.019f90ca-b0ed-15df-bf78-9812f557cd08"),
            "019f90ca-b0ed-15df-bf78-9812f557cd08"
        );
    }

    #[test]
    fn payload_uses_cloudflare_device_state_wire_names() {
        let cfg = test_config();
        let value = serde_json::to_value(build_payload(
            &cfg,
            ConnectionState::Connected {
                handshake_latency_ms: 42,
            },
        ))
        .unwrap();

        assert_eq!(value["status"], "Connected");
        assert_eq!(value["mode"], "tunnel_only");
        assert_eq!(value["tunnel_type"], "masque");
        assert_eq!(value["client_platform"], "freebsd");
        assert_eq!(value["handshake_latency_ms"], 42);
        assert!(value.get("system_info").is_none());
        assert!(value["firewalls"].is_object());
    }
}
