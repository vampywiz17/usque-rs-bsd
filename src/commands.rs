use crate::api::cloudflare::{self, EnrollFailure};
use crate::api::masque::{maintain_native_tun, MasqueConfig};
use crate::api::tunnel::TunnelDevice;
use crate::config::{self, AppConfig};
use crate::internal;
use crate::models::{AccountData, INVALID_PUBLIC_KEY};
use crate::native_tun::{TunOptions, TunRsDevice};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Args, Parser, Subcommand};
use p256::pkcs8::EncodePublicKey;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "usque-nativetun")]
#[command(about = "Native-TUN-only Rust port of usque using tun-rs")]
pub struct Cli {
    #[arg(short, long, default_value = "config.json", global = true)]
    pub config: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Register a new client and enroll a MASQUE device key.
    /// Kept because it creates the config required by nativetun.
    Register(RegisterArgs),
    /// Enroll or regenerate the MASQUE private key used by nativetun.
    Enroll(EnrollArgs),
    /// Expose WARP as a native TUN device using tun-rs.
    #[command(name = "nativetun")]
    NativeTun(NativeTunArgs),
    /// Print version information.
    Version,
}

#[derive(Debug, Args)]
pub struct RegisterArgs {
    #[arg(short, long, default_value = internal::DEFAULT_LOCALE)]
    pub locale: String,
    #[arg(short, long, default_value = internal::DEFAULT_MODEL)]
    pub model: String,
    #[arg(short, long, default_value = "")]
    pub name: String,
    #[arg(long, default_value = "")]
    pub jwt: String,
    #[arg(short = 'a', long)]
    pub accept_tos: bool,
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    #[arg(short, long, default_value = "")]
    pub name: String,
    #[arg(short = 'r', long)]
    pub regen_key: bool,
}

#[derive(Debug, Args)]
pub struct NativeTunArgs {
    #[arg(short = 'P', long, default_value_t = 443)]
    pub connect_port: u16,
    #[arg(short = '6', long)]
    pub ipv6: bool,
    #[arg(short = 'F', long)]
    pub no_tunnel_ipv4: bool,
    #[arg(short = 'S', long)]
    pub no_tunnel_ipv6: bool,
    #[arg(short = 's', long, default_value = internal::CONNECT_SNI)]
    pub sni_address: String,
    /// Send an RFC 9000 QUIC PING after this much network inactivity.
    /// Use 0s to disable keepalive.
    #[arg(short = 'k', long, default_value = "25s", value_parser = parse_duration)]
    pub keepalive_period: Duration,
    #[arg(short = 'm', long, default_value_t = 1200)]
    pub mtu: u16,
    /// Maximum UDP payload size for QUIC packets. Default 1250 was selected from FreeBSD upload tests for lower loss/jitter.
    #[arg(long, default_value_t = 1250)]
    pub initial_packet_size: u16,
    /// QUIC congestion-control algorithm. Try: cubic, reno, bbr2_gcongestion.
    #[arg(long, default_value = "cubic")]
    pub cc: String,
    /// Initial QUIC congestion window in packets. Default quiche value is 10.
    #[arg(long, default_value_t = 10)]
    pub initial_cwnd_packets: usize,
    /// Disable quiche's internal pacing decisions. Useful on FreeBSD where SO_TXTIME is unavailable and userspace sleep pacing performed poorly.
    #[arg(long)]
    pub disable_quic_pacing: bool,
    /// Enable quiche relaxed loss detection for spurious loss. Experimental.
    #[arg(long)]
    pub relaxed_loss: bool,
    /// quiche send-capacity factor. 1.0 is the library default. Values above 1 can increase throughput but may increase loss.
    #[arg(long, default_value_t = 1.0)]
    pub send_capacity_factor: f64,
    /// Optional maximum pacing rate in bits per second. 0 means no explicit limit.
    #[arg(long, default_value_t = 0)]
    pub max_pacing_rate_bps: u64,
    /// UDP socket receive/send buffer requested from the OS, in bytes.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub udp_socket_buffer: usize,
    /// Number of already-encoded MASQUE DATAGRAMs kept in the userspace TX queue.
    #[arg(long, default_value_t = 8192)]
    pub tx_queue_len: usize,
    /// Maximum number of TX DATAGRAMs queued into quiche before a flush.
    /// FreeBSD tests showed 256 is a better default than 128 for upload throughput.
    #[arg(long, default_value_t = 256)]
    pub tx_burst_packets: usize,
    /// Do not set up IP addresses and do not set the link up.
    #[arg(short = 'I', long)]
    pub no_iproute2: bool,
    #[arg(short = 'r', long, default_value = "1s", value_parser = parse_duration)]
    pub reconnect_delay: Duration,
    #[arg(long)]
    pub always_reconnect: bool,
    #[arg(long)]
    pub insecure: bool,
    #[arg(short = 'n', long, default_value = "")]
    pub interface_name: String,
    #[arg(long)]
    pub persist: bool,
    #[arg(long, default_value = "")]
    pub on_connect: String,
    #[arg(long, default_value = "")]
    pub on_disconnect: String,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Register(args) => register(&cli.config, args).await,
        Commands::Enroll(args) => enroll(&cli.config, args).await,
        Commands::NativeTun(args) => native_tun(&cli.config, args).await,
        Commands::Version => {
            println!("usque-nativetun version: {}", env!("CARGO_PKG_VERSION"));
            println!("Mode: native TUN only");
            Ok(())
        }
    }
}

async fn register(config_path: &str, args: RegisterArgs) -> Result<()> {
    if Path::new(config_path).exists() {
        println!("You already have a config. Do you want to overwrite it? (y/n) ");
        let mut response = String::new();
        std::io::stdin().read_line(&mut response).context("failed to read response")?;
        if response.trim() != "y" {
            return Ok(());
        }
    }

    if args.jwt.is_empty() {
        tracing::info!("Registering with locale {} and model {}", args.locale, args.model);
    } else {
        tracing::info!("Registering with locale {} and model {} using jwt authentication", args.locale, args.model);
    }

    let account = cloudflare::register(
        &args.model,
        &args.locale,
        if args.jwt.is_empty() { None } else { Some(args.jwt.as_str()) },
        args.accept_tos,
    )
    .await?;

    let (private_key_der, public_key_der) = internal::generate_ec_key_pair()?;
    tracing::info!("Enrolling device key...");
    let updated = enroll_or_fail(&account, &public_key_der, args.name.as_str()).await?;

    let app_cfg = build_app_config(&updated, &private_key_der, &account.token)?;
    app_cfg.save(config_path)?;
    tracing::info!("Config saved to {config_path}");
    Ok(())
}

async fn enroll(config_path: &str, args: EnrollArgs) -> Result<()> {
    let mut cfg = AppConfig::load(config_path)?;
    let account = AccountData { id: cfg.id.clone(), token: cfg.access_token.clone(), ..Default::default() };

    let (mut private_key_der, mut public_key_der): (Vec<u8>, Vec<u8>) = if args.regen_key {
        tracing::info!("Regenerating key pair...");
        internal::generate_ec_key_pair()?
    } else {
        let secret = cfg.get_ec_private_key()?;
        let private_der = secret.to_sec1_der()?.to_vec();
        let public_der = secret.public_key().to_public_key_der()?.as_bytes().to_vec();
        (private_der, public_der)
    };

    tracing::info!("Enrolling device key...");
    let updated = match cloudflare::enroll_key(&account, &public_key_der, Some(args.name.as_str())).await {
        Ok(updated) => updated,
        Err(EnrollFailure::Api { status: _, api_error }) if api_error.has_error_message(INVALID_PUBLIC_KEY) => {
            println!("Invalid public key detected. Regenerate key? (y/n): ");
            let mut response = String::new();
            std::io::stdin().read_line(&mut response).context("failed to read user input")?;
            if response.trim() != "y" {
                return Err(anyhow!("enrollment aborted by user. API errors: {}", api_error.errors_as_string("; ")));
            }
            tracing::info!("Regenerating key pair...");
            let pair = internal::generate_ec_key_pair()?;
            private_key_der = pair.0;
            public_key_der = pair.1;
            enroll_or_fail(&account, &public_key_der, args.name.as_str()).await?
        }
        Err(err) => return Err(anyhow!(err)),
    };

    cfg = build_app_config(&updated, &private_key_der, &account.token)?;
    cfg.save(config_path)?;
    tracing::info!("Config saved to {config_path}");
    Ok(())
}

async fn native_tun(config_path: &str, args: NativeTunArgs) -> Result<()> {
    let cfg = AppConfig::load(config_path)?;
    if !args.interface_name.is_empty() {
        internal::check_ifname(&args.interface_name)?;
    }
    if args.mtu != 1200 {
        tracing::warn!("MTU is not the tuned FreeBSD default 1200 for this release. Packet loss and jitter may increase.");
    }
    if args.keepalive_period.is_zero() {
        tracing::info!("QUIC keepalive is disabled");
    } else {
        tracing::info!(
            "QUIC keepalive will send an RFC 9000 PING after {:?} of network inactivity",
            args.keepalive_period
        );
    }

    let endpoint = config::select_endpoint_from_config(&cfg, args.ipv6, args.connect_port)?;
    if args.insecure {
        config::warn_insecure();
    }

    let tun = TunRsDevice::create(
        &cfg,
        TunOptions {
            name: if args.interface_name.is_empty() { None } else { Some(args.interface_name.clone()) },
            mtu: args.mtu,
            configure_addresses: !args.no_iproute2,
            ipv4: !args.no_tunnel_ipv4,
            ipv6: !args.no_tunnel_ipv6,
            persist: args.persist,
        },
    )
    .await
    .context("failed to create native tun-rs TUN device. Are you root/administrator?")?;

    tracing::info!("Created TUN device: {}", tun.name());

    let hook_env = HashMap::from([
        ("USQUE_MODE".to_string(), "nativetun".to_string()),
        ("USQUE_IFACE".to_string(), tun.name().to_string()),
        ("USQUE_IPV4".to_string(), cfg.ipv4.clone()),
        ("USQUE_IPV6".to_string(), cfg.ipv6.clone()),
    ]);

    let masque = MasqueConfig {
        private_key: cfg.get_ec_private_key()?,
        endpoint_pub_key_spki_der: cfg.get_ec_endpoint_public_key_der()?,
        sni: args.sni_address,
        insecure: args.insecure,
        endpoint,
        keepalive_period: args.keepalive_period,
        initial_packet_size: args.initial_packet_size,
        cc_algorithm: args.cc,
        initial_cwnd_packets: args.initial_cwnd_packets,
        disable_quic_pacing: args.disable_quic_pacing,
        relaxed_loss: args.relaxed_loss,
        send_capacity_factor: args.send_capacity_factor,
        max_pacing_rate_bps: args.max_pacing_rate_bps,
        udp_socket_buffer: args.udp_socket_buffer,
        tx_queue_len: args.tx_queue_len,
        tx_burst_packets: args.tx_burst_packets,
        reconnect_delay: args.reconnect_delay,
        always_reconnect: args.always_reconnect,
        on_connect: non_empty(args.on_connect),
        on_disconnect: non_empty(args.on_disconnect),
        hook_env,
    };

    tracing::info!("Tunnel device is ready; starting MASQUE packet pump");
    maintain_native_tun(&cfg, masque, tun, args.mtu as usize).await
}

async fn enroll_or_fail(account: &AccountData, public_key_der: &[u8], device_name: &str) -> Result<AccountData> {
    cloudflare::enroll_key(account, public_key_der, Some(device_name))
        .await
        .map_err(|err| anyhow!(err))
}

fn build_app_config(account: &AccountData, private_key_der: &[u8], access_token: &str) -> Result<AppConfig> {
    let peer = account
        .config
        .peers
        .first()
        .ok_or_else(|| anyhow!("Cloudflare response did not contain a peer config"))?;
    Ok(AppConfig {
        private_key: general_purpose::STANDARD.encode(private_key_der),
        endpoint_v4: config::endpoint_v4_from_account_value(&peer.endpoint.v4),
        endpoint_v6: config::endpoint_v6_from_account_value(&peer.endpoint.v6),
        endpoint_pub_key: peer.public_key.clone(),
        license: account.account.license.clone(),
        id: account.id.clone(),
        access_token: access_token.to_string(),
        ipv4: account.config.interface.addresses.v4.clone(),
        ipv6: account.config.interface.addresses.v6.clone(),
    })
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

fn parse_duration(input: &str) -> std::result::Result<Duration, String> {
    if let Some(ms) = input.strip_suffix("ms") {
        return ms.parse::<u64>().map(Duration::from_millis).map_err(|e| e.to_string());
    }
    if let Some(s) = input.strip_suffix('s') {
        return s.parse::<u64>().map(Duration::from_secs).map_err(|e| e.to_string());
    }
    if let Some(m) = input.strip_suffix('m') {
        return m.parse::<u64>().map(|m| Duration::from_secs(m * 60)).map_err(|e| e.to_string());
    }
    input.parse::<u64>().map(Duration::from_secs).map_err(|e| e.to_string())
}
