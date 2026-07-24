use crate::api::cloudflare::{self, EnrollFailure};
use crate::api::device_state::DeviceStateReporter;
use crate::api::masque::{
    maintain_native_tun, DatagramIoConfig, LifecycleHooks, MasqueConfig, PathMtuConfig,
    QuicTransportConfig, ReconnectPolicy,
};
use crate::api::tunnel::TunnelDevice;
use crate::config::{self, AppConfig};
use crate::internal;
use crate::models::{AccountData, DeviceIdentity, INVALID_PUBLIC_KEY};
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
    /// Override the Cloudflare MASQUE endpoint port. 0 uses the API-provided
    /// port list, falling back to 443 for legacy configurations.
    #[arg(short = 'P', long, default_value_t = 0)]
    pub connect_port: u16,
    /// Prefer an IPv6 MASQUE endpoint while retaining IPv4 as fallback.
    #[arg(short = '6', long)]
    pub ipv6: bool,
    #[arg(short = 'F', long)]
    pub no_tunnel_ipv4: bool,
    #[arg(short = 'S', long)]
    pub no_tunnel_ipv6: bool,
    #[arg(short = 's', long, default_value = internal::CONNECT_SNI)]
    pub sni_address: String,
    /// Schedule an RFC 9000 QUIC PING at this interval to preserve QUIC and
    /// outbound UDP/NAT state.
    /// Use 0s to disable keepalive.
    #[arg(short = 'k', long, default_value = "25s", value_parser = parse_duration)]
    pub keepalive_period: Duration,
    /// Safe MTU used while PMTUD is running. The interface is raised to the
    /// discovered MASQUE DATAGRAM capacity, up to --max-tun-mtu.
    #[arg(short = 'm', long, default_value_t = 1200)]
    pub mtu: u16,
    /// Upper bound for the dynamically discovered TUN MTU. Cloudflare's
    /// documented MASQUE thresholds are based on a 1280-byte inner packet.
    #[arg(long, default_value_t = 1280)]
    pub max_tun_mtu: u16,
    /// Maximum UDP payload PMTUD may probe. 1472 reaches a 1500-byte IPv4 path;
    /// quiche automatically discovers a lower value for IPv6 or smaller paths.
    #[arg(long, default_value_t = 1472)]
    pub initial_packet_size: u16,
    /// Disable RFC 8899 DPLPMTUD and keep the TUN interface at --mtu.
    #[arg(long)]
    pub disable_pmtud: bool,
    /// Failed probes required before quiche reduces a candidate PMTU.
    #[arg(long, default_value_t = 3)]
    pub pmtud_max_probes: u8,
    /// Periodically revalidate the discovered PMTU. Use 0s to disable
    /// revalidation while retaining initial discovery.
    #[arg(long, default_value = "10m", value_parser = parse_duration)]
    pub pmtud_revalidate_period: Duration,
    /// QUIC congestion-control algorithm. Try: cubic, reno, bbr2_gcongestion.
    #[arg(long, default_value = "cubic")]
    pub cc: String,
    /// Initial QUIC congestion window in packets. FreeBSD upload tests favor 32.
    #[arg(long, default_value_t = 32)]
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
    /// A 16-packet burst avoids severe upload latency without reducing throughput
    /// on the tested FreeBSD path.
    #[arg(long, default_value_t = 16)]
    pub tx_burst_packets: usize,
    /// Number of reusable packet buffers shared by the TUN reader and MASQUE
    /// sender. This bounds upload buffering without allocating per packet.
    #[arg(long, default_value_t = 1024)]
    pub packet_buffer_pool_size: usize,
    /// Maximum UDP datagrams sent or received by one FreeBSD mmsg syscall.
    /// Other platforms retain the portable Tokio fallback.
    #[arg(long, default_value_t = 32)]
    pub udp_batch_size: usize,
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
        std::io::stdin()
            .read_line(&mut response)
            .context("failed to read response")?;
        if response.trim() != "y" {
            return Ok(());
        }
    }

    let identity = internal::detect_device_identity(&args.name, &args.model, &args.locale);
    if args.jwt.is_empty() {
        tracing::info!(
            "Registering MASQUE device '{}' ({} {}, client {})",
            identity.name,
            identity.device_type,
            identity.os_version,
            identity.client_version
        );
    } else {
        tracing::info!(
            "Registering MASQUE device '{}' using JWT authentication",
            identity.name
        );
    }

    let (private_key_der, public_key_der) = internal::generate_ec_key_pair()?;
    let account = cloudflare::register(
        &identity,
        &public_key_der,
        if args.jwt.is_empty() {
            None
        } else {
            Some(args.jwt.as_str())
        },
        args.accept_tos,
    )
    .await?;

    tracing::info!("Enrolling device key...");
    let updated = enroll_or_fail(&account, &public_key_der, &identity).await?;

    let app_cfg = build_app_config(&updated, &private_key_der, &account.token, identity)?;
    app_cfg.save(config_path)?;
    tracing::info!("Config saved to {config_path}");
    Ok(())
}

async fn enroll(config_path: &str, args: EnrollArgs) -> Result<()> {
    let mut cfg = AppConfig::load(config_path)?;
    let account = AccountData {
        id: cfg.id.clone(),
        token: cfg.access_token.clone(),
        ..Default::default()
    };
    let mut identity = if cfg.device_identity.serial_number.is_empty() {
        internal::detect_device_identity(
            &args.name,
            internal::DEFAULT_MODEL,
            internal::DEFAULT_LOCALE,
        )
    } else {
        cfg.device_identity.clone()
    };
    if !args.name.trim().is_empty() {
        identity.name = args.name.trim().to_string();
    }
    identity.client_version = env!("CARGO_PKG_VERSION").to_string();

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
    let updated = match cloudflare::enroll_key(&account, &public_key_der, &identity).await {
        Ok(updated) => updated,
        Err(EnrollFailure::Api {
            status: _,
            api_error,
        }) if api_error.has_error_message(INVALID_PUBLIC_KEY) => {
            println!("Invalid public key detected. Regenerate key? (y/n): ");
            let mut response = String::new();
            std::io::stdin()
                .read_line(&mut response)
                .context("failed to read user input")?;
            if response.trim() != "y" {
                return Err(anyhow!(
                    "enrollment aborted by user. API errors: {}",
                    api_error.errors_as_string("; ")
                ));
            }
            tracing::info!("Regenerating key pair...");
            let pair = internal::generate_ec_key_pair()?;
            private_key_der = pair.0;
            public_key_der = pair.1;
            enroll_or_fail(&account, &public_key_der, &identity).await?
        }
        Err(err) => return Err(anyhow!(err)),
    };

    cfg = build_app_config(&updated, &private_key_der, &account.token, identity)?;
    cfg.save(config_path)?;
    tracing::info!("Config saved to {config_path}");
    Ok(())
}

async fn native_tun(config_path: &str, args: NativeTunArgs) -> Result<()> {
    let cfg = AppConfig::load(config_path)?;
    if !args.interface_name.is_empty() {
        internal::check_ifname(&args.interface_name)?;
    }
    if args.max_tun_mtu < args.mtu {
        return Err(anyhow!(
            "--max-tun-mtu ({}) must be at least --mtu ({})",
            args.max_tun_mtu,
            args.mtu
        ));
    }
    if args.keepalive_period.is_zero() {
        tracing::info!("QUIC keepalive is disabled");
    } else {
        tracing::info!(
            "QUIC keepalive will send an RFC 9000 PING after {:?} of network inactivity",
            args.keepalive_period
        );
    }

    let endpoints = config::select_endpoints_from_config(&cfg, args.ipv6, args.connect_port)?;
    if args.insecure {
        config::warn_insecure();
    }

    let device_state = match DeviceStateReporter::start(&cfg, args.always_reconnect).await {
        Ok(reporter) => {
            tracing::info!("Cloudflare device-state reporting enabled (TunnelOnly/MASQUE)");
            Some(reporter)
        }
        Err(err) => {
            tracing::warn!(
                "Cloudflare device-state reporting is unavailable; tunnel operation will continue: {err:#}"
            );
            None
        }
    };

    let tun = TunRsDevice::create(
        &cfg,
        TunOptions {
            name: if args.interface_name.is_empty() {
                None
            } else {
                Some(args.interface_name.clone())
            },
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
        sni: args.sni_address,
        insecure: args.insecure,
        endpoints,
        user_agent: if cfg.device_identity.client_version.is_empty() {
            internal::client_user_agent()
        } else {
            format!(
                "usque-nativetun/{} (FreeBSD; TunnelOnly; MASQUE)",
                cfg.device_identity.client_version
            )
        },
        quic: QuicTransportConfig {
            keepalive_period: args.keepalive_period,
            initial_packet_size: args.initial_packet_size,
            cc_algorithm: args.cc,
            initial_cwnd_packets: args.initial_cwnd_packets,
            disable_pacing: args.disable_quic_pacing,
            relaxed_loss: args.relaxed_loss,
            send_capacity_factor: args.send_capacity_factor,
            max_pacing_rate_bps: args.max_pacing_rate_bps,
        },
        path_mtu: PathMtuConfig {
            enabled: !args.disable_pmtud,
            max_probes: args.pmtud_max_probes,
            revalidate_period: args.pmtud_revalidate_period,
            initial_tun_mtu: args.mtu,
            max_tun_mtu: args.max_tun_mtu,
        },
        io: DatagramIoConfig {
            udp_socket_buffer: args.udp_socket_buffer,
            tx_queue_len: args.tx_queue_len,
            tx_burst_packets: args.tx_burst_packets,
            packet_buffer_pool_size: args.packet_buffer_pool_size,
            udp_batch_size: args.udp_batch_size,
        },
        reconnect: ReconnectPolicy {
            delay: args.reconnect_delay,
            always: args.always_reconnect,
        },
        hooks: LifecycleHooks {
            on_connect: non_empty(args.on_connect),
            on_disconnect: non_empty(args.on_disconnect),
            env: hook_env,
        },
        device_state,
    };

    tracing::info!("Tunnel device is ready; starting MASQUE packet pump");
    maintain_native_tun(masque, tun, args.max_tun_mtu as usize).await
}

async fn enroll_or_fail(
    account: &AccountData,
    public_key_der: &[u8],
    identity: &DeviceIdentity,
) -> Result<AccountData> {
    cloudflare::enroll_key(account, public_key_der, identity)
        .await
        .map_err(|err| anyhow!(err))
}

fn build_app_config(
    account: &AccountData,
    private_key_der: &[u8],
    access_token: &str,
    device_identity: DeviceIdentity,
) -> Result<AppConfig> {
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
        device_identity,
        masque_peers: account
            .config
            .peers
            .iter()
            .map(|peer| config::MasquePeerConfig {
                endpoint_v4: config::endpoint_v4_from_account_value(&peer.endpoint.v4),
                endpoint_v6: config::endpoint_v6_from_account_value(&peer.endpoint.v6),
                endpoint_host: peer.endpoint.host.clone(),
                ports: peer.endpoint.ports.clone(),
                endpoint_pub_key: peer.public_key.clone(),
            })
            .collect(),
    })
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn parse_duration(input: &str) -> std::result::Result<Duration, String> {
    if let Some(ms) = input.strip_suffix("ms") {
        return ms
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| e.to_string());
    }
    if let Some(s) = input.strip_suffix('s') {
        return s
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| e.to_string());
    }
    if let Some(m) = input.strip_suffix('m') {
        return m
            .parse::<u64>()
            .map(|m| Duration::from_secs(m * 60))
            .map_err(|e| e.to_string());
    }
    input
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|e| e.to_string())
}
