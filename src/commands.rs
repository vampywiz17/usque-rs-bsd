use crate::api::cloudflare::{self, EnrollFailure};
use crate::api::device_state::DeviceStateReporter;
use crate::api::icmp;
use crate::api::masque::{
    maintain_native_tun, CloudflareConnectProfile, DatagramIoConfig, LifecycleHooks, MasqueConfig,
    PathMtuConfig, QuicTransportConfig, ReconnectPolicy,
};
use crate::api::mesh::{self, MeshNodeToken, CONNECTOR_REGISTRATION_PLATFORM};
use crate::config::{self, AppConfig, MeshNodeIdentity, TunnelRole};
use crate::internal;
use crate::models::{AccountData, DeviceIdentity, INVALID_PUBLIC_KEY};
use crate::native_tun::{TunOptions, TunRsDevice, IPV6_MIN_MTU};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Args, Parser, Subcommand};
use p256::pkcs8::EncodePublicKey;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
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
    /// Register this host as an optional Cloudflare Mesh node.
    #[command(name = "mesh-register")]
    MeshRegister(MeshRegisterArgs),
    /// Enroll or regenerate the MASQUE private key used by nativetun.
    Enroll(EnrollArgs),
    /// Expose WARP as a native TUN device using tun-rs.
    #[command(name = "nativetun")]
    NativeTun(NativeTunArgs),
    /// Run a registered Mesh node without managing routes or firewall policy.
    #[command(name = "mesh-node")]
    MeshNode(MeshNodeArgs),
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
pub struct MeshRegisterArgs {
    /// Cloudflare-generated Mesh node token file (must be mode 0600 on Unix).
    #[arg(long)]
    pub token_file: PathBuf,
    #[arg(short, long, default_value = internal::DEFAULT_LOCALE)]
    pub locale: String,
    #[arg(short, long, default_value = internal::DEFAULT_MODEL)]
    pub model: String,
    #[arg(short, long, default_value = "")]
    pub name: String,
    /// Acknowledge that Cloudflare currently accepts Mesh nodes only as Linux.
    /// On FreeBSD this sends a documented "linux" compatibility claim and may
    /// expose the account to unsupported-use enforcement.
    #[arg(long)]
    pub acknowledge_linux_platform_claim: bool,
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
    /// Administrative upper bound for the dynamically discovered inner IP MTU.
    /// The effective value is always derived from quiche's writable DATAGRAM
    /// capacity and never exceeds this ceiling.
    #[arg(long, default_value_t = 1500)]
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
    /// Desired per-direction UDP socket-buffer growth target in bytes. The effective
    /// value is negotiated with and verified against the OS (minimum 64 KiB).
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

#[derive(Debug, Args)]
pub struct MeshNodeArgs {
    #[command(flatten)]
    pub tunnel: NativeTunArgs,
    /// Override the Mesh activation probe destination. Without this flag, the
    /// persisted config value is used, then Cloudflare's 1.1.1.1 service.
    #[arg(long)]
    pub activation_probe_target: Option<IpAddr>,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Register(args) => register(&cli.config, args).await,
        Commands::MeshRegister(args) => mesh_register(&cli.config, args).await,
        Commands::Enroll(args) => enroll(&cli.config, args).await,
        Commands::NativeTun(args) => native_tun(&cli.config, args).await,
        Commands::MeshNode(args) => mesh_node(&cli.config, args).await,
        Commands::Version => {
            println!("usque-nativetun version: {}", env!("CARGO_PKG_VERSION"));
            println!("Modes: native TUN client, optional route-neutral Mesh node");
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

async fn mesh_register(config_path: &str, args: MeshRegisterArgs) -> Result<()> {
    if Path::new(config_path).exists() {
        return Err(anyhow!(
            "refusing to overwrite existing config {config_path}; choose a separate Mesh config path"
        ));
    }
    if !args.accept_tos {
        println!(
            "You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): "
        );
        let mut response = String::new();
        std::io::stdin()
            .read_line(&mut response)
            .context("failed to read user input")?;
        if response.trim() != "y" {
            return Err(anyhow!("user did not accept TOS"));
        }
    }
    if !args.acknowledge_linux_platform_claim {
        return Err(anyhow!(
            "Cloudflare's Mesh node endpoint is Linux-only and rejects FreeBSD. Re-run with \
             --acknowledge-linux-platform-claim only after reading README.md and LEGAL.md"
        ));
    }

    let token = MeshNodeToken::read(&args.token_file)?;
    let identity = internal::detect_device_identity(&args.name, &args.model, &args.locale);
    let native_platform = identity.device_type.clone();
    let mut registration_identity = identity.clone();
    registration_identity.device_type = CONNECTOR_REGISTRATION_PLATFORM.to_string();
    tracing::warn!(
        "Cloudflare rejected FreeBSD Mesh registration; sending the explicitly acknowledged \
         compatibility platform claim '{}' for actual platform '{}'. Cloudflare may suspend or terminate service for unsupported use",
        CONNECTOR_REGISTRATION_PLATFORM, native_platform
    );
    tracing::info!(
        "Registering Mesh node '{}' (actual OS {} {}, client {})",
        identity.name,
        native_platform,
        identity.os_version,
        identity.client_version
    );
    let (private_key_der, public_key_der) = internal::generate_ec_key_pair()?;
    let account = mesh::register(&token, &registration_identity, &public_key_der).await?;
    tracing::info!("Enrolling the Mesh MASQUE key through Cloudflare's registration contract");
    let enrolled = enroll_or_fail(&account, &public_key_der, &registration_identity).await?;
    let mut app_cfg = build_app_config(&enrolled, &private_key_der, &account.token, identity)?;
    app_cfg.role = TunnelRole::MeshNode;
    app_cfg.mesh_node = Some(MeshNodeIdentity {
        account_tag: token.account_tag().to_string(),
        tunnel_id: token.tunnel_id().to_string(),
        activation_probe_target: None,
        native_platform,
        registration_platform_claim: CONNECTOR_REGISTRATION_PLATFORM.to_string(),
    });
    app_cfg.save_sensitive(config_path)?;
    tracing::info!("Mesh node config saved to {config_path} with owner-only permissions");
    tracing::info!(
        "No routes or firewall rules were created; FreeBSD/OPNsense policy remains administrator-owned"
    );
    Ok(())
}

async fn enroll(config_path: &str, args: EnrollArgs) -> Result<()> {
    let mut cfg = AppConfig::load(config_path)?;
    if cfg.role != TunnelRole::Client {
        return Err(anyhow!(
            "the enroll command only supports client configs; Mesh nodes must be registered with mesh-register"
        ));
    }
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
    run_tunnel(config_path, args, TunnelRole::Client, None).await
}

async fn mesh_node(config_path: &str, args: MeshNodeArgs) -> Result<()> {
    run_tunnel(
        config_path,
        args.tunnel,
        TunnelRole::MeshNode,
        args.activation_probe_target,
    )
    .await
}

async fn run_tunnel(
    config_path: &str,
    args: NativeTunArgs,
    requested_role: TunnelRole,
    activation_probe_override: Option<IpAddr>,
) -> Result<()> {
    let cfg = AppConfig::load(config_path)?;
    if cfg.role != requested_role {
        return Err(anyhow!(
            "config role is '{}', but the selected command requires '{}'",
            cfg.role,
            requested_role
        ));
    }
    if requested_role == TunnelRole::MeshNode && cfg.mesh_node.is_none() {
        return Err(anyhow!("Mesh node config is missing its node identity"));
    }
    if requested_role == TunnelRole::MeshNode {
        tracing::info!(
            "Mesh node mode selected; routes, forwarding and firewall policy remain under FreeBSD/OPNsense administrator control"
        );
    }
    if !args.interface_name.is_empty() {
        internal::check_ifname(&args.interface_name)?;
    }
    if args.udp_socket_buffer > libc::c_int::MAX as usize {
        return Err(anyhow!(
            "--udp-socket-buffer ({}) exceeds the largest value supported by SO_RCVBUF/SO_SNDBUF ({})",
            args.udp_socket_buffer,
            libc::c_int::MAX
        ));
    }
    if args.max_tun_mtu < args.mtu {
        return Err(anyhow!(
            "--max-tun-mtu ({}) must be at least --mtu ({})",
            args.max_tun_mtu,
            args.mtu
        ));
    }
    let tunnel_ipv6 = !args.no_tunnel_ipv6;
    if tunnel_ipv6 && args.max_tun_mtu < IPV6_MIN_MTU {
        return Err(anyhow!(
            "IPv6 requires --max-tun-mtu of at least 1280; use --no-tunnel-ipv6 for a smaller IPv4-only tunnel"
        ));
    }
    if tunnel_ipv6 && args.disable_pmtud && args.mtu < IPV6_MIN_MTU {
        return Err(anyhow!(
            "IPv6 requires --mtu of at least 1280 when PMTUD is disabled; raise --mtu or use --no-tunnel-ipv6"
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

    let activation_probe =
        build_mesh_activation_probe(&cfg, requested_role, activation_probe_override)?;
    let endpoints = config::select_endpoints_from_config(&cfg, args.ipv6, args.connect_port)?;
    if args.insecure {
        config::warn_insecure();
    }

    let device_state = match DeviceStateReporter::start(&cfg, args.always_reconnect).await {
        Ok(reporter) => {
            tracing::info!(
                role = %requested_role,
                "Cloudflare device-state reporting enabled with truthful FreeBSD/MASQUE data"
            );
            Some(reporter)
        }
        Err(err) if requested_role == TunnelRole::MeshNode => {
            return Err(err).context(
                "Mesh registration validation failed; register a fresh node instead of starting an untracked Edge session",
            );
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
            ipv6: tunnel_ipv6,
            defer_ipv6: tunnel_ipv6 && !args.disable_pmtud,
            persist: args.persist,
        },
    )
    .await
    .context("failed to create native tun-rs TUN device. Are you root/administrator?")?;

    tracing::info!("Created TUN device: {}", tun.name());
    let (hook_mode, user_agent_role) = match requested_role {
        TunnelRole::Client => ("nativetun", "TunnelOnly"),
        TunnelRole::MeshNode => ("mesh-node", "MeshNode"),
    };
    let client_version = if cfg.device_identity.client_version.is_empty() {
        env!("CARGO_PKG_VERSION")
    } else {
        &cfg.device_identity.client_version
    };
    let user_agent =
        format!("usque-nativetun/{client_version} (FreeBSD; {user_agent_role}; MASQUE)");

    let hook_env = HashMap::from([
        ("USQUE_MODE".to_string(), hook_mode.to_string()),
        ("USQUE_IFACE".to_string(), tun.name().to_string()),
        ("USQUE_IPV4".to_string(), cfg.ipv4.clone()),
        ("USQUE_IPV6".to_string(), cfg.ipv6.clone()),
    ]);

    let connect_profile = match requested_role {
        TunnelRole::Client => CloudflareConnectProfile::Client,
        TunnelRole::MeshNode => CloudflareConnectProfile::MeshNode {
            client_version: client_version.to_string(),
        },
    };
    let masque = MasqueConfig {
        private_key: cfg.get_ec_private_key()?,
        sni: args.sni_address,
        insecure: args.insecure,
        endpoints,
        user_agent,
        connect_profile,
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
            tunnel_ipv6,
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
            always: maintain_edge_session(requested_role, args.always_reconnect),
        },
        hooks: LifecycleHooks {
            on_connect: non_empty(args.on_connect),
            on_disconnect: non_empty(args.on_disconnect),
            env: hook_env,
        },
        activation_probe,
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
        role: TunnelRole::Client,
        mesh_node: None,
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

const DEFAULT_MESH_ACTIVATION_PROBE_TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

fn build_mesh_activation_probe(
    cfg: &AppConfig,
    role: TunnelRole,
    override_target: Option<IpAddr>,
) -> Result<Option<Vec<u8>>> {
    if role != TunnelRole::MeshNode {
        return Ok(None);
    }

    let target = override_target
        .or_else(|| {
            cfg.mesh_node
                .as_ref()
                .and_then(|identity| identity.activation_probe_target)
        })
        .unwrap_or(DEFAULT_MESH_ACTIVATION_PROBE_TARGET);
    let source_config = if target.is_ipv4() {
        &cfg.ipv4
    } else {
        &cfg.ipv6
    };
    let source_text = source_config.split('/').next().unwrap_or(source_config);
    let source: IpAddr = source_text.parse().with_context(|| {
        format!("invalid assigned Mesh source address '{source_text}' for activation probe")
    })?;
    let packet = icmp::compose_echo_request(source, target, 0).ok_or_else(|| {
        anyhow!(
            "Mesh activation probe target {target} does not match assigned source address {source}"
        )
    })?;

    tracing::info!(
        source = %source,
        target = %target,
        "Mesh activation probe configured; one ICMP Echo Request will be sent after each successful CONNECT-IP session"
    );
    Ok(Some(packet))
}

fn maintain_edge_session(role: TunnelRole, always_reconnect: bool) -> bool {
    always_reconnect || role == TunnelRole::MeshNode
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

#[cfg(test)]
mod tests {
    use super::maintain_edge_session;
    use crate::config::TunnelRole;

    #[test]
    fn mesh_node_always_maintains_an_edge_session() {
        assert!(maintain_edge_session(TunnelRole::MeshNode, false));
        assert!(maintain_edge_session(TunnelRole::MeshNode, true));
    }

    #[test]
    fn client_preserves_on_demand_reconnect_policy() {
        assert!(!maintain_edge_session(TunnelRole::Client, false));
        assert!(maintain_edge_session(TunnelRole::Client, true));
    }

    fn probe_config() -> crate::config::AppConfig {
        crate::config::AppConfig {
            role: TunnelRole::MeshNode,
            mesh_node: Some(crate::config::MeshNodeIdentity {
                account_tag: "a".repeat(32),
                tunnel_id: "00000000-0000-0000-0000-000000000000".to_string(),
                activation_probe_target: Some("192.0.2.10".parse().unwrap()),
                native_platform: "FreeBSD".to_string(),
                registration_platform_claim: "linux".to_string(),
            }),
            ipv4: "100.96.0.1/32".to_string(),
            ipv6: "2606:4700:cf1:1000::1/128".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn client_role_never_builds_a_mesh_activation_probe() {
        let probe = super::build_mesh_activation_probe(
            &probe_config(),
            TunnelRole::Client,
            Some("1.1.1.1".parse().unwrap()),
        )
        .unwrap();
        assert!(probe.is_none());
    }

    #[test]
    fn mesh_probe_uses_the_assigned_address_and_configured_target() {
        let packet =
            super::build_mesh_activation_probe(&probe_config(), TunnelRole::MeshNode, None)
                .unwrap()
                .unwrap();
        assert_eq!(&packet[12..16], &[100, 96, 0, 1]);
        assert_eq!(&packet[16..20], &[192, 0, 2, 10]);
    }

    #[test]
    fn mesh_probe_defaults_to_cloudflare_dns() {
        let mut cfg = probe_config();
        cfg.mesh_node.as_mut().unwrap().activation_probe_target = None;
        let packet = super::build_mesh_activation_probe(&cfg, TunnelRole::MeshNode, None)
            .unwrap()
            .unwrap();
        assert_eq!(&packet[16..20], &[1, 1, 1, 1]);
    }

    #[test]
    fn mesh_probe_cli_target_overrides_persisted_target() {
        let packet = super::build_mesh_activation_probe(
            &probe_config(),
            TunnelRole::MeshNode,
            Some("203.0.113.7".parse().unwrap()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(&packet[16..20], &[203, 0, 113, 7]);
    }

    #[test]
    fn mesh_cli_accepts_activation_probe_override() {
        use clap::Parser as _;

        let cli = super::Cli::try_parse_from([
            "usque-nativetun",
            "mesh-node",
            "--activation-probe-target",
            "2606:4700:4700::1111",
        ])
        .unwrap();
        let super::Commands::MeshNode(args) = cli.command else {
            panic!("expected Mesh node command");
        };
        assert_eq!(
            args.activation_probe_target,
            Some("2606:4700:4700::1111".parse().unwrap())
        );
    }

    #[test]
    fn client_cli_rejects_mesh_activation_probe_override() {
        use clap::Parser as _;

        assert!(super::Cli::try_parse_from([
            "usque-nativetun",
            "nativetun",
            "--activation-probe-target",
            "1.1.1.1",
        ])
        .is_err());
    }
}
