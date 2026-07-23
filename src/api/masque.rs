use crate::api::hooks::run_hook;
use crate::api::{icmp, packet};
use crate::config::{AppConfig, EndpointAddr};
use crate::native_tun::TunRsDevice;
use anyhow::{anyhow, bail, Context, Result};
use octets::{Octets, OctetsMut};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use p256::SecretKey;
use portable_atomic::{AtomicU64, Ordering};
use quiche::h3::NameValue;
use rcgen::{CertificateParams, KeyPair};
use ring::rand::SecureRandom;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const MAX_DATAGRAM_SIZE: usize = 1500;
const MIN_MTU: u16 = 1280;
const DEFAULT_UDP_SOCKET_BUFFER: usize = 8 * 1024 * 1024;
const DGRAM_QUEUE_LEN: usize = 16_384;
const TX_CHANNEL_DRAIN_BURST: usize = 256;

#[derive(Clone)]
pub struct MasqueConfig {
    pub private_key: SecretKey,
    pub endpoint_pub_key_spki_der: Vec<u8>,
    pub sni: String,
    pub insecure: bool,
    pub endpoint: EndpointAddr,
    pub keepalive_period: Duration,
    pub initial_packet_size: u16,
    pub cc_algorithm: String,
    pub initial_cwnd_packets: usize,
    pub disable_quic_pacing: bool,
    pub relaxed_loss: bool,
    pub send_capacity_factor: f64,
    pub max_pacing_rate_bps: u64,
    pub udp_socket_buffer: usize,
    pub tx_queue_len: usize,
    pub tx_burst_packets: usize,
    pub reconnect_delay: Duration,
    pub always_reconnect: bool,
    pub on_connect: Option<String>,
    pub on_disconnect: Option<String>,
    pub hook_env: HashMap<String, String>,
}

struct TlsMaterial {
    cert_pem_file: NamedTempFile,
    key_pem_file: NamedTempFile,
    endpoint_pub_key_spki_der: Vec<u8>,
}

struct Stats {
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    dropped: AtomicU64,
    quic_lost: AtomicU64,
    quic_retrans: AtomicU64,
    tx_queue_len: AtomicU64,
    tx_backpressure: AtomicU64,
}

impl Stats {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            quic_lost: AtomicU64::new(0),
            quic_retrans: AtomicU64::new(0),
            tx_queue_len: AtomicU64::new(0),
            tx_backpressure: AtomicU64::new(0),
        })
    }
}

struct TxDatagram {
    bytes: Vec<u8>,
    ip_len: usize,
}

struct TxProgress {
    queued: usize,
    backpressure: bool,
}

fn endpoint_socket(endpoint: &EndpointAddr) -> SocketAddr {
    endpoint.0
}

fn create_connected_udp_socket(endpoint: SocketAddr, socket_buffer_size: usize) -> Result<tokio::net::UdpSocket> {
    let domain = if endpoint.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let bind_addr: SocketAddr = if endpoint.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create UDP socket")?;

    // MASQUE/WARP sends a lot of QUIC DATAGRAM traffic. The FreeBSD defaults can be
    // too small for iperf bursts, which shows up as TCP retransmits inside the tunnel.
    let sockbuf = socket_buffer_size.max(64 * 1024);
    if let Err(err) = sock.set_recv_buffer_size(sockbuf) {
        tracing::warn!("failed to set UDP recv buffer size to {sockbuf}: {err}");
    }
    if let Err(err) = sock.set_send_buffer_size(sockbuf) {
        tracing::warn!("failed to set UDP send buffer size to {sockbuf}: {err}");
    }

    sock.bind(&SockAddr::from(bind_addr))
        .context("failed to bind UDP socket")?;
    sock.connect(&SockAddr::from(endpoint))
        .context("failed to connect UDP socket")?;
    sock.set_nonblocking(true)
        .context("failed to set UDP socket nonblocking")?;

    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock)
        .context("failed to convert UDP socket to tokio")
}

pub async fn maintain_native_tun(
    _app_cfg: &AppConfig,
    cfg: MasqueConfig,
    dev: Arc<TunRsDevice>,
    mtu: usize,
) -> Result<()> {
    let mut pending_pkt: Option<Vec<u8>> = None;

    loop {
        if !cfg.always_reconnect && pending_pkt.is_none() {
            tracing::info!("Tunnel idle. Waiting for outbound activity before reconnecting...");
            let mut wait_buf = vec![0u8; mtu + 128];
            let n = dev.recv_packet(&mut wait_buf).await?;
            if n == 0 {
                bail!("TUN device closed");
            }
            wait_buf.truncate(n);
            pending_pkt = Some(wait_buf);
            tracing::info!("Detected outbound activity ({n} bytes). Connecting...");
        }

        tracing::info!("Establishing MASQUE connection to {}", cfg.endpoint);
        match run_tunnel_session(&cfg, &dev, mtu, &mut pending_pkt).await {
            Ok(()) => tracing::warn!("MASQUE session ended. Reconnecting..."),
            Err(err) => tracing::warn!("MASQUE session failed: {err:#}. Reconnecting..."),
        }
        tokio::time::sleep(cfg.reconnect_delay).await;
    }
}

fn prepare_tls_material(cfg: &MasqueConfig) -> Result<TlsMaterial> {
    let key_pem = cfg
        .private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode private key as PKCS8 PEM")?;
    let key_pair = KeyPair::from_pem(key_pem.as_ref()).context("failed to load key pair into rcgen")?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("failed to create certificate parameters")?;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(24 * 60 * 60);
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate self-signed client certificate")?;

    let mut cert_pem_file = NamedTempFile::new().context("failed to create temporary cert file")?;
    cert_pem_file
        .write_all(cert.pem().as_bytes())
        .context("failed to write temporary cert file")?;
    cert_pem_file.flush()?;

    let mut key_pem_file = NamedTempFile::new().context("failed to create temporary key file")?;
    key_pem_file
        .write_all(key_pem.as_bytes())
        .context("failed to write temporary key file")?;
    key_pem_file.flush()?;

    Ok(TlsMaterial {
        cert_pem_file,
        key_pem_file,
        endpoint_pub_key_spki_der: cfg.endpoint_pub_key_spki_der.clone(),
    })
}

fn verify_endpoint_key(peer_cert_der: &[u8], expected_spki_der: &[u8]) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(peer_cert_der) else {
        tracing::warn!("failed to parse peer certificate for key pinning");
        return false;
    };
    cert.tbs_certificate.subject_pki.raw == expected_spki_der
}

async fn run_tunnel_session(
    cfg: &MasqueConfig,
    dev: &Arc<TunRsDevice>,
    mtu: usize,
    pending_pkt: &mut Option<Vec<u8>>,
) -> Result<()> {
    let endpoint = endpoint_socket(&cfg.endpoint);
    let tls_material = prepare_tls_material(cfg)?;

    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| anyhow!("quiche config: {e}"))?;
    quic_config.verify_peer(false);
    quic_config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| anyhow!("set ALPN: {e}"))?;
    quic_config
        .load_cert_chain_from_pem_file(tls_material.cert_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow!("load client cert: {e}"))?;
    quic_config
        .load_priv_key_from_pem_file(tls_material.key_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow!("load client private key: {e}"))?;

    quic_config.set_max_idle_timeout(0);
    let udp_payload = if cfg.initial_packet_size > 0 {
        usize::from(cfg.initial_packet_size)
    } else {
        MAX_DATAGRAM_SIZE
    };
    quic_config.set_max_recv_udp_payload_size(udp_payload);
    quic_config.set_max_send_udp_payload_size(udp_payload);
    quic_config.set_initial_max_data(64_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(8_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(8_000_000);
    quic_config.set_initial_max_stream_data_uni(8_000_000);
    quic_config.set_initial_max_streams_bidi(100);
    quic_config.set_initial_max_streams_uni(100);
    if !cfg.cc_algorithm.trim().is_empty() {
        quic_config
            .set_cc_algorithm_name(cfg.cc_algorithm.trim())
            .map_err(|e| anyhow!("set QUIC congestion-control algorithm '{}': {e}", cfg.cc_algorithm.trim()))?;
    }
    quic_config.set_initial_congestion_window_packets(cfg.initial_cwnd_packets);
    if cfg.disable_quic_pacing {
        quic_config.enable_pacing(false);
    }
    if cfg.relaxed_loss {
        quic_config.set_enable_relaxed_loss_threshold(true);
    }
    if cfg.send_capacity_factor > 0.0 && (cfg.send_capacity_factor - 1.0).abs() > f64::EPSILON {
        quic_config.set_send_capacity_factor(cfg.send_capacity_factor);
    }
    if cfg.max_pacing_rate_bps > 0 {
        quic_config.set_max_pacing_rate(cfg.max_pacing_rate_bps);
    }
    tracing::info!(
        "QUIC tuning: quiche=0.29 cc={} initial_cwnd_packets={} udp_payload={} dgram_queue_len={} tx_queue_len={} tx_burst_packets={} pacing={} relaxed_loss={} send_capacity_factor={} max_pacing_rate_bps={} udp_socket_buffer={}",
        cfg.cc_algorithm.trim(),
        cfg.initial_cwnd_packets,
        udp_payload,
        DGRAM_QUEUE_LEN,
        cfg.tx_queue_len,
        cfg.tx_burst_packets,
        if cfg.disable_quic_pacing { "off" } else { "on" },
        cfg.relaxed_loss,
        cfg.send_capacity_factor,
        cfg.max_pacing_rate_bps,
        cfg.udp_socket_buffer,
    );
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, DGRAM_QUEUE_LEN, DGRAM_QUEUE_LEN);

    let socket = create_connected_udp_socket(endpoint, cfg.udp_socket_buffer)?;
    let local_addr = socket.local_addr()?;

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .map_err(|_| anyhow!("RNG failure"))?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(Some(&cfg.sni), &scid, local_addr, endpoint, &mut quic_config)
        .map_err(|e| anyhow!("quiche connect: {e}"))?;

    let mut out = vec![0u8; MAX_DATAGRAM_SIZE.max(udp_payload)];
    let mut buf = vec![0u8; 65_535];

    let (write, send_info) = conn
        .send(&mut out)
        .map_err(|e| anyhow!("initial send: {e}"))?;
    let _ = send_info;
    socket.send(&out[..write]).await?;

    complete_quic_handshake(&socket, endpoint, local_addr, &mut conn, &mut buf, &mut out).await?;

    if !cfg.insecure {
        if let Some(peer_cert) = conn.peer_cert() {
            if !verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
                bail!("remote endpoint public key does not match config.json endpoint_pub_key");
            }
            tracing::debug!("Endpoint key pinning verified");
        } else {
            bail!("no peer certificate received; cannot verify endpoint public key");
        }
    } else {
        tracing::warn!("--insecure is set; skipping endpoint public key pinning");
    }

    let mut h3_config = quiche::h3::Config::new().map_err(|e| anyhow!("h3 config: {e}"))?;
    h3_config.enable_extended_connect(true);
    let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
        .map_err(|e| anyhow!("h3 connection: {e}"))?;

    let req = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"user-agent", b""),
    ];
    let stream_id = h3_conn
        .send_request(&mut conn, &req, false)
        .map_err(|e| anyhow!("send CONNECT request: {e}"))?;
    let flow_id = stream_id / 4;
    tracing::debug!("CONNECT request sent on stream {stream_id}, H3 DATAGRAM flow_id={flow_id}");

    flush_quic(&socket, &mut conn, &mut out).await?;
    wait_connect_response(&socket, endpoint, local_addr, &mut conn, &mut h3_conn, stream_id, &mut buf, &mut out).await?;

    tracing::info!("Connected to MASQUE server");
    if let Some(path) = &cfg.on_connect {
        let mut env = cfg.hook_env.clone();
        env.insert("USQUE_EVENT".to_string(), "connect".to_string());
        env.insert("USQUE_ENDPOINT".to_string(), endpoint.to_string());
        run_hook(path, &env);
    }

    let stats = Stats::new();
    let stats_handle = spawn_stats_task(stats.clone(), Instant::now());
    let flow_prefix = build_flow_prefix(flow_id)?;

    if let Some(mut pkt) = pending_pkt.take() {
        send_packet_datagram(&socket, endpoint, local_addr, &mut conn, &flow_prefix, &mut pkt, &stats, dev, &mut buf, &mut out).await?;
        flush_quic(&socket, &mut conn, &mut out).await?;
    }

    let result = data_loop(
        &socket,
        endpoint,
        local_addr,
        &mut conn,
        &mut h3_conn,
        dev,
        mtu,
        &flow_prefix,
        flow_id,
        &stats,
        cfg.keepalive_period,
        cfg.tx_queue_len.max(1),
        cfg.tx_burst_packets.max(1),
        &mut buf,
        &mut out,
    )
    .await;

    stats_handle.abort();
    if let Some(path) = &cfg.on_disconnect {
        let mut env = cfg.hook_env.clone();
        env.insert("USQUE_EVENT".to_string(), "disconnect".to_string());
        env.insert("USQUE_ENDPOINT".to_string(), endpoint.to_string());
        run_hook(path, &env);
    }

    result
}

async fn complete_quic_handshake(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    local_addr: SocketAddr,
    conn: &mut quiche::Connection,
    buf: &mut [u8],
    out: &mut [u8],
) -> Result<()> {
    while !conn.is_established() {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));
        tokio::select! {
            result = socket.recv(buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                conn.recv(&mut buf[..len], recv_info).ok();
            }
            () = tokio::time::sleep(timeout) => conn.on_timeout(),
        }
        flush_quic(socket, conn, out).await?;
        if conn.is_closed() {
            bail!("connection closed during QUIC handshake");
        }
    }
    Ok(())
}

async fn wait_connect_response(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    local_addr: SocketAddr,
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    stream_id: ßOt¶‰žËkºwµçQ¥¹œ½¹¹•Ñ¥½¸­••Á…±¥Ù”¸-••Á¥¹œ(€€€€€€€€€€€€€€€€€€€€€€€€¼¼Ñ¡¥Ì…ÐÑ¡”EU%±…å•È…Ù½¥‘ÌÍå¹Ñ¡•Ñ¥ŒÑÉ…™™¥Œ¥¹Í¥‘”(€€€€€€€€€€€€€€€€€€€€€€€€¼¼Ñ¡”QU8¥¹Ñ•É™…”…¹¥Ì¥¹‘•Á•¹‘•¹Ð½˜Ñ¡”ÑÕ¸µÉÌ(€€€€€€€€€€€€€€€€€€€€€€€€¼¼Á±…Ñ™½É´‰…­•¹¸(€€€€€€€€€€€€€€€€€€€€€€€½¹¸¹Í•¹‘}…­}•±¥¥Ñ¥¹œ ¤(€€€€€€€€€€€€€€€€€€€€€€€€€€€€¹µ…Á}•ÉÈ¡ñ•ð…¹å¡½Ü„ ‰™…¥±•Ñ¼Í¡•‘Õ±”EU%­••Á…±¥Ù”A%9èí•ôˆ¤¤üì(€€€€€€€€€€€€€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ ‰Í¡•‘Õ±•EU%­••Á…±¥Ù”A%9ˆ¤ì(€€€€€€€€€€€€€€€€€€€€€€€±…ÍÑ}¹•ÑÝ½É­}…Ñ¥Ù¥Ñä€ô%¹ÍÑ…¹Ðèé¹½Ü ¤ì(€€€€€€€€€€€€€€€€€€€€€€€™±ÕÍ €ôÑÉÕ”ì(€€€€€€€€€€€€€€€€€€€ô((€€€€€€€€€€€€€€€€€€€¥˜™±ÕÍ ì(€€€€€€€€€€€€€€€€€€€€€€€™±ÕÍ¡}ÅÕ¥Œ¡Í½­•Ð°½¹¸°½ÕÐ¤¹…Ý…¥Ðüì(€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€ô(€€€€€€€ô(€€€ô(€€€€¹…Ý…¥Ðì((€€€ÑÕ¹}É•…‘•È¹…‰½ÉÐ ¤ì(€€€É•ÍÕ±Ð)ô()…Íå¹Œ™¸‰Õ¥±‘}Ñá}‘…Ñ…É…´ (€€€½¹¸è€™ÅÕ¥¡”èé½¹¹•Ñ¥½¸°(€€€™±½Ý}ÁÉ•™¥àè€™mÔát°(€€€µÕÐÁ­ÐèY•ŒñÔàø°(€€€ÍÑ…ÑÌè€™ÉŒñMÑ…ÑÌø°(€€€‘•Øè€™ÉŒñQÕ¹IÍ•Ù¥”ø°(¤€´ø=ÁÑ¥½¸ñQá…Ñ…É…´øì(€€€¥˜±•ÐÉÈ¡”¤€ôÁ…­•ÐèéÁÉ•Á…É•}½ÕÑ½¥¹œ ™µÕÐÁ­Ð¤ì(€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€ÑÉ…¥¹œèéÑÉ…”„ ‰‘É½ÁÁ¥¹œ½ÕÑ½¥¹œÁ…­•Ðèí•ôˆ¤ì(€€€€€€€É•ÑÕÉ¸9½¹”ì(€€€ô((€€€±•Ð¥Á}±•¸€ôÁ­Ð¹±•¸ ¤ì(€€€±•ÐµÕÐ‘É…´€ôY•ŒèéÝ¥Ñ¡}…Á…¥Ñä¡™±½Ý}ÁÉ•™¥à¹±•¸ ¤€¬¥Á}±•¸¤ì(€€€‘É…´¹•áÑ•¹‘}™É½µ}Í±¥”¡™±½Ý}ÁÉ•™¥à¤ì(€€€‘É…´¹•áÑ•¹‘}™É½µ}Í±¥” ™Á­Ð¤ì((€€€¥˜±•ÐM½µ”¡µ…á}±•¸¤€ô½¹¸¹‘É…µ}µ…á}ÝÉ¥Ñ…‰±•}±•¸ ¤ì(€€€€€€€¥˜‘É…´¹±•¸ ¤€øµ…á}±•¸ì(€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ (€€€€€€€€€€€€€€€€‰‘…Ñ…É…´Ñ½¼±…É”™½ÈÁ••È½Á…Ñ èíô€øíôì•¹•É…Ñ¥¹œ%5@A…­•ÐQ½¼	¥œ¥˜Á½ÍÍ¥‰±”ˆ°(€€€€€€€€€€€€€€€‘É…´¹±•¸ ¤°(€€€€€€€€€€€€€€€µ…á}±•¸(€€€€€€€€€€€€¤ì(€€€€€€€€€€€¥˜±•ÐM½µ”¡¥µÁ}Á­Ð¤€ô¥µÀèé½µÁ½Í•}¥µÁ}Ñ½½}±…É” ™Á­Ð°5%9}5QT¤ì(€€€€€€€€€€€€€€€±•Ð|€ô‘•Ø¹Í•¹‘}Á…­•Ð ™¥µÁ}Á­Ð¤¹…Ý…¥Ðì(€€€€€€€€€€€ô(€€€€€€€€€€€É•ÑÕÉ¸9½¹”ì(€€€€€€€ô(€€€ô((€€€M½µ”¡Qá…Ñ…É…´ì‰åÑ•Ìè‘É…´°¥Á}±•¸ô¤)ô()™¸ÅÕ•Õ•}Ñá}‘…Ñ…É…µÌ (€€€½¹¸è€™µÕÐÅÕ¥¡”èé½¹¹•Ñ¥½¸°(€€€Ñá}ÅÕ•Õ”è€™µÕÐY••ÅÕ”ñQá…Ñ…É…´ø°(€€€ÍÑ…ÑÌè€™ÉŒñMÑ…ÑÌø°(€€€Ñá}‰ÕÉÍÑ}Á…­•ÑÌèÕÍ¥é”°(¤€´øQáAÉ½É•ÍÌì(€€€±•ÐµÕÐÁÉ½É•ÍÌ€ôQáAÉ½É•ÍÌìÅÕ•Õ•è€À°‰…­ÁÉ•ÍÍÕÉ”è™…±Í”ôì(€€€±•Ð‰Õ‘•Ð€ôÑá}‰ÕÉÍÑ}Á…­•ÑÌ¹µ…à Ä¤ì((€€€Ý¡¥±”ÁÉ½É•ÍÌ¹ÅÕ•Õ•€ð‰Õ‘•Ðì(€€€€€€€±•ÐM½µ”¡¥Ñ•´¤€ôÑá}ÅÕ•Õ”¹Á½Á}™É½¹Ð ¤•±Í”ì(€€€€€€€€€€€‰É•…¬ì(€€€€€€€ôì((€€€€€€€¥˜±•ÐM½µ”¡µ…á}±•¸¤€ô½¹¸¹‘É…µ}µ…á}ÝÉ¥Ñ…‰±•}±•¸ ¤ì(€€€€€€€€€€€¥˜¥Ñ•´¹‰åÑ•Ì¹±•¸ ¤€øµ…á}±•¸ì(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ (€€€€€€€€€€€€€€€€€€€€‰‘É½ÁÁ¥¹œ•¹½‘•QI4Ñ¡…Ð•á••‘ÌÁ••È½Á…Ñ ÝÉ¥Ñ…‰±”±•¸èíô€øíôˆ°(€€€€€€€€€€€€€€€€€€€¥Ñ•´¹‰åÑ•Ì¹±•¸ ¤°(€€€€€€€€€€€€€€€€€€€µ…á}±•¸(€€€€€€€€€€€€€€€€¤ì(€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”ì(€€€€€€€€€€€ô(€€€€€€€ô((€€€€€€€€¼¼ÅÕ¥¡”èé½¹¹•Ñ¥½¸èé‘É…µ}Í•¹ ¤½Á¥•ÌÑ¡”QI4Á…å±½…¥¹Ñ¼(€€€€€€€€¼¼ÅÕ¥¡”Ì¥¹Ñ•É¹…°ÅÕ•Õ”¸]”…±É•…‘ä½Ý¸…¸•¹½‘•5MEU½ ÌQI4(€€€€€€€€¼¼Y•Œ…ÐÑ¡¥ÌÁ½¥¹Ð°Í¼ÕÍ”‘É…µ}Í•¹‘}‰Õ˜ ¤Ñ¼¡…¹½Ý¹•ÉÍ¡¥ÀÑ¼(€€€€€€€€¼¼ÅÕ¥¡”…¹…Ù½¥½¹”µ•µÁä½¸Ñ¡”ÕÁ±½…¡½ÐÁ…Ñ ¸Q¡¥Ìµ¥ÉÉ½ÉÌÑ¡”(€€€€€€€€¼¼é•É¼µ½ÁäQI4A$‘•ÍÉ¥‰•‰äÅÕ¥¡”¸(€€€€€€€¥˜½¹¸¹¥Í}‘É…µ}Í•¹‘}ÅÕ•Õ•}™Õ±° ¤ì(€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}‰…­ÁÉ•ÍÍÕÉ”¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€Ñá}ÅÕ•Õ”¹ÁÕÍ¡}™É½¹Ð¡¥Ñ•´¤ì(€€€€€€€€€€€ÁÉ½É•ÍÌ¹‰…­ÁÉ•ÍÍÕÉ”€ôÑÉÕ”ì(€€€€€€€€€€€‰É•…¬ì(€€€€€€€ô((€€€€€€€±•Ð¥Á}±•¸€ô¥Ñ•´¹¥Á}±•¸ì(€€€€€€€µ…Ñ ½¹¸¹‘É…µ}Í•¹‘}‰Õ˜¡¥Ñ•´¹‰åÑ•Ì¤ì(€€€€€€€€€€€=¬  ¤¤€ôøì(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}Á…­•ÑÌ¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}‰åÑ•Ì¹™•Ñ¡}…‘¡¥Á}±•¸…ÌÔØÐ°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€ÁÉ½É•ÍÌ¹ÅÕ•Õ•€¬ô€Äì(€€€€€€€€€€€ô(€€€€€€€€€€€ÉÈ¡ÅÕ¥¡”èéÉÉ½Èèé½¹”¤€ôøì(€€€€€€€€€€€€€€€€¼¼Q¡¥ÌÍ¡½Õ±‰”É…É”‰•…ÕÍ”Ý”¡•­•¥Í}‘É…µ}Í•¹‘}ÅÕ•Õ•}™Õ±° ¤(€€€€€€€€€€€€€€€€¼¼©ÕÍÐ…‰½Ù”¸‘É…µ}Í•¹‘}‰Õ˜ ¤½¹ÍÕµ•ÌÑ¡”‰Õ™™•È°Í¼Ý”…¹¹½Ð(€€€€€€€€€€€€€€€€¼¼Í…™•±äÉ•ÑÉäÑ¡”•á…ÐÍ…µ”½Ý¹•Y•Œ¡•É”¸½Õ¹Ð¥ÐÍ•Á…É…Ñ•±ä(€€€€€€€€€€€€€€€€¼¼…Ì‰½Ñ ‰…­ÁÉ•ÍÍÕÉ”…¹„‘É½ÀÍ¼¥Ð¥ÌÙ¥Í¥‰±”¥¸±½Ì¸(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}‰…­ÁÉ•ÍÍÕÉ”¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€ÁÉ½É•ÍÌ¹‰…­ÁÉ•ÍÍÕÉ”€ôÑÉÕ”ì(€€€€€€€€€€€€€€€‰É•…¬ì(€€€€€€€€€€€ô(€€€€€€€€€€€ÉÈ¡”¤€ôøì(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ ‰‘…Ñ…É…´Í•¹‘}‰Õ˜•ÉÉ½Èèí•ôì‘É½ÁÁ¥¹œ•¹½‘•QI4ˆ¤ì(€€€€€€€€€€€ô(€€€€€€€ô(€€€ô((€€€ÁÉ½É•ÍÌ)ô()™¸Á½±±} Ì¡½¹¸è€™µÕÐÅÕ¥¡”èé½¹¹•Ñ¥½¸° Í}½¹¸è€™µÕÐÅÕ¥¡”èé Ìèé½¹¹•Ñ¥½¸¤ì(€€€±½½Àì(€€€€€€€µ…Ñ  Í}½¹¸¹Á½±°¡½¹¸¤ì(€€€€€€€€€€€=¬¡|¤€ôøíô(€€€€€€€€€€€ÉÈ¡ÅÕ¥¡”èé ÌèéÉÉ½Èèé½¹”¤€ôø‰É•…¬°(€€€€€€€€€€€ÉÈ¡”¤€ôøì(€€€€€€€€€€€€€€€ÑÉ…¥¹œèéÝ…É¸„ ‰ ÌÁ½±°•ÉÉ½Èèí•ôˆ¤ì(€€€€€€€€€€€€€€€‰É•…¬ì(€€€€€€€€€€€ô(€€€€€€€ô(€€€ô)ô()…Íå¹Œ™¸‘É…¥¹}¥¹½µ¥¹}‘…Ñ…É…µÌ (€€€½¹¸è€™µÕÐÅÕ¥¡”èé½¹¹•Ñ¥½¸°(€€€™±½Ý}¥èÔØÐ°(€€€ÍÑ…ÑÌè€™ÉŒñMÑ…ÑÌø°(€€€‘•Øè€™ÉŒñQÕ¹IÍ•Ù¥”ø°(¤ì(€€€±½½Àì(€€€€€€€µ…Ñ ½¹¸¹‘É…µ}É•Ù}‰Õ˜ ¤ì(€€€€€€€€€€€=¬¡‘É…´¤€ôøì(€€€€€€€€€€€€€€€±•Ð‘É…µ}É•˜€ô‘É…´¹…Í}É•˜ ¤ì(€€€€€€€€€€€€€€€¥˜±•ÐM½µ”¡¥Á}Á…å±½…¤€ôÁ…ÉÍ•}‘…Ñ…É…´¡‘É…µ}É•˜°™±½Ý}¥¤ì(€€€€€€€€€€€€€€€€€€€¥˜Á…­•ÐèéÙ…±¥‘…Ñ•}¥¹½µ¥¹œ¡¥Á}Á…å±½…¤¹¥Í}½¬ ¤ì(€€€€€€€€€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Éá}Á…­•ÑÌ¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Éá}‰åÑ•Ì¹™•Ñ¡}…‘¡¥Á}Á…å±½…¹±•¸ ¤…ÌÔØÐ°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€€€€€€€€€¥˜±•ÐÉÈ¡•ÉÈ¤€ô‘•Ø¹Í•¹‘}Á…­•Ð¡¥Á}Á…å±½…¤¹…Ý…¥Ðì(€€€€€€€€€€€€€€€€€€€€€€€€€€€ÑÉ…¥¹œèéÝ…É¸„ ‰™…¥±•Ñ¼ÝÉ¥Ñ”É••¥Ù•Á…­•ÐÑ¼QU8èí•ÉÈèôˆ¤ì(€€€€€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€ô(€€€€€€€€€€€ô(€€€€€€€€€€€ÉÈ¡ÅÕ¥¡”èéÉÉ½Èèé½¹”¤€ôø‰É•…¬°(€€€€€€€€€€€ÉÈ¡”¤€ôøì(€€€€€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ ‰‘…Ñ…É…´É•Ø•ÉÉ½Èèí•ôˆ¤ì(€€€€€€€€€€€€€€€‰É•…¬ì(€€€€€€€€€€€ô(€€€€€€€ô(€€€ô)ô()…Íå¹Œ™¸Í•¹‘}Á…­•Ñ}‘…Ñ…É…´ (€€€Í½­•Ðè€™Ñ½­¥¼èé¹•ÐèéU‘ÁM½­•Ð°(€€€•¹‘Á½¥¹ÐèM½­•Ñ‘‘È°(€€€±½…±}…‘‘ÈèM½­•Ñ‘‘È°(€€€½¹¸è€™µÕÐÅÕ¥¡”èé½¹¹•Ñ¥½¸°(€€€™±½Ý}ÁÉ•™¥àè€™mÔát°(€€€Á­Ðè€™µÕÐmÔát°(€€€ÍÑ…ÑÌè€™ÉŒñMÑ…ÑÌø°(€€€‘•Øè€™ÉŒñQÕ¹IÍ•Ù¥”ø°(€€€‰Õ˜è€™µÕÐmÔát°(€€€½ÕÐè€™µÕÐmÔát°(¤€´øI•ÍÕ±Ðð ¤øì(€€€µ…Ñ Á…­•ÐèéÁÉ•Á…É•}½ÕÑ½¥¹œ¡Á­Ð¤ì(€€€€€€€=¬¡|¤€ôøì(€€€€€€€€€€€±•ÐÁ­Ñ}±•¸€ôÁ­Ð¹±•¸ ¤…ÌÔØÐì(€€€€€€€€€€€±•ÐµÕÐ‘É…´€ôY•ŒèéÝ¥Ñ¡}…Á…¥Ñä¡™±½Ý}ÁÉ•™¥à¹±•¸ ¤€¬Á­Ð¹±•¸ ¤¤ì(€€€€€€€€€€€‘É…´¹•áÑ•¹‘}™É½µ}Í±¥”¡™±½Ý}ÁÉ•™¥à¤ì(€€€€€€€€€€€‘É…´¹•áÑ•¹‘}™É½µ}Í±¥”¡Á­Ð¤ì((€€€€€€€€€€€¥˜±•ÐM½µ”¡µ…á}±•¸¤€ô½¹¸¹‘É…µ}µ…á}ÝÉ¥Ñ…‰±•}±•¸ ¤ì(€€€€€€€€€€€€€€€¥˜‘É…´¹±•¸ ¤€øµ…á}±•¸ì(€€€€€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ (€€€€€€€€€€€€€€€€€€€€€€€€‰‘…Ñ…É…´Ñ½¼±…É”™½ÈÁ••È½Á…Ñ èíô€øíôì•¹•É…Ñ¥¹œ%5@A…­•ÐQ½¼	¥œ¥˜Á½ÍÍ¥‰±”ˆ°(€€€€€€€€€€€€€€€€€€€€€€€‘É…´¹±•¸ ¤°(€€€€€€€€€€€€€€€€€€€€€€€µ…á}±•¸(€€€€€€€€€€€€€€€€€€€€¤ì(€€€€€€€€€€€€€€€€€€€¥˜±•ÐM½µ”¡¥µÁ}Á­Ð¤€ô¥µÀèé½µÁ½Í•}¥µÁ}Ñ½½}±…É”¡Á­Ð°5%9}5QT¤ì(€€€€€€€€€€€€€€€€€€€€€€€±•Ð|€ô‘•Ø¹Í•¹‘}Á…­•Ð ™¥µÁ}Á­Ð¤¹…Ý…¥Ðì(€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€€€€€É•ÑÕÉ¸=¬  ¤¤ì(€€€€€€€€€€€€€€€ô(€€€€€€€€€€€ô((€€€€€€€€€€€€¼¼5¥¸µ½ÁäÁ•¹‘¥¹œµÁ…­•ÐÁ…Ñ èÑ¡”ÍÑ•…‘äµÍÑ…Ñ”QU8É•…‘•È…±É•…‘ä(€€€€€€€€€€€€¼¼¡…¹‘ÌÑ¡”•¹½‘•QI4Y•ŒÑ¼ÅÕ¥¡”Ý¥Ñ ‘É…µ}Í•¹ ¤¸(€€€€€€€€€€€€¼¼Q¡¥ÌÁ…Ñ ¥ÌÕÍ•½¹±ä™½ÈÑ¡”Í¥¹±”Á…­•Ð…ÁÑÕÉ•Ý¡¥±”Ý…¥Ñ¥¹œ(€€€€€€€€€€€€¼¼™½ÈÉ•½¹¹•Ð°‰ÕÐ­••À¥Ð½Áäµµ¥¹¥µ…°…ÌÝ•±°¸‘É…µ}Í•¹‘}‰Õ˜ ¤(€€€€€€€€€€€€¼¼Ñ…­•Ì½Ý¹•ÉÍ¡¥À…¹…Ù½¥‘ÌÅÕ¥¡”Ì¥¹Ñ•É¹…°QI4Á…å±½…½Áä¸(€€€€€€€€€€€™½È…ÑÑ•µÁÐ¥¸€À¸¸ÔÄÉÔÄØì(€€€€€€€€€€€€€€€¥˜€…½¹¸¹¥Í}‘É…µ}Í•¹‘}ÅÕ•Õ•}™Õ±° ¤ì(€€€€€€€€€€€€€€€€€€€µ…Ñ ½¹¸¹‘É…µ}Í•¹‘}‰Õ˜¡‘É…´¤ì(€€€€€€€€€€€€€€€€€€€€€€€=¬  ¤¤€ôøì(€€€€€€€€€€€€€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}Á…­•ÑÌ¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}‰åÑ•Ì¹™•Ñ¡}…‘¡Á­Ñ}±•¸°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€€€€€€€€€€€€€É•ÑÕÉ¸=¬  ¤¤ì(€€€€€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€€€€€€€€€ÉÈ¡”¤€ôøì(€€€€€€€€€€€€€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€€€€€€€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ ‰‘…Ñ…É…´Í•¹‘}‰Õ˜•ÉÉ½Èèí•ôì•¹•É…Ñ¥¹œ%5@A…­•ÐQ½¼	¥œ¥˜Á½ÍÍ¥‰±”ˆ¤ì(€€€€€€€€€€€€€€€€€€€€€€€€€€€¥˜±•ÐM½µ”¡¥µÁ}Á­Ð¤€ô¥µÀèé½µÁ½Í•}¥µÁ}Ñ½½}±…É”¡Á­Ð°5%9}5QT¤ì(€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€±•Ð|€ô‘•Ø¹Í•¹‘}Á…­•Ð ™¥µÁ}Á­Ð¤¹…Ý…¥Ðì(€€€€€€€€€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€€€€€€€€€€€€€É•ÑÕÉ¸=¬  ¤¤ì(€€€€€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€ô((€€€€€€€€€€€€€€€™±ÕÍ¡}ÅÕ¥Œ¡Í½­•Ð°½¹¸°½ÕÐ¤¹…Ý…¥Ðüì(€€€€€€€€€€€€€€€‘É…¥¹}Õ‘Á}¹½¹‰±½­¥¹œ¡Í½­•Ð°•¹‘Á½¥¹Ð°±½…±}…‘‘È°½¹¸°‰Õ˜¤ì((€€€€€€€€€€€€€€€¥˜½¹¸¹¥Í}±½Í• ¤ì(€€€€€€€€€€€€€€€€€€€‰…¥°„ ‰EU%½¹¹•Ñ¥½¸±½Í•Ý¡¥±”Ý…¥Ñ¥¹œ™½ÈQI4ÅÕ•Õ”ÍÁ…”ˆ¤ì(€€€€€€€€€€€€€€€ô((€€€€€€€€€€€€€€€±•ÐÝ…¥Ð€ô½¹¸(€€€€€€€€€€€€€€€€€€€€¹Ñ¥µ•½ÕÐ ¤(€€€€€€€€€€€€€€€€€€€€¹Õ¹ÝÉ…Á}½È¡ÕÉ…Ñ¥½¸èé™É½µ}µ¥±±¥Ì Ä¤¤(€€€€€€€€€€€€€€€€€€€€¹µ¥¸¡ÕÉ…Ñ¥½¸èé™É½µ}µ¥±±¥Ì È¤¤ì(€€€€€€€€€€€€€€€Ñ½­¥¼èéÍ•±•Ð„ì(€€€€€€€€€€€€€€€€€€€É•ÍÕ±Ð€ôÍ½­•Ð¹É•Ø¡‰Õ˜¤€ôøì(€€€€€€€€€€€€€€€€€€€€€€€±•Ð±•¸€ôÉ•ÍÕ±Ðüì(€€€€€€€€€€€€€€€€€€€€€€€±•ÐÉ•Ù}¥¹™¼€ôÅÕ¥¡”èéI•Ù%¹™¼ìÑ¼è±½…±}…‘‘È°™É½´è•¹‘Á½¥¹Ðôì(€€€€€€€€€€€€€€€€€€€€€€€¥˜±•ÐÉÈ¡”¤€ô½¹¸¹É•Ø ™µÕÐ‰Õ™l¸¹±•¹t°É•Ù}¥¹™¼¤ì(€€€€€€€€€€€€€€€€€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ ‰EU%É•ØÝ¡¥±”…ÁÁ±å¥¹œQI4‰…­ÁÉ•ÍÍÕÉ”™…¥±•èí•ôˆ¤ì(€€€€€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€€€€€€ ¤€ôÑ½­¥¼èéÑ¥µ”èéÍ±••À¡Ý…¥Ð¤€ôø½¹¸¹½¹}Ñ¥µ•½ÕÐ ¤°(€€€€€€€€€€€€€€€ô((€€€€€€€€€€€€€€€¥˜…ÑÑ•µÁÐ€ø€À€˜˜…ÑÑ•µÁÐ€”€ØÐ€ôô€Àì(€€€€€€€€€€€€€€€€€€€ÑÉ…¥¹œèéÑÉ…”„ (€€€€€€€€€€€€€€€€€€€€€€€€‰Ý…¥Ñ¥¹œ™½ÈQI4ÅÕ•Õ”ÍÁ…”è…ÑÑ•µÁÐõíôÅÕ•Õ•}±•¸õíôÅÕ•Õ•}‰åÑ•Ìõíôˆ°(€€€€€€€€€€€€€€€€€€€€€€€…ÑÑ•µÁÐ°(€€€€€€€€€€€€€€€€€€€€€€€½¹¸¹‘É…µ}Í•¹‘}ÅÕ•Õ•}±•¸ ¤°(€€€€€€€€€€€€€€€€€€€€€€€½¹¸¹‘É…µ}Í•¹‘}ÅÕ•Õ•}‰åÑ•}Í¥é” ¤(€€€€€€€€€€€€€€€€€€€€¤ì(€€€€€€€€€€€€€€€ô(€€€€€€€€€€€ô((€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€ÑÉ…¥¹œèéÑÉ…”„ ‰‘…Ñ…É…´Í•¹ÅÕ•Õ”ÍÑ…å•™Õ±°…™Ñ•È‰…­ÁÉ•ÍÍÕÉ”É•ÑÉ¥•Ì°‘É½ÁÁ¥¹œÁ…­•Ðˆ¤ì(€€€€€€€€€€€=¬  ¤¤(€€€€€€€ô(€€€€€€€ÉÈ¡”¤€ôøì(€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹™•Ñ¡}…‘ Ä°=É‘•É¥¹œèéI•±…á•¤ì(€€€€€€€€€€€ÑÉ…¥¹œèéÑÉ…”„ ‰‘É½ÁÁ¥¹œ½ÕÑ½¥¹œÁ…­•Ðèí•ôˆ¤ì(€€€€€€€€€€€=¬  ¤¤(€€€€€€€ô(€€€ô)ô()™¸‘É…¥¹}Õ‘Á}¹½¹‰±½­¥¹œ (€€€Í½­•Ðè€™Ñ½­¥¼èé¹•ÐèéU‘ÁM½­•Ð°(€€€•¹‘Á½¥¹ÐèM½­•Ñ‘‘È°(€€€±½…±}…‘‘ÈèM½­•Ñ‘‘È°(€€€½¹¸è€™µÕÐÅÕ¥¡”èé½¹¹•Ñ¥½¸°(€€€‰Õ˜è€™µÕÐmÔát°(¤€´ø‰½½°ì(€€€±•ÐµÕÐÉ••¥Ù•€ô™…±Í”ì(€€€Ý¡¥±”±•Ð=¬¡±•¸¤€ôÍ½­•Ð¹ÑÉå}É•Ø¡‰Õ˜¤ì(€€€€€€€É••¥Ù•€ôÑÉÕ”ì(€€€€€€€±•ÐÉ•Ù}¥¹™¼€ôÅÕ¥¡”èéI•Ù%¹™¼ìÑ¼è±½…±}…‘‘È°™É½´è•¹‘Á½¥¹Ðôì(€€€€€€€¥˜±•ÐÉÈ¡”¤€ô½¹¸¹É•Ø ™µÕÐ‰Õ™l¸¹±•¹t°É•Ù}¥¹™¼¤ì(€€€€€€€€€€€ÑÉ…¥¹œèé‘•‰Õœ„ ‰EU%É•Ø•ÉÉ½ÈÝ¡¥±”‘É…¥¹¥¹œU@èí•ôˆ¤ì(€€€€€€€ô(€€€ô(€€€É••¥Ù•)ô()…Íå¹Œ™¸™±ÕÍ¡}ÅÕ¥Œ (€€€Í½­•Ðè€™Ñ½­¥¼èé¹•ÐèéU‘ÁM½­•Ð°(€€€½¹¸è€™µÕÐÅÕ¥¡”èé½¹¹•Ñ¥½¸°(€€€½ÕÐè€™µÕÐmÔát°(¤€´øI•ÍÕ±Ðð ¤øì(€€€±½½Àì(€€€€€€€µ…Ñ ½¹¸¹Í•¹¡½ÕÐ¤ì(€€€€€€€€€€€=¬ ¡ÝÉ¥Ñ”°Í•¹‘}¥¹™¼¤¤€ôøì(€€€€€€€€€€€€€€€±•Ð|€ôÍ•¹‘}¥¹™¼ì(€€€€€€€€€€€€€€€Í½­•Ð¹Í•¹ ™½ÕÑl¸¹ÝÉ¥Ñ•t¤¹…Ý…¥Ðüì(€€€€€€€€€€€ô(€€€€€€€€€€€ÉÈ¡ÅÕ¥¡”èéÉÉ½Èèé½¹”¤€ôø‰É•…¬°(€€€€€€€€€€€ÉÈ¡”¤€ôø‰…¥°„ ‰ÅÕ¥ŒÍ•¹•ÉÉ½Èèí•ôˆ¤°(€€€€€€€ô(€€€ô(€€€=¬  ¤¤)ô()™¸‰Õ¥±‘}™±½Ý}ÁÉ•™¥à¡™±½Ý}¥èÔØÐ¤€´øI•ÍÕ±ÐñY•ŒñÔàøøì(€€€±•ÐµÕÐÑµÀ€ôlÁÔàì€átì(€€€±•ÐµÕÐˆ€ô=Ñ•ÑÍ5ÕÐèéÝ¥Ñ¡}Í±¥” ™µÕÐÑµÀ¤ì(€€€ˆ¹ÁÕÑ}Ù…É¥¹Ð¡™±½Ý}¥¤¹µ…Á}•ÉÈ¡ñ•ð…¹å¡½Ü„ ‰•¹½‘”™±½Ý}¥Ù…É¥¹Ðèí•ôˆ¤¤üì(€€€±•Ð±•¸€ôˆ¹½™˜ ¤ì(€€€±•ÐµÕÐ™±½Ý}ÁÉ•™¥à€ôY•ŒèéÝ¥Ñ¡}…Á…¥Ñä¡±•¸€¬€Ä¤ì(€€€™±½Ý}ÁÉ•™¥à¹•áÑ•¹‘}™É½µ}Í±¥” ™ÑµÁl¸¹±•¹t¤ì(€€€™±½Ý}ÁÉ•™¥à¹ÁÕÍ  ÁàÀÀ¤ì(€€€=¬¡™±½Ý}ÁÉ•™¥à¤)ô()™¸Á…ÉÍ•}‘…Ñ…É…´¡‘É…´è€™mÔát°•áÁ•Ñ•‘}™±½Ý}¥èÔØÐ¤€´ø=ÁÑ¥½¸ð™mÔátøì(€€€±•ÐµÕÐˆ€ô=Ñ•ÑÌèéÝ¥Ñ¡}Í±¥”¡‘É…´¤ì(€€€±•Ð™±½Ý}¥€ôˆ¹•Ñ}Ù…É¥¹Ð ¤¹½¬ ¤üì(€€€¥˜™±½Ý}¥€„ô•áÁ•Ñ•‘}™±½Ý}¥ì(€€€€€€€É•ÑÕÉ¸9½¹”ì(€€€ô(€€€±•Ð½¹Ñ•áÑ}¥€ôˆ¹•Ñ}Ù…É¥¹Ð ¤¹½¬ ¤üì(€€€¥˜½¹Ñ•áÑ}¥€„ô€Àì(€€€€€€€É•ÑÕÉ¸9½¹”ì(€€€ô(€€€±•Ð½™˜€ôˆ¹½™˜ ¤ì(€€€¥˜½™˜€øô‘É…´¹±•¸ ¤ì(€€€€€€€É•ÑÕÉ¸9½¹”ì(€€€ô(€€€M½µ” ™‘É…µm½™˜¸¹t¤)ô()™¸­••Á…±¥Ù•}É•µ…¥¹¥¹œ¡Á•É¥½èÕÉ…Ñ¥½¸°¥‘±•}™½ÈèÕÉ…Ñ¥½¸¤€´ø=ÁÑ¥½¸ñÕÉ…Ñ¥½¸øì(€€€¥˜Á•É¥½¹¥Í}é•É¼ ¤ì(€€€€€€€9½¹”(€€€ô•±Í”ì(€€€€€€€M½µ”¡Á•É¥½¹Í…ÑÕÉ…Ñ¥¹}ÍÕˆ¡¥‘±•}™½È¤¤(€€€ô)ô()™¸ÍÁ…Ý¹}ÍÑ…ÑÍ}Ñ…Í¬¡ÍÑ…ÑÌèÉŒñMÑ…ÑÌø°ÍÑ…ÉÐè%¹ÍÑ…¹Ð¤€´øÑ½­¥¼èéÑ…Í¬èé)½¥¹!…¹‘±”ð ¤øì(€€€Ñ½­¥¼èéÍÁ…Ý¸¡…Íå¹Œµ½Ù”ì(€€€€€€€±•ÐµÕÐ¥¹Ñ•ÉÙ…°€ôÑ½­¥¼èéÑ¥µ”èé¥¹Ñ•ÉÙ…°¡ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ÄÀ¤¤ì(€€€€€€€±½½Àì(€€€€€€€€€€€¥¹Ñ•ÉÙ…°¹Ñ¥¬ ¤¹…Ý…¥Ðì(€€€€€€€€€€€ÑÉ…¥¹œèé¥¹™¼„ (€€€€€€€€€€€€€€€€‰½¹¹•Ñ•õíôÑàõíô€¡íô¤Éàõíô€¡íô¤‘É½ÀõíôÑáÄõíô‰Àõíô±½ÍÐõíôÉ•ÑÉ…¹Ìõíôˆ°(€€€€€€€€€€€€€€€™½Éµ…Ñ}‘ÕÉ…Ñ¥½¸¡ÍÑ…ÉÐ¹•±…ÁÍ• ¤¤°(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}Á…­•ÑÌ¹±½…¡=É‘•É¥¹œèéI•±…á•¤°(€€€€€€€€€€€€€€€™½Éµ…Ñ}‰åÑ•Ì¡ÍÑ…ÑÌ¹Ñá}‰åÑ•Ì¹±½…¡=É‘•É¥¹œèéI•±…á•¤¤°(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Éá}Á…­•ÑÌ¹±½…¡=É‘•É¥¹œèéI•±…á•¤°(€€€€€€€€€€€€€€€™½Éµ…Ñ}‰åÑ•Ì¡ÍÑ…ÑÌ¹Éá}‰åÑ•Ì¹±½…¡=É‘•É¥¹œèéI•±…á•¤¤°(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹‘É½ÁÁ•¹±½…¡=É‘•É¥¹œèéI•±…á•¤°(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}ÅÕ•Õ•}±•¸¹±½…¡=É‘•É¥¹œèéI•±…á•¤°(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹Ñá}‰…­ÁÉ•ÍÍÕÉ”¹±½…¡=É‘•É¥¹œèéI•±…á•¤°(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹ÅÕ¥}±½ÍÐ¹±½…¡=É‘•É¥¹œèéI•±…á•¤°(€€€€€€€€€€€€€€€ÍÑ…ÑÌ¹ÅÕ¥}É•ÑÉ…¹Ì¹±½…¡=É‘•É¥¹œèéI•±…á•¤°(€€€€€€€€€€€€¤ì(€€€€€€€ô(€€€ô¤)ô()™¸™½Éµ…Ñ}‰åÑ•Ì¡‰åÑ•ÌèÔØÐ¤€´øMÑÉ¥¹œì(€€€½¹ÍÐ-%èÔØÐ€ô€ÄÀÈÐì(€€€½¹ÍÐ5%èÔØÐ€ô€ÄÀÈÐ€¨-%ì(€€€½¹ÍÐ%èÔØÐ€ô€ÄÀÈÐ€¨5%ì(€€€¥˜‰åÑ•Ì€øô%ì(€€€€€€€™½Éµ…Ð„ ‰ìè¸Åô¥ˆ°‰åÑ•Ì…Ì˜ØÐ€¼%…Ì˜ØÐ¤(€€€ô•±Í”¥˜‰åÑ•Ì€øô5%ì(€€€€€€€™½Éµ…Ð„ ‰ìè¸Åô5¥ˆ°‰åÑ•Ì…Ì˜ØÐ€¼5%…Ì˜ØÐ¤(€€€ô•±Í”¥˜‰åÑ•Ì€øô-%ì(€€€€€€€™½Éµ…Ð„ ‰ìè¸Åô-¥ˆ°‰åÑ•Ì…Ì˜ØÐ€¼-%…Ì˜ØÐ¤(€€€ô•±Í”ì(€€€€€€€™½Éµ…Ð„ ‰í‰åÑ•Íôˆ¤(€€€ô)ô()™¸™½Éµ…Ñ}‘ÕÉ…Ñ¥½¸¡èÕÉ…Ñ¥½¸¤€´øMÑÉ¥¹œì(€€€±•ÐÍ•Ì€ô¹…Í}Í•Ì ¤ì(€€€¥˜Í•Ì€ð€ØÀì(€€€€€€€™½Éµ…Ð„ ‰íÍ•ÍõÌˆ¤(€€€ô•±Í”¥˜Í•Ì€ð€ÌØÀÀì(€€€€€€€™½Éµ…Ð„ ‰íõ´ìèÀÉõÌˆ°Í•Ì€¼€ØÀ°Í•Ì€”€ØÀ¤(€€€ô•±Í”ì(€€€€€€€™½Éµ…Ð„ ‰íõ ìèÀÉõ´ìèÀÉõÌˆ°Í•Ì€¼€ÌØÀÀ°€¡Í•Ì€”€ÌØÀÀ¤€¼€ØÀ°Í•Ì€”€ØÀ¤(€€€ô)ô((m™œ¡Ñ•ÍÐ¥t)µ½Ñ•ÍÑÌì(€€€ÕÍ”ÍÕÁ•Èèè¨ì((€€€€mÑ•ÍÑt(€€€™¸­••Á…±¥Ù•}…¹}‰•}‘¥Í…‰±• ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€­••Á…±¥Ù•}É•µ…¥¹¥¹œ¡ÕÉ…Ñ¥½¸èéiI<°ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ØÀ¤¤°(€€€€€€€€€€€9½¹”(€€€€€€€€¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸­••Á…±¥Ù•}Ý…¥ÑÍ}½¹±å}™½É}É•µ…¥¹¥¹}¥‘±•}Ñ¥µ” ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€­••Á…±¥Ù•}É•µ…¥¹¥¹œ¡ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ÈÔ¤°ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ÄÀ¤¤°(€€€€€€€€€€€M½µ”¡ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ÄÔ¤¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€­••Á…±¥Ù•}É•µ…¥¹¥¹œ¡ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ÈÔ¤°ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ÈÔ¤¤°(€€€€€€€€€€€M½µ”¡ÕÉ…Ñ¥½¸èéiI<¤(€€€€€€€€¤ì(€€€ô((€€€™¸•¹½‘•}Ù…É¥¹Ð¡Ù…°èÔØÐ¤€´øY•ŒñÔàøì(€€€€€€€±•ÐµÕÐÑµÀ€ôlÁÔàì€átì(€€€€€€€±•ÐµÕÐˆ€ô=Ñ•ÑÍ5ÕÐèéÝ¥Ñ¡}Í±¥” ™µÕÐÑµÀ¤ì(€€€€€€€ˆ¹ÁÕÑ}Ù…É¥¹Ð¡Ù…°¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€ÑµÁl¸¹ˆ¹½™˜ ¥t¹Ñ½}Ù•Œ ¤(€€€ô((€€€€mÑ•ÍÑt(€€€™¸Á…ÉÍ•}‘…Ñ…É…µ}Ù…±¥ ¤ì(€€€€€€€±•ÐµÕÐ€ô•¹½‘•}Ù…É¥¹Ð Ð¤ì(€€€€€€€¹•áÑ•¹‘}™É½µ}Í±¥” ™•¹½‘•}Ù…É¥¹Ð À¤¤ì(€€€€€€€¹•áÑ•¹‘}™É½µ}Í±¥”¡ˆ‰Á…å±½…ˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Á…ÉÍ•}‘…Ñ…É…´ ™°€Ð¤°M½µ”¡ˆ‰Á…å±½…ˆ¹…Í}É•˜ ¤¤¤ì(€€€ô)ô