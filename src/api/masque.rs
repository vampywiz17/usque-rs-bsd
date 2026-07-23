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

    let mut h3_config = quiche::h3::Config::new().map_err(|e| any…2262 tokens truncated….push_back(tx_dgram);
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        tun_reader_closed = true;
                        break;
                    }
                }
            }

            let progress = queue_tx_datagrams(conn, &mut tx_queue, stats, tx_burst_packets);
            if progress.queued > 0 {
                flush_quic(socket, conn, out).await?;
            } else if progress.backpressure {
                // Quiche's DATAGRAM queue is full. Push already-queued QUIC packets
                // out to UDP and then wait for ACKs/timers instead of burning CPU.
                flush_quic(socket, conn, out).await?;
            }

            stats.tx_queue_len.store(tx_queue.len() as u64, Ordering::Relaxed);
            let qs = conn.stats();
            stats.quic_lost.store(qs.lost as u64, Ordering::Relaxed);
            stats.quic_retrans.store(qs.retrans as u64, Ordering::Relaxed);

            if conn.is_closed() {
                bail!("QUIC connection closed");
            }
            if tun_reader_closed && tx_queue.is_empty() {
                bail!("TUN reader ended");
            }

            // If we still have queued DATAGRAMs and quiche accepted a full burst,
            // continue immediately. This batches upload traffic without the naive
            // per-packet sleep that hurt throughput in the pacing build.
            if !tx_queue.is_empty() && progress.queued >= tx_burst_packets && !progress.backpressure {
                continue;
            }

            let timeout = conn.timeout().unwrap_or(keepalive_period).min(keepalive_period);
            tokio::select! {
                biased;
                result = socket.recv(buf) => {
                    let len = result?;
                    let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                    if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                        tracing::debug!("QUIC recv error: {e}");
                    }
                }
                maybe_tx_dgram = tx_rx.recv(), if !tun_reader_closed && tx_queue.len() < tx_queue_len => {
                    match maybe_tx_dgram {
                        Some(tx_dgram) => {
                            tx_queue.push_back(tx_dgram);
                        }
                        None => tun_reader_closed = true,
                    }
                }
                () = tokio::time::sleep(timeout) => conn.on_timeout(),
            }
        }
    }
    .await;

    tun_reader.abort();
    result
}

async fn build_tx_datagram(
    conn: &quiche::Connection,
    flow_prefix: &[u8],
    mut pkt: Vec<u8>,
    stats: &Arc<Stats>,
    dev: &Arc<TunRsDevice>,
) -> Option<TxDatagram> {
    if let Err(e) = packet::prepare_outgoing(&mut pkt) {
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        tracing::trace!("dropping outgoing packet: {e}");
        return None;
    }

    let ip_len = pkt.len();
    let mut dgram = Vec::with_capacity(flow_prefix.len() + ip_len);
    dgram.extend_from_slice(flow_prefix);
    dgram.extend_from_slice(&pkt);

    if let Some(max_len) = conn.dgram_max_writable_len() {
        if dgram.len() > max_len {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                "datagram too large for peer/path: {} > {}; generating ICMP Packet Too Big if possible",
                dgram.len(),
                max_len
            );
            if let Some(icmp_pkt) = icmp::compose_icmp_too_large(&pkt, MIN_MTU) {
                let _ = dev.send_packet(&icmp_pkt).await;
            }
            return None;
        }
    }

    Some(TxDatagram { bytes: dgram, ip_len })
}

fn queue_tx_datagrams(
    conn: &mut quiche::Connection,
    tx_queue: &mut VecDeque<TxDatagram>,
    stats: &Arc<Stats>,
    tx_burst_packets: usize,
) -> TxProgress {
    let mut progress = TxProgress { queued: 0, backpressure: false };
    let budget = tx_burst_packets.max(1);

    while progress.queued < budget {
        let Some(item) = tx_queue.pop_front() else {
            break;
        };

        if let Some(max_len) = conn.dgram_max_writable_len() {
            if item.bytes.len() > max_len {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    "dropping encoded DATAGRAM that exceeds peer/path writable len: {} > {}",
                    item.bytes.len(),
                    max_len
                );
                continue;
            }
        }

        // quiche::Connection::dgram_send() copies the DATAGRAM payload into
        // quiche's internal queue. We already own an encoded MASQUE/H3 DATAGRAM
        // Vec at this point, so use dgram_send_buf() to hand ownership to
        // quiche and avoid one memcpy on the upload hot path. This mirrors the
        // zero-copy DATAGRAM API described by quiche.
        if conn.is_dgram_send_queue_full() {
            stats.tx_backpressure.fetch_add(1, Ordering::Relaxed);
            tx_queue.push_front(item);
            progress.backpressure = true;
            break;
        }

        let ip_len = item.ip_len;
        match conn.dgram_send_buf(item.bytes) {
            Ok(()) => {
                stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                stats.tx_bytes.fetch_add(ip_len as u64, Ordering::Relaxed);
                progress.queued += 1;
            }
            Err(quiche::Error::Done) => {
                // This should be rare because we checked is_dgram_send_queue_full()
                // just above. dgram_send_buf() consumes the buffer, so we cannot
                // safely retry the exact same owned Vec here. Count it separately
                // as both backpressure and a drop so it is visible in logs.
                stats.tx_backpressure.fetch_add(1, Ordering::Relaxed);
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                progress.backpressure = true;
                break;
            }
            Err(e) => {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("datagram send_buf error: {e}; dropping encoded DATAGRAM");
            }
        }
    }

    progress
}

fn poll_h3(conn: &mut quiche::Connection, h3_conn: &mut quiche::h3::Connection) {
    loop {
        match h3_conn.poll(conn) {
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(e) => {
                tracing::warn!("h3 poll error: {e}");
                break;
            }
        }
    }
}

async fn drain_incoming_datagrams(
    conn: &mut quiche::Connection,
    flow_id: u64,
    stats: &Arc<Stats>,
    dev: &Arc<TunRsDevice>,
) {
    loop {
        match conn.dgram_recv_buf() {
            Ok(dgram) => {
                let dgram_ref = dgram.as_ref();
                if let Some(ip_payload) = parse_datagram(dgram_ref, flow_id) {
                    if packet::validate_incoming(ip_payload).is_ok() {
                        stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                        stats.rx_bytes.fetch_add(ip_payload.len() as u64, Ordering::Relaxed);
                        if let Err(err) = dev.send_packet(ip_payload).await {
                            tracing::warn!("failed to write received packet to TUN: {err:#}");
                        }
                    }
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                tracing::debug!("datagram recv error: {e}");
                break;
            }
        }
    }
}

async fn send_packet_datagram(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    local_addr: SocketAddr,
    conn: &mut quiche::Connection,
    flow_prefix: &[u8],
    pkt: &mut [u8],
    stats: &Arc<Stats>,
    dev: &Arc<TunRsDevice>,
    buf: &mut [u8],
    out: &mut [u8],
) -> Result<()> {
    match packet::prepare_outgoing(pkt) {
        Ok(_) => {
            let pkt_len = pkt.len() as u64;
            let mut dgram = Vec::with_capacity(flow_prefix.len() + pkt.len());
            dgram.extend_from_slice(flow_prefix);
            dgram.extend_from_slice(pkt);

            if let Some(max_len) = conn.dgram_max_writable_len() {
                if dgram.len() > max_len {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        "datagram too large for peer/path: {} > {}; generating ICMP Packet Too Big if possible",
                        dgram.len(),
                        max_len
                    );
                    if let Some(icmp_pkt) = icmp::compose_icmp_too_large(pkt, MIN_MTU) {
                        let _ = dev.send_packet(&icmp_pkt).await;
                    }
                    return Ok(());
                }
            }

            // Min-copy pending-packet path: the steady-state TUN reader already
            // hands the encoded DATAGRAM Vec to quiche with dgram_send().
            // This path is used only for the single packet captured while waiting
            // for reconnect, but keep it copy-minimal as well. dgram_send_buf()
            // takes ownership and avoids quiche's internal DATAGRAM payload copy.
            for attempt in 0..512u16 {
                if !conn.is_dgram_send_queue_full() {
                    match conn.dgram_send_buf(dgram) {
                        Ok(()) => {
                            stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                            stats.tx_bytes.fetch_add(pkt_len, Ordering::Relaxed);
                            return Ok(());
                        }
                        Err(e) => {
                            stats.dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!("datagram send_buf error: {e}; generating ICMP Packet Too Big if possible");
                            if let Some(icmp_pkt) = icmp::compose_icmp_too_large(pkt, MIN_MTU) {
                                let _ = dev.send_packet(&icmp_pkt).await;
                            }
                            return Ok(());
                        }
                    }
                }

                flush_quic(socket, conn, out).await?;
                drain_udp_nonblocking(socket, endpoint, local_addr, conn, buf);

                if conn.is_closed() {
                    bail!("QUIC connection closed while waiting for DATAGRAM queue space");
                }

                let wait = conn
                    .timeout()
                    .unwrap_or(Duration::from_millis(1))
                    .min(Duration::from_millis(2));
                tokio::select! {
                    result = socket.recv(buf) => {
                        let len = result?;
                        let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                        if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                            tracing::debug!("QUIC recv while applying DATAGRAM backpressure failed: {e}");
                        }
                    }
                    () = tokio::time::sleep(wait) => conn.on_timeout(),
                }

                if attempt > 0 && attempt % 64 == 0 {
                    tracing::trace!(
                        "waiting for DATAGRAM queue space: attempt={} queue_len={} queue_bytes={}",
                        attempt,
                        conn.dgram_send_queue_len(),
                        conn.dgram_send_queue_byte_size()
                    );
                }
            }

            stats.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::trace!("datagram send queue stayed full after backpressure retries, dropping packet");
            Ok(())
        }
        Err(e) => {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::trace!("dropping outgoing packet: {e}");
            Ok(())
        }
    }
}

fn drain_udp_nonblocking(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    local_addr: SocketAddr,
    conn: &mut quiche::Connection,
    buf: &mut [u8],
) {
    while let Ok(len) = socket.try_recv(buf) {
        let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
        if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
            tracing::debug!("QUIC recv error while draining UDP: {e}");
        }
    }
}

async fn flush_quic(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> Result<()> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => {
                let _ = send_info;
                socket.send(&out[..write]).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => bail!("quic send error: {e}"),
        }
    }
    Ok(())
}

fn build_flow_prefix(flow_id: u64) -> Result<Vec<u8>> {
    let mut tmp = [0u8; 8];
    let mut b = OctetsMut::with_slice(&mut tmp);
    b.put_varint(flow_id).map_err(|e| anyhow!("encode flow_id varint: {e}"))?;
    let len = b.off();
    let mut flow_prefix = Vec::with_capacity(len + 1);
    flow_prefix.extend_from_slice(&tmp[..len]);
    flow_prefix.push(0x00);
    Ok(flow_prefix)
}

fn parse_datagram(dgram: &[u8], expected_flow_id: u64) -> Option<&[u8]> {
    let mut b = Octets::with_slice(dgram);
    let flow_id = b.get_varint().ok()?;
    if flow_id != expected_flow_id {
        return None;
    }
    let context_id = b.get_varint().ok()?;
    if context_id != 0 {
        return None;
    }
    let off = b.off();
    if off >= dgram.len() {
        return None;
    }
    Some(&dgram[off..])
}

fn spawn_stats_task(stats: Arc<Stats>, start: Instant) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            tracing::info!(
                "connected={} tx={} ({}) rx={} ({}) drop={} txq={} bp={} lost={} retrans={}",
                format_duration(start.elapsed()),
                stats.tx_packets.load(Ordering::Relaxed),
                format_bytes(stats.tx_bytes.load(Ordering::Relaxed)),
                stats.rx_packets.load(Ordering::Relaxed),
                format_bytes(stats.rx_bytes.load(Ordering::Relaxed)),
                stats.dropped.load(Ordering::Relaxed),
                stats.tx_queue_len.load(Ordering::Relaxed),
                stats.tx_backpressure.load(Ordering::Relaxed),
                stats.quic_lost.load(Ordering::Relaxed),
                stats.quic_retrans.load(Ordering::Relaxed),
            );
        }
    })
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m {:02}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut b = OctetsMut::with_slice(&mut tmp);
        b.put_varint(val).unwrap();
        tmp[..b.off()].to_vec()
    }

    #[test]
    fn parse_datagram_valid() {
        let mut d = encode_varint(4);
        d.extend_from_slice(&encode_varint(0));
        d.extend_from_slice(b"payload");
        assert_eq!(parse_datagram(&d, 4), Some(b"payload".as_ref()));
    }
}
