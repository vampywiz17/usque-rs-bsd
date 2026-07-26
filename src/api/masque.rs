mod connect_ip;
mod handshake;
mod stats;
mod supervisor;
mod timing;
mod udp;
pub use supervisor::maintain_native_tun;

use crate::api::device_state::{DeviceStateReporter, TunnelMetrics};
use crate::api::hooks::run_hook;
use crate::api::{icmp, packet};
use crate::config::MasqueEndpoint;
use crate::native_tun::TunRsDevice;
use anyhow::{anyhow, bail, Result};
use connect_ip::{build_flow_prefix, parse_datagram};
use handshake::{
    complete_quic_handshake, prepare_tls_material, verify_endpoint_key, wait_connect_response,
};
use p256::SecretKey;
use portable_atomic::Ordering;
use ring::rand::SecureRandom;
use serde::Serialize;
use stats::{spawn_stats_task, Stats};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use timing::{discovered_tun_mtu, keepalive_remaining, pmtud_remaining};
use udp::{create_connected_udp_socket, UdpBatchIo, MAX_DATAGRAM_SIZE, MAX_UDP_BATCH_SIZE};

const DGRAM_QUEUE_LEN: usize = 16_384;
const TX_CHANNEL_DRAIN_BURST: usize = 256;
const MAX_PACKET_BUFFER_POOL_SIZE: usize = 16_384;
const MESH_H3_STATS_INTERVAL: Duration = Duration::from_secs(15);

pub struct QuicTransportConfig {
    pub keepalive_period: Duration,
    pub initial_packet_size: u16,
    pub cc_algorithm: String,
    pub initial_cwnd_packets: usize,
    pub disable_pacing: bool,
    pub relaxed_loss: bool,
    pub send_capacity_factor: f64,
    pub max_pacing_rate_bps: u64,
}

pub struct PathMtuConfig {
    pub enabled: bool,
    pub max_probes: u8,
    pub revalidate_period: Duration,
    pub initial_tun_mtu: u16,
    pub max_tun_mtu: u16,
    pub tunnel_ipv6: bool,
}

pub struct DatagramIoConfig {
    pub udp_socket_buffer: usize,
    pub tx_queue_len: usize,
    pub tx_burst_packets: usize,
    pub packet_buffer_pool_size: usize,
    pub udp_batch_size: usize,
}

pub struct ReconnectPolicy {
    pub delay: Duration,
    pub always: bool,
}

pub struct LifecycleHooks {
    pub on_connect: Option<String>,
    pub on_disconnect: Option<String>,
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareConnectProfile {
    Client,
    MeshNode { client_version: String },
}

impl CloudflareConnectProfile {
    fn reports_h3_stats(&self) -> bool {
        matches!(self, Self::MeshNode { .. })
    }
}

pub struct MasqueConfig {
    pub private_key: SecretKey,
    pub sni: String,
    pub insecure: bool,
    pub endpoints: Vec<MasqueEndpoint>,
    pub user_agent: String,
    pub connect_profile: CloudflareConnectProfile,
    pub quic: QuicTransportConfig,
    pub path_mtu: PathMtuConfig,
    pub io: DatagramIoConfig,
    pub reconnect: ReconnectPolicy,
    pub hooks: LifecycleHooks,
    pub device_state: Option<DeviceStateReporter>,
}

fn connect_request_headers(
    profile: &CloudflareConnectProfile,
    user_agent: &str,
    pq_enabled: bool,
) -> Vec<quiche::h3::Header> {
    let scheme: &[u8] = match profile {
        CloudflareConnectProfile::Client => b"https",
        CloudflareConnectProfile::MeshNode { .. } => b"http",
    };
    let mut headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", scheme),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
    ];
    match profile {
        CloudflareConnectProfile::Client => {
            headers.push(quiche::h3::Header::new(b"capsule-protocol", b"?1"));
            headers.push(quiche::h3::Header::new(
                b"user-agent",
                user_agent.as_bytes(),
            ));
        }
        CloudflareConnectProfile::MeshNode { client_version } => {
            // Cloudflare's Linux-only Connector contract prefixes its actual
            // client version with `l-`. The version remains this program's own
            // version; it never claims an official Cloudflare release.
            let cf_client_version = format!("l-{client_version}");
            headers.push(quiche::h3::Header::new(
                b"pq-enabled",
                if pq_enabled { b"true" } else { b"false" },
            ));
            headers.push(quiche::h3::Header::new(
                b"cf-client-version",
                cf_client_version.as_bytes(),
            ));
        }
    }
    headers
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct H3StatsRequest {
    schema_version: &'static str,
    stats: H3StatsFields,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct H3StatsFields {
    rtt_us: u64,
    min_rtt_us: u64,
    rtt_var_us: u64,
    packets_sent: usize,
    packets_recvd: usize,
    packets_lost: usize,
    packets_retrans: usize,
    bytes_sent: u64,
    bytes_recvd: u64,
    bytes_lost: u64,
    bytes_retrans: u64,
}

struct PendingH3StatsReport {
    stream_id: u64,
    body: Vec<u8>,
    written: usize,
}

fn h3_stats_request_headers() -> [quiche::h3::Header; 4] {
    [
        quiche::h3::Header::new(b":method", b"POST"),
        quiche::h3::Header::new(b":scheme", b"http"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/h3-stats"),
    ]
}

fn h3_stats_request(conn: &quiche::Connection) -> Option<H3StatsRequest> {
    let path = conn.path_stats().find(|path| path.active)?;
    let micros = |duration: Duration| duration.as_micros().min(u128::from(u64::MAX)) as u64;
    Some(H3StatsRequest {
        schema_version: "0",
        stats: H3StatsFields {
            rtt_us: micros(path.rtt),
            min_rtt_us: micros(path.min_rtt.unwrap_or(path.rtt)),
            rtt_var_us: micros(path.rttvar),
            packets_sent: path.sent,
            packets_recvd: path.recv,
            packets_lost: path.lost,
            packets_retrans: path.retrans,
            bytes_sent: path.sent_bytes,
            bytes_recvd: path.recv_bytes,
            bytes_lost: path.lost_bytes,
            bytes_retrans: path.stream_retrans_bytes,
        },
    })
}

fn start_h3_stats_report(
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
) -> Result<Option<PendingH3StatsReport>> {
    let Some(request) = h3_stats_request(conn) else {
        return Ok(None);
    };
    let body = serde_json::to_vec(&request).map_err(|err| anyhow!("serialize H3 stats: {err}"))?;
    let stream_id = h3_conn
        .send_request(conn, &h3_stats_request_headers(), false)
        .map_err(|err| anyhow!("send H3 stats request: {err}"))?;
    Ok(Some(PendingH3StatsReport {
        stream_id,
        body,
        written: 0,
    }))
}

fn flush_h3_stats_report(
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    report: &mut PendingH3StatsReport,
) -> Result<bool> {
    match h3_conn.send_body(conn, report.stream_id, &report.body[report.written..], true) {
        Ok(written) => {
            report.written += written;
            Ok(report.written == report.body.len())
        }
        Err(quiche::h3::Error::Done) => Ok(false),
        Err(err) => Err(anyhow!("send H3 stats body: {err}")),
    }
}

struct TxDatagram {
    bytes: Vec<u8>,
    wire_len: usize,
    ip_len: usize,
}

struct TxProgress {
    queued: usize,
    backpressure: bool,
    icmp_packets: Vec<Vec<u8>>,
}

async fn run_tunnel_session(
    cfg: &MasqueConfig,
    selected_endpoint: &MasqueEndpoint,
    dev: &Arc<TunRsDevice>,
    mtu: usize,
    pending_pkt: &mut Option<Vec<u8>>,
) -> Result<()> {
    let connection_started = Instant::now();
    let endpoint = selected_endpoint.addr.0;
    let tls_material = prepare_tls_material(cfg, selected_endpoint)?;
    let mut quic_config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| anyhow!("quiche config: {e}"))?;
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
    let udp_payload = if cfg.quic.initial_packet_size > 0 {
        usize::from(cfg.quic.initial_packet_size)
    } else {
        MAX_DATAGRAM_SIZE
    };
    quic_config.set_max_recv_udp_payload_size(udp_payload);
    quic_config.set_max_send_udp_payload_size(udp_payload);
    quic_config.discover_pmtu(cfg.path_mtu.enabled);
    if cfg.path_mtu.enabled {
        quic_config.set_pmtud_max_probes(cfg.path_mtu.max_probes);
    }
    quic_config.set_initial_max_data(64_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(8_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(8_000_000);
    quic_config.set_initial_max_stream_data_uni(8_000_000);
    quic_config.set_initial_max_streams_bidi(100);
    quic_config.set_initial_max_streams_uni(100);
    if !cfg.quic.cc_algorithm.trim().is_empty() {
        quic_config
            .set_cc_algorithm_name(cfg.quic.cc_algorithm.trim())
            .map_err(|e| {
                anyhow!(
                    "set QUIC congestion-control algorithm '{}': {e}",
                    cfg.quic.cc_algorithm.trim()
                )
            })?;
    }
    quic_config.set_initial_congestion_window_packets(cfg.quic.initial_cwnd_packets);
    if cfg.quic.disable_pacing {
        quic_config.enable_pacing(false);
    }
    if cfg.quic.relaxed_loss {
        quic_config.set_enable_relaxed_loss_threshold(true);
    }
    if cfg.quic.send_capacity_factor > 0.0
        && (cfg.quic.send_capacity_factor - 1.0).abs() > f64::EPSILON
    {
        quic_config.set_send_capacity_factor(cfg.quic.send_capacity_factor);
    }
    if cfg.quic.max_pacing_rate_bps > 0 {
        // quiche 0.29 interprets this API as an integer number of Mbit/s,
        // while our CLI intentionally exposes bits per second. Round down so
        // the configured ceiling is never exceeded, with 1 Mbit/s as the
        // smallest non-zero value supported by quiche.
        let max_pacing_rate_mbps = (cfg.quic.max_pacing_rate_bps / 1_000_000).max(1);
        quic_config.set_max_pacing_rate(max_pacing_rate_mbps);
    }
    let packet_buffer_pool_size = cfg
        .io
        .packet_buffer_pool_size
        .clamp(1, MAX_PACKET_BUFFER_POOL_SIZE);
    let tx_queue_len = cfg.io.tx_queue_len.max(1).min(packet_buffer_pool_size);
    tracing::info!(
        "QUIC tuning: quiche=0.29.3 cc={} initial_cwnd_packets={} max_udp_payload={} pmtud={} pmtud_max_probes={} initial_tun_mtu={} max_tun_mtu={} dgram_queue_len={} tx_queue_len={} tx_burst_packets={} packet_buffer_pool_size={} udp_batch_size={} pacing={} relaxed_loss={} send_capacity_factor={} max_pacing_rate_bps={} udp_socket_buffer={}",
        cfg.quic.cc_algorithm.trim(),
        cfg.quic.initial_cwnd_packets,
        udp_payload,
        cfg.path_mtu.enabled,
        cfg.path_mtu.max_probes,
        cfg.path_mtu.initial_tun_mtu,
        cfg.path_mtu.max_tun_mtu,
        DGRAM_QUEUE_LEN,
        tx_queue_len,
        cfg.io.tx_burst_packets,
        packet_buffer_pool_size,
        cfg.io.udp_batch_size.clamp(1, MAX_UDP_BATCH_SIZE),
        if cfg.quic.disable_pacing { "off" } else { "on" },
        cfg.quic.relaxed_loss,
        cfg.quic.send_capacity_factor,
        cfg.quic.max_pacing_rate_bps,
        cfg.io.udp_socket_buffer,
    );
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, DGRAM_QUEUE_LEN, DGRAM_QUEUE_LEN);

    let socket = create_connected_udp_socket(endpoint, cfg.io.udp_socket_buffer)?;
    let local_addr = socket.local_addr()?;

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .map_err(|_| anyhow!("RNG failure"))?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(
        Some(&cfg.sni),
        &scid,
        local_addr,
        endpoint,
        &mut quic_config,
    )
    .map_err(|e| anyhow!("quiche connect: {e}"))?;

    let mut out = vec![0u8; MAX_DATAGRAM_SIZE.max(udp_payload)];
    let mut buf = vec![0u8; 65_535];
    let mut udp_batch = UdpBatchIo::new(MAX_DATAGRAM_SIZE.max(udp_payload), cfg.io.udp_batch_size);

    let (write, send_info) = conn
        .send(&mut out)
        .map_err(|e| anyhow!("initial send: {e}"))?;
    let _ = send_info;
    socket.send(&out[..write]).await?;

    complete_quic_handshake(
        &socket,
        endpoint,
        local_addr,
        &mut conn,
        &mut buf,
        &mut udp_batch,
    )
    .await?;
    let pq_enabled = false;

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

    let req = connect_request_headers(&cfg.connect_profile, &cfg.user_agent, pq_enabled);
    let stream_id = h3_conn
        .send_request(&mut conn, &req, false)
        .map_err(|e| anyhow!("send CONNECT request: {e}"))?;
    let flow_id = stream_id / 4;
    tracing::debug!("CONNECT request sent on stream {stream_id}, H3 DATAGRAM flow_id={flow_id}");

    udp_batch.flush_quic(&socket, &mut conn).await?;
    wait_connect_response(
        &socket,
        endpoint,
        local_addr,
        &mut conn,
        &mut h3_conn,
        stream_id,
        &mut buf,
        &mut udp_batch,
    )
    .await?;

    tracing::info!("Connected to MASQUE server");
    if let Some(reporter) = &cfg.device_state {
        reporter.connected(connection_started.elapsed());
    }
    if let Some(path) = &cfg.hooks.on_connect {
        let mut env = cfg.hooks.env.clone();
        env.insert("USQUE_EVENT".to_string(), "connect".to_string());
        env.insert("USQUE_ENDPOINT".to_string(), endpoint.to_string());
        run_hook(path, &env);
    }

    let stats = Stats::new();
    let stats_handle = spawn_stats_task(stats.clone(), Instant::now());
    let flow_prefix = build_flow_prefix(flow_id)?;

    if let Some(mut pkt) = pending_pkt.take() {
        send_packet_datagram(
            &socket,
            endpoint,
            local_addr,
            &mut conn,
            &flow_prefix,
            &mut pkt,
            &stats,
            dev,
            &mut buf,
            &mut udp_batch,
        )
        .await?;
        udp_batch.flush_quic(&socket, &mut conn).await?;
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
        cfg.device_state.as_ref(),
        cfg.connect_profile.reports_h3_stats(),
        cfg.quic.keepalive_period,
        cfg.path_mtu.enabled,
        cfg.path_mtu.revalidate_period,
        cfg.path_mtu.max_tun_mtu,
        tx_queue_len,
        cfg.io.tx_burst_packets.max(1),
        packet_buffer_pool_size,
        &mut udp_batch,
    )
    .await;

    stats_handle.abort();
    if let Some(reporter) = &cfg.device_state {
        reporter.disconnected();
    }
    if let Some(path) = &cfg.hooks.on_disconnect {
        let mut env = cfg.hooks.env.clone();
        env.insert("USQUE_EVENT".to_string(), "disconnect".to_string());
        env.insert("USQUE_ENDPOINT".to_string(), endpoint.to_string());
        run_hook(path, &env);
    }

    result
}

async fn data_loop(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    local_addr: SocketAddr,
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    dev: &Arc<TunRsDevice>,
    mtu: usize,
    flow_prefix: &[u8],
    flow_id: u64,
    stats: &Arc<Stats>,
    device_state: Option<&DeviceStateReporter>,
    report_h3_stats: bool,
    keepalive_period: Duration,
    enable_pmtud: bool,
    pmtud_revalidate_period: Duration,
    max_tun_mtu: u16,
    tx_queue_len: usize,
    tx_burst_packets: usize,
    packet_buffer_pool_size: usize,
    udp_batch: &mut UdpBatchIo,
) -> Result<()> {
    let pool_size = packet_buffer_pool_size.clamp(1, MAX_PACKET_BUFFER_POOL_SIZE);
    let queue_size = tx_queue_len.min(pool_size).max(1);
    let (tx, mut tx_rx) = tokio::sync::mpsc::channel::<TxDatagram>(queue_size);
    let (recycle_tx, mut free_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(pool_size);
    let reader_dev = dev.clone();
    let reader_stats = stats.clone();
    let reader_flow_prefix = flow_prefix.to_vec();
    let reader_buf_len = mtu + 128;
    let packet_buffer_len = reader_flow_prefix.len() + reader_buf_len;
    for _ in 0..pool_size {
        recycle_tx
            .try_send(vec![0u8; packet_buffer_len])
            .map_err(|_| anyhow!("failed to initialize packet buffer pool"))?;
    }
    let reader_recycle_tx = recycle_tx.clone();
    let tun_reader = tokio::spawn(async move {
        let prefix_len = reader_flow_prefix.len();
        loop {
            // tun-rs recommends reusable buffers for sustained packet I/O.
            // FreeBSD does not expose tun-rs's Linux-only recv_multiple/offload
            // path, so a bounded pool removes the per-packet allocation while
            // retaining the portable native AsyncDevice API.
            let Some(mut dgram) = free_rx.recv().await else {
                break;
            };
            dgram[..prefix_len].copy_from_slice(&reader_flow_prefix);

            match reader_dev.recv_packet(&mut dgram[prefix_len..]).await {
                Ok(0) => {
                    tracing::debug!("TUN reader received EOF");
                    break;
                }
                Ok(n) => {
                    let ip_start = prefix_len;
                    let ip_end = prefix_len + n;
                    if let Err(e) = packet::prepare_outgoing(&mut dgram[ip_start..ip_end]) {
                        reader_stats.dropped.fetch_add(1, Ordering::Relaxed);
                        tracing::trace!("dropping outgoing packet in TUN reader: {e}");
                        let _ = reader_recycle_tx.try_send(dgram);
                        continue;
                    }

                    let tx_dgram = TxDatagram {
                        bytes: dgram,
                        wire_len: ip_end,
                        ip_len: n,
                    };
                    if tx.send(tx_dgram).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!("TUN reader failed: {err:#}");
                    break;
                }
            }
        }
    });

    let result: Result<()> = async {
        let mut tx_queue: VecDeque<TxDatagram> = VecDeque::with_capacity(tx_queue_len.min(65_536));
        let mut tun_reader_closed = false;
        let mut last_telemetry_sample = Instant::now() - Duration::from_secs(1);
        // Publish the initial Mesh path state as soon as CONNECT succeeds.
        let mut last_h3_stats_report = Instant::now() - MESH_H3_STATS_INTERVAL;
        let mut pending_h3_stats_report: Option<PendingH3StatsReport> = None;
        // Drive keepalive from a periodic outbound deadline, not from received
        // packets. Incoming traffic does not reliably refresh UDP/NAT state in
        // the client-to-server direction, so postponing PING after a receive can
        // let the path expire before the first probe is transmitted.
        let mut last_keepalive_probe = Instant::now();
        let mut last_pmtud_revalidation = Instant::now();
        let mut applied_pmtu: Option<usize> = None;

        loop {
            udp_batch.drain_quic(socket, endpoint, local_addr, conn)?;
            // Receiving an ACK can schedule the next RFC 8899 probe. Drain
            // quiche immediately so discovery progresses even on an idle TUN.
            udp_batch.flush_quic(socket, conn).await?;
            poll_h3(conn, h3_conn);
            drain_incoming_datagrams(conn, flow_id, stats, dev).await;

            let mut h3_output_queued = false;
            if report_h3_stats
                && pending_h3_stats_report.is_none()
                && last_h3_stats_report.elapsed() >= MESH_H3_STATS_INTERVAL
            {
                last_h3_stats_report = Instant::now();
                match start_h3_stats_report(conn, h3_conn) {
                    Ok(Some(report)) => pending_h3_stats_report = Some(report),
                    Ok(None) => tracing::debug!("active QUIC path is not ready for H3 stats"),
                    Err(err) => tracing::warn!("failed to start H3 tunnel stats report: {err:#}"),
                }
            }
            if let Some(report) = pending_h3_stats_report.as_mut() {
                h3_output_queued = true;
                match flush_h3_stats_report(conn, h3_conn, report) {
                    Ok(true) => {
                        tracing::debug!("reported truthful QUIC path stats over H3");
                        pending_h3_stats_report = None;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!("failed to finish H3 tunnel stats report: {err:#}");
                        pending_h3_stats_report = None;
                    }
                }
            }
            if h3_output_queued {
                udp_batch.flush_quic(socket, conn).await?;
            }

            if enable_pmtud {
                if let Some(path_pmtu) = conn.pmtu() {
                    if applied_pmtu != Some(path_pmtu) {
                        if let Some(tun_mtu) =
                            discovered_tun_mtu(conn, flow_prefix.len(), max_tun_mtu)
                        {
                            let old_mtu = dev.mtu()?;
                            dev.apply_path_mtu(tun_mtu, true)?;
                            tracing::info!(
                                "PMTUD completed: QUIC UDP payload={} bytes, MASQUE TUN MTU={} bytes (was {})",
                                path_pmtu,
                                tun_mtu,
                                old_mtu
                            );
                            applied_pmtu = Some(path_pmtu);
                        }
                    }
                }
            }

            for _ in 0..TX_CHANNEL_DRAIN_BURST {
                if tx_queue.len() >= tx_queue_len {
                    break;
                }
                match tx_rx.try_recv() {
                    Ok(tx_dgram) => {
                        tx_queue.push_back(tx_dgram);
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        tun_reader_closed = true;
                        break;
                    }
                }
            }

            let progress = queue_tx_datagrams(
                conn,
                &mut tx_queue,
                stats,
                tx_burst_packets,
                &recycle_tx,
                flow_prefix.len(),
                dev.current_mtu(),
            );
            for icmp_packet in &progress.icmp_packets {
                if let Err(err) = dev.send_packet(&icmp_packet).await {
                    tracing::debug!("failed to return ICMP Packet Too Big to TUN: {err:#}");
                }
            }
            if progress.queued > 0 {
                udp_batch.flush_quic(socket, conn).await?;
            } else if progress.backpressure {
                // Quiche's DATAGRAM queue is full. Push already-queued QUIC packets
                // out to UDP and then wait for ACKs/timers instead of burning CPU.
                udp_batch.flush_quic(socket, conn).await?;
            }

            stats.tx_queue_len.store(tx_queue.len() as u64, Ordering::Relaxed);
            let qs = conn.stats();
            stats.quic_lost.store(qs.lost as u64, Ordering::Relaxed);
            stats.quic_retrans.store(qs.retrans as u64, Ordering::Relaxed);

            if conn.is_closed() {
                bail!(
                    "QUIC connection closed (timed_out={}, local_error={:?}, peer_error={:?})",
                    conn.is_timed_out(),
                    conn.local_error(),
                    conn.peer_error()
                );
            }
            if tun_reader_closed && tx_queue.is_empty() {
                bail!("TUN reader ended");
            }

            // If we still have queued DATAGRAMs and quiche accepted a full burst,
            // continue immediately. This batches upload traffic without the naive
            // per-packet sleep that hurt throughput in the pacing build.
            if last_telemetry_sample.elapsed() >= Duration::from_secs(1) {
                publish_tunnel_metrics(conn, device_state);
                last_telemetry_sample = Instant::now();
            }

            if !tx_queue.is_empty() && progress.queued >= tx_burst_packets && !progress.backpressure {
                continue;
            }

            let quic_timeout = conn.timeout();
            let keepalive_wait =
                keepalive_remaining(keepalive_period, last_keepalive_probe.elapsed());
            let pmtud_wait = pmtud_remaining(
                enable_pmtud,
                pmtud_revalidate_period,
                last_pmtud_revalidation.elapsed(),
            );
            let h3_stats_wait = if report_h3_stats && pending_h3_stats_report.is_none() {
                Some(MESH_H3_STATS_INTERVAL.saturating_sub(last_h3_stats_report.elapsed()))
            } else {
                None
            };
            let timeout = [quic_timeout, keepalive_wait, pmtud_wait, h3_stats_wait]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(Duration::from_secs(60 * 60));
            let quic_timeout_due = quic_timeout.is_some_and(|quic| quic <= timeout);
            tokio::select! {
                result = socket.readable() => {
                    result?;
                    udp_batch.drain_quic(socket, endpoint, local_addr, conn)?;
                }
                maybe_tx_dgram = tx_rx.recv(), if !tun_reader_closed && tx_queue.len() < tx_queue_len => {
                    match maybe_tx_dgram {
                        Some(tx_dgram) => {
                            tx_queue.push_back(tx_dgram);
                        }
                        None => tun_reader_closed = true,
                    }
                }
                () = tokio::time::sleep(timeout) => {
                    let mut flush = false;

                    if quic_timeout_due {
                        conn.on_timeout();
                        flush = true;
                    }

                    if keepalive_remaining(
                        keepalive_period,
                        last_keepalive_probe.elapsed(),
                    ) == Some(Duration::ZERO) {
                        // RFC 9000 sections 10.1.2 and 19.2 explicitly define
                        // PING as an ack-eliciting connection keepalive. Keeping
                        // this at the QUIC layer avoids synthetic traffic inside
                        // the TUN interface and is independent of the tun-rs
                        // platform backend.
                        conn.send_ack_eliciting()
                            .map_err(|e| anyhow!("failed to schedule QUIC keepalive PING: {e}"))?;
                        tracing::debug!("scheduled periodic QUIC keepalive PING");
                        last_keepalive_probe = Instant::now();
                        flush = true;
                    }

                    if pmtud_remaining(
                        enable_pmtud,
                        pmtud_revalidate_period,
                        last_pmtud_revalidation.elapsed(),
                    ) == Some(Duration::ZERO) {
                        conn.revalidate_pmtu();
                        last_pmtud_revalidation = Instant::now();
                        applied_pmtu = None;
                        tracing::debug!("scheduled RFC 8899 PMTU revalidation");
                        flush = true;
                    }

                    if flush {
                        udp_batch.flush_quic(socket, conn).await?;
                    }
                },
            }
        }
    }
    .await;

    tun_reader.abort();
    result
}

fn publish_tunnel_metrics(conn: &quiche::Connection, reporter: Option<&DeviceStateReporter>) {
    let Some(reporter) = reporter else {
        return;
    };
    let Some(path) = conn.path_stats().find(|path| path.active) else {
        return;
    };
    let micros = |duration: Duration| duration.as_micros().min(u128::from(u64::MAX)) as u64;
    let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);

    reporter.update_tunnel_metrics(TunnelMetrics {
        local_ip: path.local_addr.ip(),
        rtt_us: micros(path.rtt),
        min_rtt_us: path.min_rtt.map(micros),
        rtt_var_us: micros(path.rttvar),
        packets_sent_upstream: count(path.sent),
        packets_received_downstream: count(path.recv),
        packets_lost_upstream: count(path.lost),
        packets_retransmitted_upstream: count(path.retrans),
        bytes_sent_upstream: path.sent_bytes,
        bytes_received_downstream: path.recv_bytes,
        bytes_lost_upstream: path.lost_bytes,
        bytes_retransmitted_upstream: path.stream_retrans_bytes,
    });
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
            if let Some(icmp_pkt) = icmp::compose_icmp_too_large(&pkt, dev.current_mtu()) {
                let _ = dev.send_packet(&icmp_pkt).await;
            }
            return None;
        }
    }

    let wire_len = dgram.len();
    Some(TxDatagram {
        bytes: dgram,
        wire_len,
        ip_len,
    })
}

fn queue_tx_datagrams(
    conn: &mut quiche::Connection,
    tx_queue: &mut VecDeque<TxDatagram>,
    stats: &Arc<Stats>,
    tx_burst_packets: usize,
    recycle_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    flow_prefix_len: usize,
    effective_tun_mtu: u16,
) -> TxProgress {
    let mut progress = TxProgress {
        queued: 0,
        backpressure: false,
        icmp_packets: Vec::new(),
    };
    let budget = tx_burst_packets.max(1);

    while progress.queued < budget {
        let Some(item) = tx_queue.pop_front() else {
            break;
        };

        if let Some(max_len) = conn.dgram_max_writable_len() {
            if item.wire_len > max_len {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    "dropping encoded DATAGRAM that exceeds peer/path writable len: {} > {}",
                    item.wire_len,
                    max_len
                );
                if item.wire_len >= flow_prefix_len {
                    if let Some(packet) = icmp::compose_icmp_too_large(
                        &item.bytes[flow_prefix_len..item.wire_len],
                        effective_tun_mtu,
                    ) {
                        progress.icmp_packets.push(packet);
                    }
                }
                let _ = recycle_tx.try_send(item.bytes);
                continue;
            }
        }

        if conn.is_dgram_send_queue_full() {
            stats.tx_backpressure.fetch_add(1, Ordering::Relaxed);
            tx_queue.push_front(item);
            progress.backpressure = true;
            break;
        }

        let ip_len = item.ip_len;
        match conn.dgram_send(&item.bytes[..item.wire_len]) {
            Ok(()) => {
                stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                stats.tx_bytes.fetch_add(ip_len as u64, Ordering::Relaxed);
                let _ = recycle_tx.try_send(item.bytes);
                progress.queued += 1;
            }
            Err(quiche::Error::Done) => {
                stats.tx_backpressure.fetch_add(1, Ordering::Relaxed);
                tx_queue.push_front(item);
                progress.backpressure = true;
                break;
            }
            Err(e) => {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("datagram send error: {e}; dropping encoded DATAGRAM");
                let _ = recycle_tx.try_send(item.bytes);
            }
        }
    }

    progress
}

fn poll_h3(conn: &mut quiche::Connection, h3_conn: &mut quiche::h3::Connection) {
    use quiche::h3::NameValue as _;

    let mut discard = [0u8; 4096];
    loop {
        match h3_conn.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                if let Some(status) = list
                    .iter()
                    .find(|header| header.name() == b":status")
                    .map(|header| header.value())
                {
                    tracing::debug!(
                        stream_id,
                        status = %String::from_utf8_lossy(status),
                        "received H3 control response status"
                    );
                    if status != b"200" {
                        tracing::warn!(
                            "H3 control request on stream {stream_id} returned status {}",
                            String::from_utf8_lossy(status)
                        );
                    }
                }
            }
            Ok((stream_id, quiche::h3::Event::Data)) => loop {
                match h3_conn.recv_body(conn, stream_id, &mut discard) {
                    Ok(0) | Err(quiche::h3::Error::Done) => break,
                    Ok(read) => {
                        tracing::debug!(
                            stream_id,
                            response_bytes = read,
                            "received H3 control response body"
                        );
                    }
                    Err(err) => {
                        tracing::warn!("failed to drain H3 response body: {err}");
                        break;
                    }
                }
            },
            Ok((stream_id, quiche::h3::Event::Reset(code))) => {
                tracing::warn!("H3 control stream {stream_id} was reset with code {code}");
            }
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
                        stats
                            .rx_bytes
                            .fetch_add(ip_payload.len() as u64, Ordering::Relaxed);
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
    udp_batch: &mut UdpBatchIo,
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
                    if let Some(icmp_pkt) = icmp::compose_icmp_too_large(pkt, dev.current_mtu()) {
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
                            tracing::debug!("datagram send_buf error: {e}; dropping packet");
                            return Ok(());
                        }
                    }
                }

                udp_batch.flush_quic(socket, conn).await?;
                udp_batch.drain_quic(socket, endpoint, local_addr, conn)?;

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
            tracing::trace!(
                "datagram send queue stayed full after backpressure retries, dropping packet"
            );
            Ok(())
        }
        Err(e) => {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::trace!("dropping outgoing packet: {e}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::NameValue;

    fn header_value<'a>(headers: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a [u8]> {
        headers
            .iter()
            .find(|header| header.name() == name)
            .map(|header| header.value())
    }

    #[test]
    fn client_connect_profile_preserves_existing_headers() {
        let headers = connect_request_headers(&CloudflareConnectProfile::Client, "usque-test", false);
        assert_eq!(header_value(&headers, b":scheme"), Some(&b"https"[..]));
        assert_eq!(
            header_value(&headers, b"capsule-protocol"),
            Some(&b"?1"[..])
        );
        assert_eq!(
            header_value(&headers, b"user-agent"),
            Some(&b"usque-test"[..])
        );
        assert_eq!(header_value(&headers, b"pq-enabled"), None);
        assert_eq!(header_value(&headers, b"cf-client-version"), None);
    }

    #[test]
    fn mesh_connect_profile_uses_truthful_connector_headers() {
        let headers = connect_request_headers(
            &CloudflareConnectProfile::MeshNode {
                client_version: "0.7.0".to_string(),
            },
            "unused-in-mesh",
            false,
        );
        assert_eq!(headers.len(), 7);
        assert_eq!(header_value(&headers, b":method"), Some(&b"CONNECT"[..]));
        assert_eq!(
            header_value(&headers, b":protocol"),
            Some(&b"cf-connect-ip"[..])
        );
        assert_eq!(header_value(&headers, b":scheme"), Some(&b"http"[..]));
        assert_eq!(header_value(&headers, b"pq-enabled"), Some(&b"false"[..]));
        assert_eq!(
            header_value(&headers, b"cf-client-version"),
            Some(&b"l-0.7.0"[..])
        );
        assert_eq!(header_value(&headers, b"capsule-protocol"), None);
        assert_eq!(header_value(&headers, b"user-agent"), None);
    }

    #[test]
    fn only_mesh_profile_reports_h3_stats() {
        assert!(!CloudflareConnectProfile::Client.reports_h3_stats());
        assert!(CloudflareConnectProfile::MeshNode {
            client_version: "0.7.0".to_string(),
        }
        .reports_h3_stats());
    }

    #[test]
    fn h3_stats_request_matches_connector_schema() {
        let headers = h3_stats_request_headers();
        assert_eq!(headers.len(), 4);
        assert_eq!(header_value(&headers, b":method"), Some(&b"POST"[..]));
        assert_eq!(header_value(&headers, b":scheme"), Some(&b"http"[..]));
        assert_eq!(
            header_value(&headers, b":authority"),
            Some(&b"cloudflareaccess.com"[..])
        );
        assert_eq!(header_value(&headers, b":path"), Some(&b"/h3-stats"[..]));

        let request = H3StatsRequest {
            schema_version: "0",
            stats: H3StatsFields {
                rtt_us: 16_051,
                min_rtt_us: 15_260,
                rtt_var_us: 2_926,
                packets_sent: 18,
                packets_recvd: 13,
                packets_lost: 2,
                packets_retrans: 2,
                bytes_sent: 6_171,
                bytes_recvd: 3_898,
                bytes_lost: 111,
                bytes_retrans: 25,
            },
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"schema_version":"0","stats":{"rtt_us":16051,"min_rtt_us":15260,"rtt_var_us":2926,"packets_sent":18,"packets_recvd":13,"packets_lost":2,"packets_retrans":2,"bytes_sent":6171,"bytes_recvd":3898,"bytes_lost":111,"bytes_retrans":25}}"#
        );
    }

    #[test]
    fn udp_batch_size_is_bounded() {
        assert_eq!(UdpBatchIo::new(1250, 0).batch_size, 1);
        assert_eq!(UdpBatchIo::new(1250, 32).batch_size, 32);
        assert_eq!(
            UdpBatchIo::new(1250, MAX_UDP_BATCH_SIZE + 1).batch_size,
            MAX_UDP_BATCH_SIZE
        );
    }

    #[cfg(target_os = "freebsd")]
    #[tokio::test]
    async fn recvmmsg_clears_tokio_readiness_after_eagain() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"x", receiver.local_addr().unwrap())
            .await
            .unwrap();

        receiver.readable().await.unwrap();
        let mut batch = UdpBatchIo::new(1500, 4);
        assert_eq!(batch.try_recv_batch(&receiver).unwrap(), 1);
        assert_eq!(batch.try_recv_batch(&receiver).unwrap(), 0);

        assert!(
            tokio::time::timeout(Duration::from_millis(20), receiver.readable())
                .await
                .is_err(),
            "readable readiness stayed set after recvmmsg returned EAGAIN"
        );
    }
}
