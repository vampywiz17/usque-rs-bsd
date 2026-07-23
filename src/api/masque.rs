use crate::api::hooks::run_hook;
use crate::api::{icmp, packet};
use crate::config::{AppConfig, MasqueEndpoint};
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
#[cfg(target_os = "freebsd")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const MAX_DATAGRAM_SIZE: usize = 1500;
const MIN_MTU: u16 = 1280;
const DEFAULT_UDP_SOCKET_BUFFER: usize = 8 * 1024 * 1024;
const DGRAM_QUEUE_LEN: usize = 16_384;
const TX_CHANNEL_DRAIN_BURST: usize = 256;
const MAX_PACKET_BUFFER_POOL_SIZE: usize = 16_384;
const MAX_UDP_BATCH_SIZE: usize = 64;

#[derive(Clone)]
pub struct MasqueConfig {
    pub private_key: SecretKey,
    pub sni: String,
    pub insecure: bool,
    pub endpoints: Vec<MasqueEndpoint>,
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
    pub packet_buffer_pool_size: usize,
    pub udp_batch_size: usize,
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
    wire_len: usize,
    ip_len: usize,
}

struct TxProgress {
    queued: usize,
    backpressure: bool,
}

struct UdpBatchIo {
    tx_buffers: Vec<Vec<u8>>,
    tx_lens: Vec<usize>,
    tx_at: Vec<Instant>,
    rx_buffers: Vec<Vec<u8>>,
    batch_size: usize,
}

impl UdpBatchIo {
    fn new(datagram_size: usize, requested_batch_size: usize) -> Self {
        let batch_size = requested_batch_size.clamp(1, MAX_UDP_BATCH_SIZE);
        let datagram_size = datagram_size.max(MAX_DATAGRAM_SIZE);
        Self {
            tx_buffers: (0..batch_size)
                .map(|_| vec![0u8; datagram_size])
                .collect(),
            tx_lens: vec![0; batch_size],
            tx_at: vec![Instant::now(); batch_size],
            rx_buffers: (0..batch_size)
                .map(|_| vec![0u8; datagram_size])
                .collect(),
            batch_size,
        }
    }

    async fn flush_quic(
        &mut self,
        socket: &tokio::net::UdpSocket,
        conn: &mut quiche::Connection,
    ) -> Result<()> {
        loop {
            let mut count = 0;
            let mut drained = false;

            while count < self.batch_size {
                match conn.send(&mut self.tx_buffers[count]) {
                    Ok((write, send_info)) => {
                        // quiche has already produced a complete UDP datagram.
                        // Batching only changes how ready datagrams cross the
                        // userspace/kernel boundary.
                        self.tx_lens[count] = write;
                        self.tx_at[count] = send_info.at;
                        count += 1;
                    }
                    Err(quiche::Error::Done) => {
                        drained = true;
                        break;
                    }
                    Err(e) => bail!("quic send error: {e}"),
                }
            }

            if count > 0 {
                self.send_paced_batches(socket, count).await?;
            }
            if drained {
                return Ok(());
            }
        }
    }

    async fn send_paced_batches(
        &mut self,
        socket: &tokio::net::UdpSocket,
        count: usize,
    ) -> Result<()> {
        let mut start = 0;
        while start < count {
            let wait = self.tx_at[start].saturating_duration_since(Instant::now());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }

            // Preserve quiche's pacing decision: only coalesce packets whose
            // requested send time has arrived. Equal/deadline-ready packets
            // still cross into the kernel with one sendmmsg call on FreeBSD.
            let now = Instant::now();
            let mut end = start + 1;
            while end < count && self.tx_at[end] <= now {
                end += 1;
            }
            self.send_batch(socket, start, end).await?;
            start = end;
        }
        Ok(())
    }

    async fn send_batch(
        &mut self,
        socket: &tokio::net::UdpSocket,
        start: usize,
        end: usize,
    ) -> Result<()> {
        #[cfg(target_os = "freebsd")]
        {
            let fd = socket.as_raw_fd();
            let mut sent = start;
            while sent < end {
                match sendmmsg_nonblocking(
                    fd,
                    &self.tx_buffers[sent..end],
                    &self.tx_lens[sent..end],
                ) {
                    Ok(0) => {
                        socket.writable().await?;
                    }
                    Ok(n) => sent += n,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        socket.writable().await?;
                    }
                    Err(err) => return Err(err).context("FreeBSD sendmmsg failed"),
                }
            }
            return Ok(());
        }

        #[cfg(not(target_os = "freebsd"))]
        {
            for index in start..end {
                socket
                    .send(&self.tx_buffers[index][..self.tx_lens[index]])
                    .await?;
            }
            Ok(())
        }
    }

    fn drain_quic(
        &mut self,
        socket: &tokio::net::UdpSocket,
        endpoint: SocketAddr,
        local_addr: SocketAddr,
        conn: &mut quiche::Connection,
    ) -> Result<usize> {
        let mut total = 0;
        loop {
            let count = self.try_recv_batch(socket)?;
            if count == 0 {
                return Ok(total);
            }
            total += count;

            for index in 0..count {
                let len = self.tx_lens[index];
                if len == 0 {
                    continue;
                }
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from: endpoint,
                };
                if let Err(err) =
                    conn.recv(&mut self.rx_buffers[index][..len], recv_info)
                {
                    tracing::debug!("QUIC recv error while draining UDP batch: {err}");
                }
            }

            if count < self.batch_size {
                return Ok(total);
            }
        }
    }

    fn try_recv_batch(
        &mut self,
        socket: &tokio::net::UdpSocket,
    ) -> std::io::Result<usize> {
        #[cfg(target_os = "freebsd")]
        {
            return recvmmsg_nonblocking(
                socket.as_raw_fd(),
                &mut self.rx_buffers,
                &mut self.tx_lens,
            );
        }

        #[cfg(not(target_os = "freebsd"))]
        {
            let mut count = 0;
            while count < self.batch_size {
                match socket.try_recv(&mut self.rx_buffers[count]) {
                    Ok(len) => {
                        self.tx_lens[count] = len;
                        count += 1;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }
            Ok(count)
        }
    }
}

#[cfg(target_os = "freebsd")]
fn sendmmsg_nonblocking(
    fd: std::os::fd::RawFd,
    buffers: &[Vec<u8>],
    lengths: &[usize],
) -> std::io::Result<usize> {
    let count = buffers.len().min(lengths.len()).min(MAX_UDP_BATCH_SIZE);
    let mut iovecs: [libc::iovec; MAX_UDP_BATCH_SIZE] =
        std::array::from_fn(|_| libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        });
    let mut messages: [libc::mmsghdr; MAX_UDP_BATCH_SIZE] =
        std::array::from_fn(|_| unsafe { std::mem::zeroed() });

    for index in 0..count {
        iovecs[index].iov_base = buffers[index].as_ptr() as *mut libc::c_void;
        iovecs[index].iov_len = lengths[index];
        messages[index].msg_hdr.msg_iov = &mut iovecs[index];
        messages[index].msg_hdr.msg_iovlen = 1;
    }

    let result = unsafe {
        libc::sendmmsg(
            fd,
            messages.as_mut_ptr(),
            count as _,
            libc::MSG_DONTWAIT,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

#[cfg(target_os = "freebsd")]
fn recvmmsg_nonblocking(
    fd: std::os::fd::RawFd,
    buffers: &mut [Vec<u8>],
    lengths: &mut [usize],
) -> std::io::Result<usize> {
    let count = buffers.len().min(lengths.len()).min(MAX_UDP_BATCH_SIZE);
    let mut iovecs: [libc::iovec; MAX_UDP_BATCH_SIZE] =
        std::array::from_fn(|_| libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        });
    let mut messages: [libc::mmsghdr; MAX_UDP_BATCH_SIZE] =
        std::array::from_fn(|_| unsafe { std::mem::zeroed() });

    for index in 0..count {
        iovecs[index].iov_base =
            buffers[index].as_mut_ptr() as *mut libc::c_void;
        iovecs[index].iov_len = buffers[index].len();
        messages[index].msg_hdr.msg_iov = &mut iovecs[index];
        messages[index].msg_hdr.msg_iovlen = 1;
    }

    let result = unsafe {
        libc::recvmmsg(
            fd,
            messages.as_mut_ptr(),
            count as _,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(0);
        }
        return Err(err);
    }

    for index in 0..result as usize {
        if messages[index].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
            lengths[index] = 0;
            tracing::debug!("dropping truncated UDP datagram from recvmmsg batch");
        } else {
            lengths[index] =
                (messages[index].msg_len as usize).min(buffers[index].len());
        }
    }
    Ok(result as usize)
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
    let mut endpoint_index = 0usize;

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

        let endpoint = cfg
            .endpoints
            .get(endpoint_index)
            .ok_or_else(|| anyhow!("MASQUE endpoint list is empty"))?;
        tracing::info!(
            "Establishing MASQUE connection to {} ({}/{}){}",
            endpoint.addr,
            endpoint_index + 1,
            cfg.endpoints.len(),
            if endpoint.host.is_empty() {
                String::new()
            } else {
                format!(" for {}", endpoint.host)
            }
        );
        match run_tunnel_session(&cfg, endpoint, &dev, mtu, &mut pending_pkt).await {
            Ok(()) => tracing::warn!("MASQUE session ended. Reconnecting..."),
            Err(err) => tracing::warn!("MASQUE session failed: {err:#}. Reconnecting..."),
        }
        endpoint_index = (endpoint_index + 1) % cfg.endpoints.len();
        tokio::time::sleep(cfg.reconnect_delay).await;
    }
}

fn prepare_tls_material(
    cfg: &MasqueConfig,
    endpoint: &MasqueEndpoint,
) -> Result<TlsMaterial> {
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
        endpoint_pub_key_spki_der: endpoint.endpoint_pub_key_spki_der.clone(),
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
    selected_endpoint: &MasqueEndpoint,
    dev: &Arc<TunRsDevice>,
    mtu: usize,
    pending_pkt: &mut Option<Vec<u8>>,
) -> Result<()> {
    let endpoint = selected_endpoint.addr.0;
    let tls_material = prepare_tls_material(cfg, selected_endpoint)?;

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
    let packet_buffer_pool_size = cfg
        .packet_buffer_pool_size
        .clamp(1, MAX_PACKET_BUFFER_POOL_SIZE);
    let tx_queue_len = cfg.tx_queue_len.max(1).min(packet_buffer_pool_size);
    tracing::info!(
        "QUIC tuning: quiche=0.29 cc={} initial_cwnd_packets={} udp_payload={} dgram_queue_len={} tx_queue_len={} tx_burst_packets={} packet_buffer_pool_size={} udp_batch_size={} pacing={} relaxed_loss={} send_capacity_factor={} max_pacing_rate_bps={} udp_socket_buffer={}",
        cfg.cc_algorithm.trim(),
        cfg.initial_cwnd_packets,
        udp_payload,
        DGRAM_QUEUE_LEN,
        tx_queue_len,
        cfg.tx_burst_packets,
        packet_buffer_pool_size,
        cfg.udp_batch_size.clamp(1, MAX_UDP_BATCH_SIZE),
        if cfg.disable_quic_pacing { "off" } else { "on" },
        cfg.relaxed_loss,
        cfg.send_capacity_factor,
        cfg.max_pacing_rate_bps,
        cfg.udp_socket_buffer,
    );
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, DGRAM_QUEUE_LEN, DGRAM_QUEUE_LEN);

    let socket = create_connected_udp_socket(endpoint, cfg.udp_socket_buffer)?;
    let local_addr = socket.local_addr()?…2220 tokens truncated… free_rx.recv().await else {
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
        let mut last_network_activity = Instant::now();

        loop {
            if udp_batch.drain_quic(socket, endpoint, local_addr, conn)? > 0 {
                last_network_activity = Instant::now();
            }
            poll_h3(conn, h3_conn);
            drain_incoming_datagrams(conn, flow_id, stats, dev).await;

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
            );
            if progress.queued > 0 {
                udp_batch.flush_quic(socket, conn).await?;
                last_network_activity = Instant::now();
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

            let quic_timeout = conn.timeout();
            let keepalive_wait =
                keepalive_remaining(keepalive_period, last_network_activity.elapsed());
            let (timeout, quic_timeout_due) = match (quic_timeout, keepalive_wait) {
                (Some(quic), Some(keepalive)) => {
                    (quic.min(keepalive), quic <= keepalive)
                }
                (Some(quic), None) => (quic, true),
                (None, Some(keepalive)) => (keepalive, false),
                // No QUIC recovery timer and keepalive disabled. This long timer
                // only keeps the select branch available; socket/TUN activity
                // wakes the loop immediately.
                (None, None) => (Duration::from_secs(60 * 60), false),
            };
            tokio::select! {
                biased;
                result = socket.readable() => {
                    result?;
                    if udp_batch.drain_quic(socket, endpoint, local_addr, conn)? > 0 {
                        last_network_activity = Instant::now();
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
                () = tokio::time::sleep(timeout) => {
                    let mut flush = false;

                    if quic_timeout_due {
                        conn.on_timeout();
                        flush = true;
                    }

                    if keepalive_remaining(
                        keepalive_period,
                        last_network_activity.elapsed(),
                    ) == Some(Duration::ZERO) {
                        // RFC 9000 sections 10.1.2 and 19.2 explicitly define
                        // PING as an ack-eliciting connection keepalive. Keeping
                        // this at the QUIC layer avoids synthetic traffic inside
                        // the TUN interface and is independent of the tun-rs
                        // platform backend.
                        conn.send_ack_eliciting()
                            .map_err(|e| anyhow!("failed to schedule QUIC keepalive PING: {e}"))?;
                        tracing::debug!("scheduled QUIC keepalive PING");
                        last_network_activity = Instant::now();
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
) -> TxProgress {
    let mut progress = TxProgress { queued: 0, backpressure: false };
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

fn keepalive_remaining(period: Duration, idle_for: Duration) -> Option<Duration> {
    if period.is_zero() {
        None
    } else {
        Some(period.saturating_sub(idle_for))
    }
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

    #[test]
    fn udp_batch_size_is_bounded() {
        assert_eq!(UdpBatchIo::new(1250, 0).batch_size, 1);
        assert_eq!(UdpBatchIo::new(1250, 32).batch_size, 32);
        assert_eq!(
            UdpBatchIo::new(1250, MAX_UDP_BATCH_SIZE + 1).batch_size,
            MAX_UDP_BATCH_SIZE
        );
    }

    #[test]
    fn keepalive_can_be_disabled() {
        assert_eq!(
            keepalive_remaining(Duration::ZERO, Duration::from_secs(60)),
            None
        );
    }

    #[test]
    fn keepalive_waits_only_for_remaining_idle_time() {
        assert_eq!(
            keepalive_remaining(Duration::from_secs(25), Duration::from_secs(10)),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            keepalive_remaining(Duration::from_secs(25), Duration::from_secs(25)),
            Some(Duration::ZERO)
        );
    }

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let len = {
            let mut b = OctetsMut::with_slice(&mut tmp);
            b.put_varint(val).unwrap();
            b.off()
        };
        tmp[..len].to_vec()
    }

    #[test]
    fn parse_datagram_valid() {
        let mut d = encode_varint(4);
        d.extend_from_slice(&encode_varint(0));
        d.extend_from_slice(b"payload");
        assert_eq!(parse_datagram(&d, 4), Some(b"payload".as_ref()));
    }
}
