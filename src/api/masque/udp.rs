//! QUIC UDP socket integration and paced batch I/O.
//!
//! FreeBSD uses `sendmmsg`/`recvmmsg` behind Tokio's `try_io` readiness
//! contract. Other targets retain the portable connected `UdpSocket` path.

use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
#[cfg(target_os = "freebsd")]
use std::os::fd::AsRawFd;
use std::time::Instant;

pub(super) const MAX_DATAGRAM_SIZE: usize = 1500;
pub(super) const MAX_UDP_BATCH_SIZE: usize = 64;
const MIN_UDP_SOCKET_BUFFER: usize = 64 * 1024;
const UDP_SOCKET_BUFFER_SEARCH_GRANULARITY: usize = 64 * 1024;

#[derive(Debug)]
struct SocketBufferTuning {
    initial: usize,
    effective: usize,
    target: usize,
    target_accepted: bool,
    limit_error: Option<std::io::Error>,
}

pub(super) struct UdpBatchIo {
    tx_buffers: Vec<Vec<u8>>,
    tx_lens: Vec<usize>,
    tx_at: Vec<Instant>,
    rx_buffers: Vec<Vec<u8>>,
    pub(super) batch_size: usize,
}

impl UdpBatchIo {
    pub(super) fn new(datagram_size: usize, requested_batch_size: usize) -> Self {
        let batch_size = requested_batch_size.clamp(1, MAX_UDP_BATCH_SIZE);
        let datagram_size = datagram_size.max(MAX_DATAGRAM_SIZE);
        Self {
            tx_buffers: (0..batch_size).map(|_| vec![0u8; datagram_size]).collect(),
            tx_lens: vec![0; batch_size],
            tx_at: vec![Instant::now(); batch_size],
            rx_buffers: (0..batch_size).map(|_| vec![0u8; datagram_size]).collect(),
            batch_size,
        }
    }

    pub(super) async fn flush_quic(
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
                // Keep raw sendmmsg() synchronized with Tokio's writable
                // readiness state. Otherwise EAGAIN can leave a stale writable
                // notification behind and spin one CPU core under backpressure.
                match socket.try_io(tokio::io::Interest::WRITABLE, || {
                    sendmmsg_nonblocking(fd, &self.tx_buffers[sent..end], &self.tx_lens[sent..end])
                }) {
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
            Ok(())
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

    pub(super) fn drain_quic(
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
                if let Err(err) = conn.recv(&mut self.rx_buffers[index][..len], recv_info) {
                    tracing::debug!("QUIC recv error while draining UDP batch: {err}");
                }
            }

            if count < self.batch_size {
                return Ok(total);
            }
        }
    }

    pub(super) fn try_recv_batch(
        &mut self,
        socket: &tokio::net::UdpSocket,
    ) -> std::io::Result<usize> {
        #[cfg(target_os = "freebsd")]
        {
            // recvmmsg() operates on the raw descriptor, so it must run through
            // Tokio's readiness guard. EAGAIN must reach try_io() so Tokio can
            // clear a stale readable notification. Converting it to Ok(0)
            // earlier leaves the socket readable forever and causes a busy loop.
            match socket.try_io(tokio::io::Interest::READABLE, || {
                recvmmsg_nonblocking(socket.as_raw_fd(), &mut self.rx_buffers, &mut self.tx_lens)
            }) {
                Ok(count) => Ok(count),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(err) => Err(err),
            }
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
    let mut iovecs: [libc::iovec; MAX_UDP_BATCH_SIZE] = std::array::from_fn(|_| libc::iovec {
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

    let result =
        unsafe { libc::sendmmsg(fd, messages.as_mut_ptr(), count as _, libc::MSG_DONTWAIT) };
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
    let mut iovecs: [libc::iovec; MAX_UDP_BATCH_SIZE] = std::array::from_fn(|_| libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    });
    let mut messages: [libc::mmsghdr; MAX_UDP_BATCH_SIZE] =
        std::array::from_fn(|_| unsafe { std::mem::zeroed() });

    for index in 0..count {
        iovecs[index].iov_base = buffers[index].as_mut_ptr() as *mut libc::c_void;
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
        // Preserve EAGAIN so UdpSocket::try_io() can clear Tokio's readable
        // readiness state. The caller turns it into an empty batch afterwards.
        return Err(std::io::Error::last_os_error());
    }

    for index in 0..result as usize {
        if messages[index].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
            lengths[index] = 0;
            tracing::debug!("dropping truncated UDP datagram from recvmmsg batch");
        } else {
            lengths[index] = (messages[index].msg_len as usize).min(buffers[index].len());
        }
    }
    Ok(result as usize)
}

fn tune_socket_buffer<Get, Set>(
    requested_target: usize,
    mut get_size: Get,
    mut set_size: Set,
) -> std::io::Result<SocketBufferTuning>
where
    Get: FnMut() -> std::io::Result<usize>,
    Set: FnMut(usize) -> std::io::Result<()>,
{
    let target = requested_target.max(MIN_UDP_SOCKET_BUFFER);
    let initial = get_size()?;
    if initial >= target {
        return Ok(SocketBufferTuning {
            initial,
            effective: initial,
            target,
            target_accepted: true,
            limit_error: None,
        });
    }

    let mut effective = initial;
    let mut accepted_request = None;
    let mut candidate = MIN_UDP_SOCKET_BUFFER;

    loop {
        // Never replace a larger kernel default with a smaller requested value.
        if candidate > initial {
            match set_size(candidate) {
                Ok(()) => {
                    effective = get_size()?;
                    accepted_request = Some(candidate);
                }
                Err(mut limit_error) => {
                    // A rejected power-of-two step only establishes an upper bound.
                    // Refine it so kernels with a non-power-of-two cap can still
                    // grant nearly all available capacity.
                    if let Some(mut low) = accepted_request {
                        let mut high = candidate;
                        while high.saturating_sub(low) > UDP_SOCKET_BUFFER_SEARCH_GRANULARITY {
                            let midpoint = low + (high - low) / 2;
                            let midpoint = (midpoint / UDP_SOCKET_BUFFER_SEARCH_GRANULARITY)
                                * UDP_SOCKET_BUFFER_SEARCH_GRANULARITY;
                            if midpoint <= low {
                                break;
                            }
                            match set_size(midpoint) {
                                Ok(()) => {
                                    low = midpoint;
                                    effective = get_size()?;
                                }
                                Err(err) => {
                                    high = midpoint;
                                    limit_error = err;
                                }
                            }
                        }
                    }

                    return Ok(SocketBufferTuning {
                        initial,
                        effective,
                        target,
                        target_accepted: false,
                        limit_error: Some(limit_error),
                    });
                }
            }
        }

        if candidate == target {
            return Ok(SocketBufferTuning {
                initial,
                effective,
                target,
                target_accepted: true,
                limit_error: None,
            });
        }
        candidate = candidate.saturating_mul(2).min(target);
    }
}

fn log_socket_buffer_tuning(direction: &str, result: std::io::Result<SocketBufferTuning>) {
    match result {
        Ok(tuning) if tuning.target_accepted => tracing::info!(
            "UDP {direction} socket buffer: system_default={} target={} effective={}",
            tuning.initial,
            tuning.target,
            tuning.effective
        ),
        Ok(tuning) => tracing::warn!(
            "UDP {direction} socket buffer is OS-limited: system_default={} target={} effective={}: {}",
            tuning.initial,
            tuning.target,
            tuning.effective,
            tuning
                .limit_error
                .as_ref()
                .map(std::io::Error::to_string)
                .unwrap_or_else(|| "socket option rejected".to_string())
        ),
        Err(err) => tracing::warn!(
            "failed to query or verify UDP {direction} socket buffer; retaining the kernel-managed value: {err}"
        ),
    }
}

pub(super) fn create_connected_udp_socket(
    endpoint: SocketAddr,
    socket_buffer_size: usize,
) -> Result<tokio::net::UdpSocket> {
    let domain = if endpoint.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let bind_addr: SocketAddr = if endpoint.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create UDP socket")?;

    // Socket buffer sizing is a per-socket capability negotiation. Start with
    // the kernel default, grow toward the configured ceiling and verify every
    // accepted SO_RCVBUF/SO_SNDBUF value. A system-wide sysctl is never changed.
    log_socket_buffer_tuning(
        "receive",
        tune_socket_buffer(
            socket_buffer_size,
            || sock.recv_buffer_size(),
            |size| sock.set_recv_buffer_size(size),
        ),
    );
    log_socket_buffer_tuning(
        "send",
        tune_socket_buffer(
            socket_buffer_size,
            || sock.send_buffer_size(),
            |size| sock.set_send_buffer_size(size),
        ),
    );

    sock.bind(&SockAddr::from(bind_addr))
        .context("failed to bind UDP socket")?;
    sock.connect(&SockAddr::from(endpoint))
        .context("failed to connect UDP socket")?;
    sock.set_nonblocking(true)
        .context("failed to set UDP socket nonblocking")?;

    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock).context("failed to convert UDP socket to tokio")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug)]
    struct FakeSocketBuffer {
        current: usize,
        maximum: usize,
        requests: Vec<usize>,
    }

    impl FakeSocketBuffer {
        fn set(&mut self, size: usize) -> std::io::Result<()> {
            self.requests.push(size);
            if size > self.maximum {
                Err(std::io::Error::from_raw_os_error(libc::ENOBUFS))
            } else {
                self.current = size;
                Ok(())
            }
        }
    }

    fn tune_fake(
        initial: usize,
        maximum: usize,
        target: usize,
    ) -> (SocketBufferTuning, FakeSocketBuffer) {
        let state = RefCell::new(FakeSocketBuffer {
            current: initial,
            maximum,
            requests: Vec::new(),
        });
        let tuning = tune_socket_buffer(
            target,
            || Ok(state.borrow().current),
            |size| state.borrow_mut().set(size),
        )
        .unwrap();
        (tuning, state.into_inner())
    }

    #[test]
    fn socket_buffer_tuning_reaches_supported_target() {
        let target = 8 * 1024 * 1024;
        let (tuning, state) = tune_fake(32 * 1024, target, target);

        assert!(tuning.target_accepted);
        assert_eq!(tuning.effective, target);
        assert_eq!(state.requests.last(), Some(&target));
    }

    #[test]
    fn socket_buffer_tuning_refines_non_power_of_two_limit() {
        let maximum = 3_600_000;
        let (tuning, _) = tune_fake(32 * 1024, maximum, 8 * 1024 * 1024);

        assert!(!tuning.target_accepted);
        assert!(tuning.limit_error.is_some());
        assert!(tuning.effective <= maximum);
        assert!(maximum - tuning.effective < UDP_SOCKET_BUFFER_SEARCH_GRANULARITY);
    }

    #[test]
    fn socket_buffer_tuning_retains_default_when_growth_is_rejected() {
        let initial = 128 * 1024;
        let (tuning, _) = tune_fake(initial, 100 * 1024, 8 * 1024 * 1024);

        assert!(!tuning.target_accepted);
        assert_eq!(tuning.effective, initial);
    }

    #[test]
    fn socket_buffer_tuning_does_not_reduce_large_kernel_default() {
        let initial = 16 * 1024 * 1024;
        let (tuning, state) = tune_fake(initial, initial, 8 * 1024 * 1024);

        assert!(tuning.target_accepted);
        assert_eq!(tuning.effective, initial);
        assert!(state.requests.is_empty());
    }

    #[test]
    fn socket_buffer_tuning_accepts_exact_non_power_of_two_target() {
        let target = 3_500_000;
        let (tuning, state) = tune_fake(32 * 1024, target, target);

        assert!(tuning.target_accepted);
        assert_eq!(tuning.effective, target);
        assert_eq!(state.requests.last(), Some(&target));
    }
}
