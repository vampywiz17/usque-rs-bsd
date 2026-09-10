//! Client TLS material, QUIC handshake, and HTTP/3 CONNECT establishment.

use super::udp::UdpBatchIo;
use super::MasqueConfig;
use crate::config::MasqueEndpoint;
use anyhow::{bail, Context, Result};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use quiche::h3::NameValue;
use rcgen::{CertificateParams, KeyPair};
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::NamedTempFile;

pub(super) struct TlsMaterial {
    pub(super) cert_pem_file: NamedTempFile,
    pub(super) key_pem_file: NamedTempFile,
    pub(super) endpoint_pub_key_spki_der: Vec<u8>,
}

pub(super) fn prepare_tls_material(
    cfg: &MasqueConfig,
    endpoint: &MasqueEndpoint,
) -> Result<TlsMaterial> {
    let key_pem = cfg
        .private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode private key as PKCS8 PEM")?;
    let key_pair =
        KeyPair::from_pem(key_pem.as_ref()).context("failed to load key pair into rcgen")?;

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

pub(super) fn verify_endpoint_key(peer_cert_der: &[u8], expected_spki_der: &[u8]) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(peer_cert_der) else {
        tracing::warn!("failed to parse peer certificate for key pinning");
        return false;
    };
    cert.tbs_certificate.subject_pki.raw == expected_spki_der
}

pub(super) async fn complete_quic_handshake(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    local_addr: SocketAddr,
    conn: &mut quiche::Connection,
    buf: &mut [u8],
    udp_batch: &mut UdpBatchIo,
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
        udp_batch.flush_quic(socket, conn).await?;
        if conn.is_closed() {
            bail!("connection closed during QUIC handshake");
        }
    }
    Ok(())
}

// Keep the QUIC/H3 state and I/O buffers explicit at this protocol boundary;
// bundling mutable transport state would obscure ownership without reducing work.
#[allow(clippy::too_many_arguments)]
pub(super) async fn wait_connect_response(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    local_addr: SocketAddr,
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    stream_id: u64,
    buf: &mut [u8],
    udp_batch: &mut UdpBatchIo,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for CONNECT response");
        }
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));
        tokio::select! {
            result = socket.recv(buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                conn.recv(&mut buf[..len], recv_info).ok();
            }
            () = tokio::time::sleep(timeout) => conn.on_timeout(),
        }

        loop {
            match h3_conn.poll(conn) {
                Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == stream_id => {
                    for h in &list {
                        if h.name() == b":status" {
                            let status = std::str::from_utf8(h.value()).unwrap_or("?");
                            validate_connect_status(status)?;
                            return Ok(());
                        }
                    }
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => bail!("h3 poll error while waiting for CONNECT response: {e}"),
            }
        }
        udp_batch.flush_quic(socket, conn).await?;
        if conn.is_closed() {
            bail!("connection closed before CONNECT response");
        }
    }
}

fn validate_connect_status(status: &str) -> Result<()> {
    if status.starts_with('2') {
        return Ok(());
    }
    if status == "403" {
        bail!("CONNECT rejected with 403; login failed or Access enrollment/certificate is not accepted");
    }
    bail!("CONNECT rejected with status {status}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::masque::{
        CloudflareConnectProfile, DatagramIoConfig, LifecycleHooks, PathMtuConfig,
        QuicTransportConfig, ReconnectPolicy,
    };
    use crate::config::EndpointAddr;
    use p256::SecretKey;
    use rand_core::OsRng;
    use std::collections::HashMap;

    fn test_config(private_key: SecretKey) -> MasqueConfig {
        MasqueConfig {
            private_key,
            sni: "example.invalid".into(),
            insecure: false,
            endpoints: Vec::new(),
            user_agent: "usque-test".into(),
            connect_profile: CloudflareConnectProfile::Client,
            quic: QuicTransportConfig {
                keepalive_period: Duration::from_secs(25),
                max_idle_timeout: Duration::from_secs(60),
                initial_packet_size: 1200,
                cc_algorithm: "cubic".into(),
                initial_cwnd_packets: 32,
                disable_pacing: false,
                relaxed_loss: false,
                send_capacity_factor: 1.0,
                max_pacing_rate_bps: 0,
            },
            path_mtu: PathMtuConfig {
                enabled: true,
                max_probes: 3,
                revalidate_period: Duration::from_secs(600),
                initial_tun_mtu: 1200,
                max_tun_mtu: 1500,
                tunnel_ipv6: true,
            },
            io: DatagramIoConfig {
                udp_socket_buffer: 262_144,
                tx_queue_len: 1024,
                tx_burst_packets: 16,
                packet_buffer_pool_size: 1024,
                udp_batch_size: 32,
            },
            reconnect: ReconnectPolicy {
                delay: Duration::from_secs(1),
                always: false,
            },
            hooks: LifecycleHooks {
                on_connect: None,
                on_disconnect: None,
                env: HashMap::new(),
            },
            activation_probe: None,
            device_state: None,
        }
    }

    #[test]
    fn accepts_successful_connect_status() {
        assert!(validate_connect_status("200").is_ok());
        assert!(validate_connect_status("204").is_ok());
    }

    #[test]
    fn preserves_connect_rejection_diagnostics() {
        let forbidden = validate_connect_status("403").unwrap_err().to_string();
        assert!(forbidden.contains("login failed or Access enrollment/certificate"));
        assert_eq!(
            validate_connect_status("500").unwrap_err().to_string(),
            "CONNECT rejected with status 500"
        );
    }

    #[test]
    fn generated_tls_material_uses_the_configured_identity_and_preserves_pin() {
        let endpoint_pin = vec![1, 2, 3, 4];
        let endpoint = MasqueEndpoint {
            addr: EndpointAddr("192.0.2.1:443".parse().unwrap()),
            host: "example.invalid".into(),
            endpoint_pub_key_spki_der: endpoint_pin.clone(),
        };
        let material =
            prepare_tls_material(&test_config(SecretKey::random(&mut OsRng)), &endpoint).unwrap();

        assert_eq!(material.endpoint_pub_key_spki_der, endpoint_pin);
        let cert_pem = std::fs::read(material.cert_pem_file.path()).unwrap();
        let cert_der = pem::parse(cert_pem).unwrap().into_contents();
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        let actual_spki = cert.tbs_certificate.subject_pki.raw.to_vec();
        assert!(verify_endpoint_key(&cert_der, &actual_spki));
        assert!(!verify_endpoint_key(&cert_der, b"different-spki"));
        assert!(!verify_endpoint_key(b"not-a-certificate", &actual_spki));

        let key_pem = std::fs::read_to_string(material.key_pem_file.path()).unwrap();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }
}
