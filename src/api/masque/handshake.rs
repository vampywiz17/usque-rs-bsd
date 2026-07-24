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
    use super::validate_connect_status;

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
}
