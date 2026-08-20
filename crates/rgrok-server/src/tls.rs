use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::config::Config;
use crate::dns::CloudflareClient;
use crate::tunnel_manager::ServerState;

/// The source of the certificate used by the server.
///
/// This is kept separate from the loaded rustls configuration so startup can
/// decide whether a missing certificate is a development condition or an
/// ACME provisioning condition before generating a self-signed certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSource {
    /// A certificate and key explicitly configured by the operator.
    BringYourOwn,
    /// A certificate previously provisioned by ACME and cached on disk.
    CachedAcme,
    /// No certificate is available yet; Cloudflare ACME must provision one.
    AcmeProvision,
    /// No production certificate source is configured (development mode).
    SelfSigned,
}

/// Whether Cloudflare DNS-01 credentials are configured for ACME.
pub fn cloudflare_acme_configured(config: &Config) -> bool {
    !config.cloudflare.api_token.is_empty() && !config.cloudflare.zone_id.is_empty()
}

/// Select the certificate source used at startup.
pub fn select_tls_source(config: &Config) -> anyhow::Result<TlsSource> {
    let byo_cert = config.tls.cert_file.is_some();
    let byo_key = config.tls.key_file.is_some();
    if byo_cert != byo_key {
        anyhow::bail!("tls.cert_file and tls.key_file must be configured together");
    }
    if byo_cert {
        return Ok(TlsSource::BringYourOwn);
    }

    let cert_path = PathBuf::from(&config.tls.cert_dir).join("fullchain.pem");
    let key_path = PathBuf::from(&config.tls.cert_dir).join("privkey.pem");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => return Ok(TlsSource::CachedAcme),
        (true, false) | (false, true) => {
            anyhow::bail!(
                "incomplete cached ACME certificate in {} (fullchain.pem and privkey.pem are both required)",
                config.tls.cert_dir
            );
        }
        (false, false) => {}
    }

    if cloudflare_acme_configured(config) {
        Ok(TlsSource::AcmeProvision)
    } else if config.cloudflare.api_token.is_empty() && config.cloudflare.zone_id.is_empty() {
        Ok(TlsSource::SelfSigned)
    } else {
        anyhow::bail!("cloudflare.api_token and cloudflare.zone_id must be configured together");
    }
}

/// Load TLS configuration from the selected on-disk source, or generate the
/// development certificate. ACME provisioning is intentionally not performed
/// here because it is asynchronous and must happen before listeners start.
pub fn load_tls_config(config: &Config) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    match select_tls_source(config)? {
        TlsSource::BringYourOwn => {
            info!("Loading TLS certificates from files");
            load_from_files(
                config
                    .tls
                    .cert_file
                    .as_deref()
                    .expect("validated cert_file"),
                config.tls.key_file.as_deref().expect("validated key_file"),
            )
        }
        TlsSource::CachedAcme => {
            info!("Loading ACME certificates from {}", config.tls.cert_dir);
            let cert_path = PathBuf::from(&config.tls.cert_dir).join("fullchain.pem");
            let key_path = PathBuf::from(&config.tls.cert_dir).join("privkey.pem");
            load_from_files(
                cert_path.to_str().expect("certificate path is valid UTF-8"),
                key_path.to_str().expect("key path is valid UTF-8"),
            )
        }
        TlsSource::AcmeProvision => {
            anyhow::bail!("no TLS certificate found; Cloudflare ACME provisioning is required")
        }
        TlsSource::SelfSigned => {
            info!("Generating self-signed certificate for development");
            generate_self_signed(&config.server.domain)
        }
    }
}

/// Provision a wildcard TLS certificate via ACME DNS-01 challenge using Cloudflare.
///
/// Flow:
/// 1. Create or restore ACME account
/// 2. Order wildcard cert for *.domain + domain
/// 3. Complete DNS-01 challenges via Cloudflare TXT records
/// 4. Finalize order with CSR
/// 5. Download and save cert chain
/// 6. Clean up TXT records
pub async fn provision_wildcard_cert(config: &Config) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    use instant_acme::{
        Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
        OrderStatus,
    };

    let cf = CloudflareClient::new(
        config.cloudflare.api_token.clone(),
        config.cloudflare.zone_id.clone(),
    );

    // 1. Create or restore ACME account
    let account_path = PathBuf::from(&config.tls.cert_dir).join("acme_account.json");
    std::fs::create_dir_all(&config.tls.cert_dir)?;

    let account = if account_path.exists() {
        let creds_json = std::fs::read_to_string(&account_path)?;
        let creds: AccountCredentials = serde_json::from_str(&creds_json)?;
        Account::builder()
            .map_err(|e| anyhow::anyhow!("ACME builder: {}", e))?
            .from_credentials(creds)
            .await
            .map_err(|e| anyhow::anyhow!("ACME restore: {}", e))?
    } else {
        let directory_url = match config.tls.acme_env.as_str() {
            "production" => LetsEncrypt::Production.url().to_string(),
            _ => LetsEncrypt::Staging.url().to_string(),
        };
        let (account, creds) = Account::builder()
            .map_err(|e| anyhow::anyhow!("ACME builder: {}", e))?
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", config.tls.acme_email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url,
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("ACME create: {}", e))?;

        // Persist credentials for future restarts
        let creds_json = serde_json::to_string_pretty(&creds)?;
        std::fs::write(&account_path, &creds_json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&account_path, std::fs::Permissions::from_mode(0o600))?;
        }
        info!("Created new ACME account");
        account
    };

    // 2. Order wildcard cert
    let identifiers = vec![
        Identifier::Dns(format!("*.{}", config.server.domain)),
        Identifier::Dns(config.server.domain.clone()),
    ];

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| anyhow::anyhow!("ACME order: {}", e))?;

    // 3. Get authorizations and find DNS-01 challenges, create TXT records
    let mut txt_record_ids: Vec<String> = Vec::new();
    let challenge_domain = format!("_acme-challenge.{}", config.server.domain);

    {
        let mut auths = order.authorizations();
        while let Some(result) = auths.next().await {
            let mut auth = result.map_err(|e| anyhow::anyhow!("ACME auth: {}", e))?;
            let challenge = auth
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| anyhow::anyhow!("No DNS-01 challenge found"))?;
            let txt_value = challenge.key_authorization().dns_value();
            let record_id = cf.create_txt_record(&challenge_domain, &txt_value).await?;
            txt_record_ids.push(record_id);
            info!(domain = %challenge_domain, "Created ACME DNS-01 TXT record");
        }
    }

    // 4. Wait for DNS propagation
    info!("Waiting 30s for DNS propagation...");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // 5. Tell ACME server the challenges are ready
    {
        let mut auths = order.authorizations();
        while let Some(result) = auths.next().await {
            let mut auth = result.map_err(|e| anyhow::anyhow!("ACME auth: {}", e))?;
            if let Some(mut challenge) = auth.challenge(ChallengeType::Dns01) {
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| anyhow::anyhow!("ACME challenge ready: {}", e))?;
            }
        }
    }

    // 6. Poll for order to become ready
    let mut attempts = 0;
    loop {
        let state = order
            .refresh()
            .await
            .map_err(|e| anyhow::anyhow!("ACME refresh: {}", e))?;

        match state.status {
            OrderStatus::Ready => {
                info!("ACME order is ready for finalization");
                break;
            }
            OrderStatus::Pending => {
                attempts += 1;
                if attempts > 30 {
                    // Clean up TXT records before bailing
                    let _ = cf.delete_txt_records(&challenge_domain).await;
                    anyhow::bail!("ACME order still pending after 150s");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            OrderStatus::Invalid => {
                let _ = cf.delete_txt_records(&challenge_domain).await;
                anyhow::bail!("ACME order became invalid");
            }
            OrderStatus::Valid => {
                // Already valid (e.g. from a previous attempt), skip finalize
                break;
            }
            status => {
                let _ = cf.delete_txt_records(&challenge_domain).await;
                anyhow::bail!("Unexpected ACME order status: {:?}", status);
            }
        }
    }

    // 7. Generate private key + CSR, finalize the order
    let private_key = rcgen::KeyPair::generate()?;

    let mut params = rcgen::CertificateParams::new(vec![
        format!("*.{}", config.server.domain),
        config.server.domain.clone(),
    ])?;
    params.distinguished_name = rcgen::DistinguishedName::new();

    let csr = params.serialize_request(&private_key)?;

    if order.state().status != OrderStatus::Valid {
        order
            .finalize_csr(csr.der())
            .await
            .map_err(|e| anyhow::anyhow!("ACME finalize: {}", e))?;

        // Poll until valid
        let mut finalize_attempts = 0;
        loop {
            let state = order
                .refresh()
                .await
                .map_err(|e| anyhow::anyhow!("ACME refresh after finalize: {}", e))?;

            match state.status {
                OrderStatus::Valid => break,
                OrderStatus::Processing => {
                    finalize_attempts += 1;
                    if finalize_attempts > 20 {
                        let _ = cf.delete_txt_records(&challenge_domain).await;
                        anyhow::bail!("ACME order still processing after finalize");
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                status => {
                    let _ = cf.delete_txt_records(&challenge_domain).await;
                    anyhow::bail!("ACME order failed after finalize: {:?}", status);
                }
            }
        }
    }

    // 8. Download certificate chain
    let cert_pem = order
        .certificate()
        .await
        .map_err(|e| anyhow::anyhow!("ACME certificate: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No certificate returned by ACME"))?;

    // 9. Save to disk
    let key_pem = private_key.serialize_pem();
    save_cert(&cert_pem, &key_pem, &config.tls.cert_dir)?;

    // 10. Clean up TXT records
    cf.delete_txt_records(&challenge_domain).await?;
    info!("ACME wildcard certificate provisioned successfully");

    // Load the newly saved cert
    let cert_path = PathBuf::from(&config.tls.cert_dir).join("fullchain.pem");
    let key_path = PathBuf::from(&config.tls.cert_dir).join("privkey.pem");
    load_from_files(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
}

/// Load cert and key from PEM files
fn load_from_files(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let cert_data = std::fs::read(cert_path)?;
    let key_data = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_data[..]).collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut &key_data[..])?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Only advertise HTTP/1.1 — prevents clients from attempting h2
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Generate a self-signed certificate for development/testing
fn generate_self_signed(domain: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let subject_alt_names = vec![
        domain.to_string(),
        format!("*.{}", domain),
        "localhost".to_string(),
    ];

    let key_pair = rcgen::KeyPair::generate()?;
    let cert_params = rcgen::CertificateParams::new(subject_alt_names)?;
    let cert = cert_params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    Ok(Arc::new(config))
}

/// Save cert and key to disk
pub fn save_cert(cert_pem: &str, key_pem: &str, cert_dir: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(cert_dir)?;
    let cert_path = PathBuf::from(cert_dir).join("fullchain.pem");
    let key_path = PathBuf::from(cert_dir).join("privkey.pem");

    std::fs::write(&cert_path, cert_pem)?;
    std::fs::write(&key_path, key_pem)?;

    // Set restrictive permissions on the key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("Saved TLS certificates to {}", cert_dir);
    Ok(())
}

/// Create a TLS acceptor from a server config
#[allow(dead_code)]
pub fn make_acceptor(config: Arc<rustls::ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

/// Background loop that checks certificate expiry every 12 hours.
/// If the cert expires within 30 days, re-provisions via ACME and
/// sends the new config through the watch channel for hot-reload.
pub async fn cert_renewal_loop(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));

    // Skip the immediate first tick
    interval.tick().await;

    loop {
        interval.tick().await;

        // Only ACME-managed certificates should be renewed here. BYO
        // certificates are owned by the operator and self-signed development
        // certificates have no ACME account to renew them with.
        if !cloudflare_acme_configured(&state.config)
            || state.config.tls.cert_file.is_some()
            || state.config.tls.key_file.is_some()
        {
            continue;
        }

        // Check if cert expires within 30 days
        let cert_path = PathBuf::from(&state.config.tls.cert_dir).join("fullchain.pem");
        if !cert_path.exists() {
            continue;
        }

        match cert_expires_within(&cert_path, Duration::from_secs(30 * 24 * 3600)) {
            Ok(true) => {
                info!("Certificate expires within 30 days — starting renewal");
            }
            Ok(false) => {
                info!("Certificate still valid, skipping renewal");
                continue;
            }
            Err(e) => {
                warn!("Failed to check certificate expiry: {}", e);
                continue;
            }
        }

        // Re-provision
        match provision_wildcard_cert(&state.config).await {
            Ok(new_tls_config) => {
                info!("Certificate renewed successfully — hot-swapping TLS config");
                let _ = state.tls_config.send(Some(new_tls_config));
            }
            Err(e) => {
                tracing::error!("Certificate renewal failed: {}", e);
            }
        }
    }
}

/// Check if a PEM certificate file expires within the given duration.
fn cert_expires_within(cert_path: &PathBuf, threshold: Duration) -> anyhow::Result<bool> {
    let cert_data = std::fs::read(cert_path)?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_data[..]).collect::<Result<Vec<_>, _>>()?;

    let cert = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("No certificates found in PEM file"))?;

    // Parse the X.509 certificate to extract the notAfter field
    // We use a simple DER parser to extract the validity period
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {}", e))?;

    let not_after = parsed.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    let remaining = not_after - now;
    Ok(remaining < threshold.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(cert_dir: &str) -> Config {
        let mut config = Config::default();
        config.tls.cert_dir = cert_dir.to_string();
        config.cloudflare.api_token.clear();
        config.cloudflare.zone_id.clear();
        config
    }

    fn temp_cert_dir() -> PathBuf {
        std::env::temp_dir().join(format!("rgrok-tls-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn missing_certificate_uses_self_signed_only_without_cloudflare() {
        let cert_dir = temp_cert_dir();
        let config = test_config(cert_dir.to_str().unwrap());

        assert_eq!(select_tls_source(&config).unwrap(), TlsSource::SelfSigned);

        let _ = std::fs::remove_dir_all(cert_dir);
    }

    #[test]
    fn missing_certificate_requires_acme_when_cloudflare_is_configured() {
        let cert_dir = temp_cert_dir();
        let mut config = test_config(cert_dir.to_str().unwrap());
        config.cloudflare.api_token = "api-token".to_string();
        config.cloudflare.zone_id = "zone-id".to_string();

        assert_eq!(
            select_tls_source(&config).unwrap(),
            TlsSource::AcmeProvision
        );
        let error = load_tls_config(&config).unwrap_err().to_string();
        assert!(error.contains("ACME provisioning is required"), "{error}");

        let _ = std::fs::remove_dir_all(cert_dir);
    }

    #[test]
    fn cached_acme_certificate_is_selected_as_a_pair() {
        let cert_dir = temp_cert_dir();
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("fullchain.pem"), b"placeholder").unwrap();
        std::fs::write(cert_dir.join("privkey.pem"), b"placeholder").unwrap();

        let config = test_config(cert_dir.to_str().unwrap());
        assert_eq!(select_tls_source(&config).unwrap(), TlsSource::CachedAcme);

        let _ = std::fs::remove_dir_all(cert_dir);
    }

    #[test]
    fn incomplete_certificate_sources_are_rejected() {
        let cert_dir = temp_cert_dir();
        let mut config = test_config(cert_dir.to_str().unwrap());
        config.tls.cert_file = Some("cert.pem".to_string());
        assert!(select_tls_source(&config).is_err());

        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("fullchain.pem"), b"placeholder").unwrap();
        let config = test_config(cert_dir.to_str().unwrap());
        assert!(select_tls_source(&config).is_err());

        let _ = std::fs::remove_dir_all(cert_dir);
    }
}
