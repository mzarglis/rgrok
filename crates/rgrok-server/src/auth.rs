use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Default number of bcrypt verifications that may run concurrently.
///
/// bcrypt is deliberately CPU-intensive.  Keeping this limit separate from
/// Tokio's blocking-pool limit prevents an invalid-credential flood from
/// filling that pool with work that cannot make progress concurrently anyway.
const BASIC_AUTH_PERMIT_TIMEOUT: Duration = Duration::from_secs(1);

fn default_basic_auth_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1)
}

/// Runs password verification on Tokio's blocking pool with bounded
/// concurrency.
#[derive(Clone)]
pub struct BasicAuthVerifier {
    permits: Arc<Semaphore>,
}

impl Default for BasicAuthVerifier {
    fn default() -> Self {
        Self::new(default_basic_auth_concurrency())
    }
}

impl BasicAuthVerifier {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent.max(1))),
        }
    }

    async fn acquire_permit(&self) -> Option<OwnedSemaphorePermit> {
        tokio::time::timeout(
            BASIC_AUTH_PERMIT_TIMEOUT,
            self.permits.clone().acquire_owned(),
        )
        .await
        .ok()?
        .ok()
    }

    /// Verify a Basic authorization header without retaining its decoded
    /// (plaintext) credentials in the async request task while waiting for a
    /// permit.
    pub async fn verify_header(
        &self,
        header_value: &str,
        expected_username: &str,
        hash: &str,
    ) -> bool {
        let permit = match self.acquire_permit().await {
            Some(permit) => permit,
            None => return false,
        };

        // Clone sensitive values only after a permit is available, so an
        // arbitrarily large waiter queue does not retain credential strings.
        let header_value = header_value.to_owned();
        let expected_username = expected_username.to_owned();
        let hash = hash.to_owned();

        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            parse_basic_auth_header(&header_value)
                .map(|(user, pass)| {
                    user == expected_username && verify_basic_auth_password(&pass, &hash)
                })
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    #[cfg(test)]
    async fn run_blocking_for_test<T, F>(&self, operation: F) -> Option<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = self.acquire_permit().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        })
        .await
        .ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    pub jti: String,
    pub ver: u32,
}

/// Generate a signed JWT auth token
pub fn generate_token(
    secret: &str,
    label: &str,
    expires_in: Option<u64>,
) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let claims = TokenClaims {
        sub: label.to_string(),
        iat: now,
        exp: expires_in.map(|d| now + d),
        jti: uuid::Uuid::new_v4().to_string(),
        ver: 1,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    Ok(format!("rgrok_tok_{}", token))
}

/// Validate a JWT auth token, returning the claims if valid
pub fn validate_token(token: &str, secret: &str) -> anyhow::Result<TokenClaims> {
    let raw_token = token.strip_prefix("rgrok_tok_").unwrap_or(token);

    let mut validation = Validation::default();
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let token_data = decode::<TokenClaims>(
        raw_token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;

    // Manual expiry check (since some tokens have no exp)
    if let Some(exp) = token_data.claims.exp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if now > exp {
            anyhow::bail!("token has expired");
        }
    }

    Ok(token_data.claims)
}

/// Parse a "user:pass" basic auth string and hash the password with bcrypt
pub fn hash_basic_auth_password(password: &str) -> anyhow::Result<String> {
    Ok(bcrypt::hash(password, 10)?)
}

/// Verify a plaintext password against a bcrypt hash
pub fn verify_basic_auth_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Return a non-reversible cache key for an Authorization header.
pub fn auth_header_fingerprint(header_value: &str) -> [u8; 32] {
    Sha256::digest(header_value.as_bytes()).into()
}

/// Parse a base64-encoded Authorization header value for Basic auth
pub fn parse_basic_auth_header(header_value: &str) -> Option<(String, String)> {
    use base64::Engine;
    let encoded = header_value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded_str.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "a]3k9f!2mP#vR8xL$qW5nT@jB7cY0hG&";

    #[test]
    fn test_generate_and_validate_token() {
        let token = generate_token(TEST_SECRET, "test-laptop", None).unwrap();
        assert!(token.starts_with("rgrok_tok_"));

        let claims = validate_token(&token, TEST_SECRET).unwrap();
        assert_eq!(claims.sub, "test-laptop");
        assert_eq!(claims.ver, 1);
        assert!(claims.exp.is_none());
    }

    #[test]
    fn test_invalid_secret_rejects() {
        let token = generate_token(TEST_SECRET, "test", None).unwrap();
        assert!(validate_token(&token, "wrong-secret-that-is-long-enough-32").is_err());
    }

    #[test]
    fn test_parse_basic_auth() {
        // "admin:secret" base64 encoded
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        let (user, pass) = parse_basic_auth_header(&format!("Basic {}", encoded)).unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn test_bcrypt_password() {
        let hash = hash_basic_auth_password("mypassword").unwrap();
        assert!(verify_basic_auth_password("mypassword", &hash));
        assert!(!verify_basic_auth_password("wrongpassword", &hash));
    }

    #[tokio::test]
    async fn test_basic_auth_verifier_checks_header_without_blocking_async_task() {
        use base64::Engine;

        let verifier = BasicAuthVerifier::new(1);
        let hash = hash_basic_auth_password("mypassword").unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:mypassword");
        let header = format!("Basic {encoded}");

        assert!(verifier.verify_header(&header, "admin", &hash).await);
        assert!(!verifier.verify_header(&header, "other-user", &hash).await);

        let wrong_encoded = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        let wrong_header = format!("Basic {wrong_encoded}");
        assert!(!verifier.verify_header(&wrong_header, "admin", &hash).await);
    }

    #[tokio::test]
    async fn test_basic_auth_verifier_limits_concurrent_blocking_work() {
        let verifier = BasicAuthVerifier::new(1);
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();
        let first_verifier = verifier.clone();
        let first = tokio::spawn(async move {
            first_verifier
                .run_blocking_for_test(move || {
                    let _ = first_started_tx.send(());
                    release_first_rx.blocking_recv().unwrap();
                    1u8
                })
                .await
        });

        first_started_rx.await.unwrap();
        assert_eq!(verifier.available_permits(), 0);

        let (second_started_tx, mut second_started_rx) = tokio::sync::oneshot::channel();
        let second_verifier = verifier.clone();
        let second = tokio::spawn(async move {
            second_verifier
                .run_blocking_for_test(move || {
                    let _ = second_started_tx.send(());
                    2u8
                })
                .await
        });

        // The second operation cannot start until the first operation drops
        // its permit, and therefore remains pending while the first is held.
        assert_eq!(verifier.available_permits(), 0);
        assert!(matches!(
            second_started_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        release_first_tx.send(()).unwrap();
        assert_eq!(first.await.unwrap(), Some(1));
        second_started_rx.await.unwrap();
        assert_eq!(second.await.unwrap(), Some(2));
        assert_eq!(verifier.available_permits(), 1);
    }

    #[test]
    fn test_auth_header_fingerprint_is_stable_without_retaining_header() {
        let first = auth_header_fingerprint("Basic YWRtaW46cGFzcw==");
        let second = auth_header_fingerprint("Basic YWRtaW46cGFzcw==");
        let different = auth_header_fingerprint("Basic YWRtaW46d3Jvbmc=");

        assert_eq!(first, second);
        assert_ne!(first, different);
    }

    #[test]
    fn test_expired_token_rejected() {
        // Create a token that expired 100 seconds ago
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = TokenClaims {
            sub: "test".to_string(),
            iat: now - 200,
            exp: Some(now - 100), // expired 100s ago
            jti: uuid::Uuid::new_v4().to_string(),
            ver: 1,
        };

        let raw_token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap();

        let token = format!("rgrok_tok_{}", raw_token);
        let result = validate_token(&token, TEST_SECRET);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("expired"),
            "error should mention expiration"
        );
    }

    #[test]
    fn test_token_not_yet_expired_is_valid() {
        // Token that expires 1 hour from now should be valid
        let token = generate_token(TEST_SECRET, "valid-user", Some(3600)).unwrap();
        let claims = validate_token(&token, TEST_SECRET).unwrap();
        assert_eq!(claims.sub, "valid-user");
        assert!(claims.exp.is_some());
    }

    #[test]
    fn test_empty_token_rejected() {
        let result = validate_token("", TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_token_random_string_rejected() {
        let result = validate_token("rgrok_tok_not-a-valid-jwt-at-all", TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_token_no_prefix_random_string_rejected() {
        let result = validate_token("totallygarbage123!@#", TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_without_prefix_still_validates() {
        // validate_token strips the prefix if present but also works without it
        let token = generate_token(TEST_SECRET, "no-prefix", None).unwrap();
        let raw = token.strip_prefix("rgrok_tok_").unwrap();
        let claims = validate_token(raw, TEST_SECRET).unwrap();
        assert_eq!(claims.sub, "no-prefix");
    }
}
