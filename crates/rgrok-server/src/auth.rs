use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

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
pub fn generate_token(secret: &str, label: &str, expires_in: Option<u64>) -> anyhow::Result<String> {
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
    let raw_token = token
        .strip_prefix("rgrok_tok_")
        .unwrap_or(token);

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
