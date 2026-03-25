use rand::Rng;

const ADJECTIVES: &[&str] = &[
    "amber", "brave", "calm", "dark", "eager", "fair", "glad", "hale", "iron", "just", "keen",
    "lush", "mild", "neat", "open", "pale", "rare", "sage", "tall", "vast", "warm", "bold", "cool",
    "deep", "easy", "fast", "gold", "high", "jade", "kind", "lean", "moss", "nova", "opal", "pure",
    "ruby", "silk", "teal", "true", "vivid", "wise", "airy", "blue", "crisp", "dusk", "epic",
    "free", "gray", "hazy", "iced",
];

const NOUNS: &[&str] = &[
    "atlas", "beam", "coast", "dawn", "echo", "forge", "glow", "haven", "inlet", "jewel", "knoll",
    "lake", "mesa", "north", "orbit", "pine", "quest", "ridge", "shore", "tide", "unity", "vale",
    "wave", "yield", "zenith", "arch", "brook", "cliff", "delta", "field", "grove", "hill", "isle",
    "jade", "keep", "leaf", "marsh", "nest", "oak", "peak", "reef", "storm", "trail", "umber",
    "vine", "wind", "apex", "bay", "cove", "dune",
];

/// Generates a memorable, URL-safe subdomain like "amber-atlas-7f3a"
pub fn generate_subdomain() -> String {
    let mut rng = rand::rng();
    let adj = ADJECTIVES[rng.random_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.random_range(0..NOUNS.len())];
    let suffix: String = (0..4)
        .map(|_| format!("{:x}", rng.random::<u8>() & 0xF))
        .collect();
    format!("{}-{}-{}", adj, noun, suffix)
}

/// Validates that a subdomain is URL-safe and meets length requirements
pub fn validate_subdomain(subdomain: &str) -> Result<(), String> {
    if subdomain.len() < 3 {
        return Err("subdomain must be at least 3 characters".to_string());
    }
    if subdomain.len() > 40 {
        return Err("subdomain must be at most 40 characters".to_string());
    }
    if !subdomain
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(
            "subdomain may only contain lowercase letters, digits, and hyphens".to_string(),
        );
    }
    if subdomain.starts_with('-') || subdomain.ends_with('-') {
        return Err("subdomain must not start or end with a hyphen".to_string());
    }

    const RESERVED: &[&str] = &[
        "www",
        "api",
        "mail",
        "smtp",
        "ftp",
        "admin",
        "dashboard",
        "status",
        "health",
        "metrics",
        "internal",
    ];
    if RESERVED.contains(&subdomain) {
        return Err(format!("subdomain '{}' is reserved", subdomain));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_subdomain_format() {
        let sub = generate_subdomain();
        let parts: Vec<&str> = sub.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert!(ADJECTIVES.contains(&parts[0]));
        assert!(NOUNS.contains(&parts[1]));
        assert_eq!(parts[2].len(), 4);
    }

    #[test]
    fn test_validate_subdomain_valid() {
        assert!(validate_subdomain("myapp").is_ok());
        assert!(validate_subdomain("my-app-123").is_ok());
        assert!(validate_subdomain("abc").is_ok());
    }

    #[test]
    fn test_validate_subdomain_invalid() {
        assert!(validate_subdomain("ab").is_err()); // too short
        assert!(validate_subdomain("MY-APP").is_err()); // uppercase
        assert!(validate_subdomain("-myapp").is_err()); // starts with hyphen
        assert!(validate_subdomain("www").is_err()); // reserved
        assert!(validate_subdomain("api").is_err()); // reserved
    }
}
