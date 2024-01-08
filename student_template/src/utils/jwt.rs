use std::env;
use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, DecodingKey, encode, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum Role {
    Access,
    Refresh,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    sub: String,
    iat: usize,
    exp: usize,
    role: Role,
}

impl Claims {
    pub fn duration(role: Role) -> Duration {
        match role {
            Role::Access => Duration::hours(1),
            Role::Refresh => Duration::days(5),
        }
    }

    pub fn new<T: Into<String>>(email: T, role: Role, duration: Duration) -> Self {
        let now = Utc::now();
        Self {
            sub: email.into(),
            iat: now.timestamp() as usize,
            exp: (now + duration).timestamp() as usize,
            role,
        }
    }
}

// Function to create a JWT token based on user email and role.
pub fn create_token<T: Into<String>>(email: T, role: Role) -> Result<String> {
    let duration = Claims::duration(role);
    let claims = Claims::new(email, role, duration);
    let secret_key = get_secret_key(&role)?;

    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
        .map_err(|e| anyhow!("Failed to create JWT token: {}", e))
}

// Function to verify a JWT token and return the subject (email) if valid.
pub fn verify_token<T: Into<String>>(jwt: T, role: Role) -> Result<String> {
    let token = jwt.into();
    let secret_key = get_secret_key(&role)?;
    let curr_time = Utc::now().timestamp() as usize;

    let decoded_claim = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret_key.as_ref()),
        &Validation::default(),
    )?;

    validate_token_claims(&decoded_claim.claims, curr_time, role)?;

    Ok(decoded_claim.claims.sub)
}

// Validates the JWT token claims including issue time, expiration, and role.
fn validate_token_claims(claims: &Claims, current_time: usize, expected_role: Role) -> Result<()> {
    if claims.iat > current_time {
        return Err(anyhow!("JWT issued time is in the future"));
    }

    if claims.exp <= current_time {
        return Err(anyhow!("JWT has expired"));
    }

    if claims.role != expected_role {
        return Err(anyhow!("Invalid role in JWT"));
    }

    Ok(())
}


// Retrieves the secret key for a specific role from the environment variables.
fn get_secret_key(role: &Role) -> Result<String> {
    let key = match role {
        Role::Access => "ACCESS_SECRET",
        Role::Refresh => "REFRESH_SECRET",
    };
    env::var(key).map_err(|_| anyhow!("Secret key for {:?} not found in environment", role))
}