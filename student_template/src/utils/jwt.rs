use std::env;
use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, DecodingKey, encode, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

use crate::consts::{ACCESS_TOKEN_EXPIRATION_HOURS, REFRESH_TOKEN_EXPIRATION_DAYS};

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
            Role::Access => Duration::hours(ACCESS_TOKEN_EXPIRATION_HOURS),
            Role::Refresh => Duration::days(REFRESH_TOKEN_EXPIRATION_DAYS),
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

pub fn verify<T: Into<String>>(jwt: T, role: Role) -> Result<String> {
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

// Function to validate token claims.
fn validate_token_claims(claims: &Claims, current_time: usize, expected_role: Role) -> Result<()> {
    // Check if JWT was issued in the future.
    if claims.iat > current_time {
        return Err(anyhow!("JWT issued time is in the future"));
    }

    // Check if JWT has expired.
    if claims.exp <= current_time {
        return Err(anyhow!("JWT has expired"));
    }

    // Validate role in JWT.
    if claims.role != expected_role {
        return Err(anyhow!("Invalid role in JWT"));
    }

    Ok(())
}


fn get_secret_key(role: &Role) -> Result<String> {
    let key = match role {
        Role::Access => "ACCESS_SECRET",
        Role::Refresh => "REFRESH_SECRET",
    };
    env::var(key).map_err(|_| anyhow!("Secret key for {:?} not found in environment", role))
}