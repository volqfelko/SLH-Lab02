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

pub fn verify_token(token: &str) -> Result<()> {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);

    decode::<Claims>(token, &DecodingKey::from_secret(SECRET_KEY), &validation)
        .map(|_| ())
        .map_err(|e| anyhow!("Failed to verify JWT token: {}", e))
}

fn get_secret_key(role: &Role) -> Result<String> {
    let key = match role {
        Role::Access => "ACCESS_SECRET",
        Role::Refresh => "REFRESH_SECRET",
    };
    env::var(key).map_err(|_| anyhow!("Secret key for {:?} not found in environment", role))
}