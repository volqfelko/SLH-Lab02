use http::StatusCode;
use log::error;
use regex::Regex;
use zxcvbn::zxcvbn;
use once_cell::sync::Lazy;
use crate::consts::{VALID_EMAIL, MIN_STRENGTH_PASSWORD, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH};

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(VALID_EMAIL).expect("Invalid regex pattern for email")
});

pub fn validate_email(email: &str) -> bool {
    EMAIL_REGEX.is_match(email)
}

pub fn validate_password(password: &str, email: &str) -> bool {
    match zxcvbn(password, &[email]) {
        Ok(result) => result.score() >= MIN_STRENGTH_PASSWORD,
        Err(e) => {
            error!("Error while checking password strength: {:?}", e);
            false
        },
    }
}

pub fn validate_login(email: &str, password1: &str, password2: &str) -> Result<StatusCode, (StatusCode, &'static str)> {
    if !validate_email(email) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email"));
    }

    if password1 != password2 {
        return Err((StatusCode::BAD_REQUEST, "Passwords not matching"));
    }

    if password1.len() < MIN_PASSWORD_LENGTH || password1.len() > MAX_PASSWORD_LENGTH {
        return Err((StatusCode::BAD_REQUEST, "Invalid password length"));
    }

    if !validate_password(password1, email) {
        return Err((StatusCode::BAD_REQUEST, "Password is too weak"));
    }

    Ok(StatusCode::OK)
}