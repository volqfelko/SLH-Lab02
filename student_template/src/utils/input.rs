use http::StatusCode;
use log::error;
use regex::Regex;
use zxcvbn::zxcvbn;
use once_cell::sync::Lazy;
use crate::consts::{VALID_EMAIL, PASSWORD_MINIMUM_STRENGTH, PASSWORD_MAXIMUM_LENGTH, PASSWORD_MINIMUM_LENGTH};

static VALID_EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(VALID_EMAIL).expect("Invalid regex for validating email")
});
pub fn is_email_valid(user_email: &str) -> bool {
    VALID_EMAIL_PATTERN.is_match(user_email)
}

pub fn is_password_strong(user_password: &str, associated_email: &str) -> bool {
    match zxcvbn(user_password, &[associated_email]) {
        Ok(analysis) => analysis.score() >= PASSWORD_MINIMUM_STRENGTH,
        Err(error) => {
            error!("Password strength evaluation error: {:?}", error);
            false
        },
    }
}

pub fn is_inputs_valid(email: &str, password1: &str, password2: &str) -> Result<StatusCode, (StatusCode, &'static str)> {
    if !is_email_valid(email) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email"));
    }

    if password1 != password2 {
        return Err((StatusCode::BAD_REQUEST, "Passwords not matching"));
    }

    if password1.len() < PASSWORD_MINIMUM_LENGTH || password1.len() > PASSWORD_MAXIMUM_LENGTH {
        return Err((StatusCode::BAD_REQUEST, "Invalid password length"));
    }

    if !is_password_strong(password1, email) {
        return Err((StatusCode::BAD_REQUEST, "Password is too weak"));
    }

    Ok(StatusCode::OK)
}