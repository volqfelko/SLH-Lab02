use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
    password_hash::Error as ArgonError,
};

// This function applies the Argon2 algorithm to securely hash a given password
// and returns the hashed password string or an error in case the hashing process encounters an issue.
pub fn hash_password(password: &str) -> Result<String, ArgonError> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

// Compares a plain text password with a hashed password using the Argon2 algorithm.
// It evaluates to true if the plain password, once hashed, matches the given hash; otherwise, it returns false.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let argon2 = Argon2::default();

    PasswordHash::new(hash)
        .map(|parsed_hash| argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
        .unwrap_or(false)
}