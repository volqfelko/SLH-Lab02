use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
    password_hash::Error as ArgonError,
};

// Hashes a password using the Argon2 algorithm.
// Returns the hashed password or an error if hashing fails.
pub fn hash_password(password: &str) -> Result<String, ArgonError> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

// Verifies a password against a given hash.
// Returns true if the password matches the hash, false otherwise.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let argon2 = Argon2::default();

    PasswordHash::new(hash)
        .map(|parsed_hash| argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
        .unwrap_or(false)
}