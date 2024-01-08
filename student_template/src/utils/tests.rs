#[cfg(test)]
mod tests {
    use std::env;
    use http::StatusCode;
    use crate::utils::crypto::{hash_password, verify_password};
    use crate::utils::input::{is_email_valid, is_inputs_valid, is_password_strong};
    use crate::utils::jwt::{create_token, Role, verify_token};
    use rstest::rstest;
    use serial_test::serial;

    // Verify that hashing the same password multiple times produces different results
    #[test]
    fn hashing_same_password_generates_different_hashes() {
        let test_password = "secret123";
        let first_hash = hash_password(test_password).unwrap();
        let second_hash = hash_password(test_password).unwrap();

        assert_ne!(first_hash, second_hash, "Hashes of the same password should be different");
    }

    // Check if a very long password is hashed correctly
    #[test]
    fn hashing_long_password_creates_valid_hash() {
        let long_password = "b".repeat(1000);
        let password_hash = hash_password(&long_password).unwrap();

        assert!(!password_hash.is_empty(), "Hash of a long password should not be empty");
    }

    // Test verifying a password against its correct hash
    #[test]
    fn verify_password_with_correct_hash() {
        let original_password = "mypassword";
        let correct_hash = hash_password(original_password).unwrap();

        assert!(verify_password(original_password, &correct_hash), "Verification should succeed with correct hash");
    }

    // Ensure different passwords produce different hashes
    #[test]
    fn different_passwords_produce_unique_hashes() {
        let pass_one = "firstpass";
        let pass_two = "secondpass";

        let hash_one = hash_password(pass_one).unwrap();
        let hash_two = hash_password(pass_two).unwrap();

        assert_ne!(hash_one, hash_two, "Different passwords should have different hashes");
    }

    // Test hashing an empty password
    #[test]
    fn hashing_empty_password_results_in_non_empty_hash() {
        let empty_password = "";
        let result_hash = hash_password(empty_password).unwrap();

        assert!(!result_hash.is_empty(), "Hash of an empty password should not be empty");
    }

    // Test verifying a password against an incorrect hash
    #[test]
    fn verify_password_with_incorrect_hash() {
        let user_password = "user123";
        let wrong_hash = "incorrecthash";

        assert!(!verify_password(user_password, wrong_hash), "Verification should fail with an incorrect hash");
    }

    // Test verifying a password against an empty hash
    #[test]
    fn verify_password_with_empty_hash() {
        let some_password = "pass123";
        assert!(!verify_password(some_password, ""), "Verification should fail with an empty hash");
    }

    // Test verifying an empty password against a hash
    #[test]
    fn verify_empty_password_with_hash() {
        let any_password = "simplepass";
        let hash_for_password = hash_password(any_password).unwrap();

        assert!(!verify_password("", &hash_for_password), "Verification should fail with an empty password");
    }

    // Test verifying a correct password against a mismatched hash
    #[test]
    fn verify_correct_password_with_mismatched_hash() {
        let correct_password = "correctpass";
        let mismatched_hash = hash_password("anotherpass").unwrap();

        assert!(!verify_password(correct_password, &mismatched_hash), "Verification should fail with a mismatched hash");
    }

    // Test various email formats for validity
    #[test]
    fn email_validation_checks() {
        let valid_emails = [
            "contact@example.com",
            "name.surname@example.org",
            "alias+tag@example.net",
            "email@subdomain.example.com",
            "info@example.global"
        ];
        let invalid_emails = [
            "plainaddress",
            "@no-local-part.com",
            "no-at.domain",
            "double-dot@domain..com",
            " space@example.com"
        ];

        for email in valid_emails.iter() {
            assert!(is_email_valid(email), "Email '{email}' should be valid");
        }
        for email in invalid_emails.iter() {
            assert!(!is_email_valid(email), "Email '{email}' should be invalid");
        }
    }

    // Test password strength against various criteria
    #[test]
    fn password_strength_validation() {
        assert!(is_password_strong("$trong€rP@ssw0rd", "user@user.user"));
        let weak_passwords = ["weakpass", "commonpass", "short", "12345678", "abcdefgh"];

        for &password in weak_passwords.iter() {
            assert!(!is_password_strong(password, "user@example.com"), "Password '{password}' should be weak");
        }
    }

    // Validate login credentials with different scenarios
    #[test]
    fn login_credentials_validation() {
        let valid_login = ("user@user.user", "StrongPass123!", "StrongPass123!");
        assert_eq!(is_inputs_valid(valid_login.0, valid_login.1, valid_login.2), Ok(StatusCode::OK));

        let test_cases = [
            ("userexample.com", "StrongPass123!", "StrongPass123!", "Invalid email"),
            ("user@example.com", "short", "short", "Invalid password length"),
            ("user@example.com", "commonpassword", "commonpassword", "Password is too weak"),
            ("user@example.com", &"a".repeat(65), &"a".repeat(65), "Invalid password length"),
            ("user@example.com", "Password123", "Mismatch123", "Passwords not matching"),
        ];

        for &(email, pass1, pass2, message) in test_cases.iter() {
            assert_eq!(is_inputs_valid(email, pass1, pass2), Err((StatusCode::BAD_REQUEST, message)), "Test case with email '{email}' failed");
        }
    }

    fn set_environment_variables() {
        env::set_var("ACCESS_SECRET", "ultra_secret_test_access");
        env::set_var("REFRESH_SECRET", "ultra_secret_test_refresh");
    }

    fn remove_environment_variables() {
        env::remove_var("ACCESS_SECRET");
        env::remove_var("REFRESH_SECRET");
    }

    #[rstest]
    #[serial]
    fn jwt_verification_with_invalid_secret() {
        set_environment_variables();

        let token = create_token("example@example.com", Role::Access).unwrap();

        // Alter the secret to an invalid one
        env::set_var("ACCESS_SECRET", "invalid_secret");
        env::set_var("REFRESH_SECRET", "invalid_secret");

        assert!(verify_token(&token, Role::Access).is_err(), "Token verification should fail with an incorrect secret");

        remove_environment_variables();
    }

    #[rstest]
    #[serial]
    fn jwt_creation_and_validation() {
        set_environment_variables();

        for role in &[Role::Access, Role::Refresh] {
            let token = create_token("example@example.com", *role).unwrap();
            assert!(verify_token(&token, *role).is_ok(), "Token should be valid for the specified role");
        }

        remove_environment_variables();
    }

/* CHANGER LA LIGNE 26 dans jwt.rs pour set le token a moins de 10 secondes pour qu'il soit expiré
    #[rstest]
    #[serial]
    fn jwt_verification_for_expired_token() {
        set_environment_variables();

        let expired_token = create_token("expired@example.com", Role::Access).unwrap();
        std::thread::sleep(time::Duration::from_secs(10));

        assert!(verify_token(&expired_token, Role::Access).is_err(), "Token should be invalid after expiration");

        remove_environment_variables();
    }
*/
    #[rstest]
    #[serial]
    fn jwt_verification_with_invalid_role() {
        set_environment_variables();

        let token = create_token("role@example.com", Role::Access).unwrap();
        assert!(verify_token(&token, Role::Refresh).is_err(), "Token should not be valid for an incorrect role");

        remove_environment_variables();
    }

    #[rstest]
    #[serial]
    fn jwt_verification_of_malformed_token() {
        set_environment_variables();

        let malformed_token = "not.a.valid.token";
        assert!(verify_token(malformed_token, Role::Access).is_err(), "Malformed token should not pass verification");

        remove_environment_variables();
    }

    #[rstest]
    #[serial]
    fn jwt_creation_without_secret_keys() {
        remove_environment_variables();

        let access_token_result = create_token("example@example.com", Role::Access);
        assert!(access_token_result.is_err(), "Token creation should not succeed without secret keys");

        let refresh_token_result = create_token("example@example.com", Role::Refresh);
        assert!(refresh_token_result.is_err(), "Token creation should not succeed without secret keys");
    }

}