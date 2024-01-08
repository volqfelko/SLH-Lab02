use axum::Json;
use axum::response::{ErrorResponse, IntoResponse};
use http::StatusCode;
use log::info;
use tower_sessions::Session;
use crate::backend::middlewares::AccessUser;
use crate::backend::models::ChangePassword;
use crate::database::user;
use crate::utils::crypto::{hash_password, verify_password};
use crate::utils::input::is_inputs_valid;

pub async fn change_password (
    session: Session,
    user: AccessUser,
    Json(parameters): Json<ChangePassword>
) -> axum::response::Result<StatusCode> {
    info!("Changing user's password");

    // Check that the anti-CSRF token isn't expired
    let token_expiration = session.get::<i64>("csrf_expiration").or(Err(StatusCode::INTERNAL_SERVER_ERROR))?.ok_or(StatusCode::BAD_REQUEST)?;
    if token_expiration < time::OffsetDateTime::now_utc().unix_timestamp() {
        info!("Anti-CSRF token expired");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF token expired"))?;
    }

    // Compare the anti-CSRF token saved with the given one
    let token = session.get::<String>("csrf")
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::BAD_REQUEST)?;
    if token != parameters.csrf {
        info!("Anti-CSRF tokens don't match");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF tokens don't match"))?;
    }

    // Validate the password with same criteria as when registering.
    if let Err(e) = is_inputs_valid(&user.email, &parameters.password, &parameters.password2) {
        return Err(ErrorResponse::from(e.into_response()));
    }

    // Retrieve the user's details from the database.
    let db_user = user::get(&user.email)
        .ok_or((StatusCode::BAD_REQUEST, "User does not exist"))?;

    // Check if the old password provided matches the one in the database; return an error if it doesn't.
    if !verify_password(&parameters.old_password, &db_user.hash) {
        return Err((StatusCode::BAD_REQUEST, "Incorrect old password").into());
    }

    // Check if the new password is the same as the old password; return an error if they are the same.
    if &parameters.password == &parameters.old_password {
        return Err((StatusCode::BAD_REQUEST, "Old and new passwords are the same").into());
    }

    // Hash the new password, returning an internal server error if hashing fails.
    let hashed_password = hash_password(&parameters.password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password"))?;

    // Attempt to update the user's password in the database, returning an error if the update fails.
    user::change_password(&user.email, &hashed_password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update password"))?;

    // Return OK status if all the above operations are successful.
    Ok(StatusCode::OK)
}