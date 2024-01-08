use axum::Json;
use crate::backend::models::{NewUser, UserLogin, Token};
use axum::http::StatusCode;
use axum::response::{ErrorResponse, Html, IntoResponse, Redirect};
use log::{debug, info, trace, warn};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tower_sessions::Session;
use uuid::Uuid;
use crate::{database, HBS};
use crate::backend::middlewares::AccessUser;
use axum::extract::Path;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use crate::database::email::Email;

use crate::database::{token, user};
use crate::utils::crypto::{verify_password, hash_password};
use crate::email::{get_verification_url, send_mail};
use crate::utils::jwt::{create_token, Role, Claims};
use crate::utils::input::is_inputs_valid;

fn process_new_user_inputs(new_user: &NewUser) -> Result<(String, &str), ErrorResponse> {
    // Process and check new user's email and password for validity
    let processed_email = new_user.email.trim().to_lowercase();
    is_inputs_valid(&processed_email, &new_user.password, &new_user.password2)?;
    Ok((processed_email, &new_user.password))
}

fn create_and_store_email_token(user_email: &str) -> Result<String, (StatusCode, &'static str)> {
    // Create a unique token for the email
    let token_for_email = Uuid::new_v4().to_string();

    // Store the newly created email token in the database
    let token_lifetime = Claims::duration(Role::Access).to_std().unwrap();
    token::add(user_email, &token_for_email, token_lifetime)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Error in database transaction"))?;

    Ok(token_for_email)
}

fn send_confirmation_email(user_email: &str, token: &str) -> Result<(), (StatusCode, &'static str)> {
    // Attempt to dispatch a verification email and manage any errors
    send_mail(user_email, "Verify Your Email Address", &get_verification_url(token))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Error sending verification email"))?;

    Ok(())
}

pub async fn register(Json(user): Json<NewUser>) -> axum::response::Result<StatusCode> {
    info!("Register new user");

    // Process user input for email and password
    let (email, password) = process_new_user_inputs(&user)?;

    // Encrypt the user password, return error if encryption fails
    let hash = hash_password(&password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Password encryption error"))?;

    // Add new user to database, return error if creation fails
    user::create(&email, &hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "User creation in database failed"))?;

    // Generate and store a token for email verification, return error if this fails
    let email_token = create_and_store_email_token(&email)?;

    // Dispatch an email for account confirmation, return error if sending fails
    send_confirmation_email(&email, &email_token)?;

    // Return a status indicating successful creation
    Ok(StatusCode::CREATED)
}


pub async fn verify(Path(token): Path<String>) -> Redirect {
    let result = match token::consume(token) {
        Ok(email) => {
            if user::verify(&email).is_ok() {
                info!("User successfully verified: {}", email);
                Redirect::to("/?verify=ok")
            } else {
                warn!("User failed to verify");
                Redirect::to("/?verify=failed")
            }
        }
        Err(e) => {
            warn!("Failed to consume token: {}", e);
            Redirect::to("/?verify=failed")
        }
    };

    result
}

pub async fn login(Json(user_login): Json<UserLogin>) -> axum::response::Result<Json<Token>> {
    info!("Login user");

    // Normalize email and check user's verification status
    let user_email = user_login.email.trim().to_ascii_lowercase();
    if !user::verified(&user_email).unwrap_or(false) {
        warn!("User not verified: {}", user_email);
        return Err(ErrorResponse::from((StatusCode::UNAUTHORIZED, "Account not verified")));
    }

    // Fetch user from database and authenticate, returning error for invalid credentials
    let database_user = user::get(&user_email)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid email or password"))?;
    if !verify_password(&user_login.password, &database_user.hash) {
        warn!("Invalid password for user: {}", user_email);
        return Err(ErrorResponse::from((StatusCode::UNAUTHORIZED, "Invalid email or password")));
    }

    // Generate a new JWT for the user, reporting error if token generation fails
    let access_token = create_token(&user_email, Role::Refresh)
        .map_err(|_| ErrorResponse::from((StatusCode::INTERNAL_SERVER_ERROR, "Error generating access token")))?;

    Ok(Json(Token { token: access_token }))
}

/// Serve index page
/// If the user is logged, add a anti-CSRF token to the password change form
pub async fn home(
    session: Session,
    user: Option<AccessUser>,
) -> axum::response::Result<impl IntoResponse> {
    trace!("Serving home");

    // Create anti-CSRF token if the user is logged
    let infos = match user {
        Some(user) => {
            debug!("Add anti-CSRF token to home");

            // Generate anti-CSRF token
            let token = Uuid::new_v4().to_string();
            let expiration = OffsetDateTime::now_utc() + Duration::minutes(10);

            // Add token+exp to session
            session.insert("csrf", token.clone()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
            session.insert("csrf_expiration", expiration.unix_timestamp()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

            Some(json!({"email": user.email, "token": token}))
        },
        None => None, // Can't use user.map, async move are experimental
    };

    Ok(Html(HBS.render("index", &infos).unwrap()))
}
/// DEBUG/ADMIN endpoint
/// List pending emails to send
pub async fn email(Path(email): Path<String>) -> axum::response::Result<Json<Vec<Email>>> {
    let emails = database::email::get(&email).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(emails.into())
}
pub async fn logout(jar: CookieJar) -> (CookieJar, Redirect) {
    let jar = jar.remove(Cookie::from("access"));
    (jar, Redirect::to("/"))
}
pub async fn login_page() -> impl IntoResponse {
    Html(HBS.render("login", &Some(())).unwrap())
}
