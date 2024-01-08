use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use http::StatusCode;
use log::info;
use crate::backend::middlewares::RefreshUser;
use crate::utils::jwt::{create_token,Role};

pub async fn get_access(user: RefreshUser, jar: CookieJar) -> axum::response::Result<CookieJar> {
    info!("Get access JWT from refresh JWT");
    // User's refresh token is already checked through the extractor RefreshUser
    // You can trust the email given in the parameter "user"

    // Generate a JWT (JSON Web Token) for the user, specifying the user's email and the role as `Access`.
    // If token creation fails, return an `InternalServerError`.
    let jwt: String = create_token(user.email, Role::Access).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Construct a cookie to store the JWT. Set various properties for the cookie:
    // - Path: The cookie is valid for the root path ("/").
    // - HttpOnly: The cookie is not accessible via JavaScript (enhances security).
    // - Secure: The cookie is only sent over HTTPS.
    // - SameSite: Strictly enforce same-site policy for added security against CSRF attacks.
    let cookie = Cookie::build(("access", jwt))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict);

    // Add the constructed cookie to the cookie jar.
    let jar = jar.add(cookie);

    // Return the updated cookie jar as a successful result.
    Ok(jar)
}
