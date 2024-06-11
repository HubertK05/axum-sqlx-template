use anyhow::Context;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{async_trait, debug_handler, Json, RequestPartsExt, Router};
use axum_extra::extract::CookieJar;
use redis::{aio::ConnectionLike, AsyncCommands, RedisResult};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::jwt::{init_token_family, invalidate, refresh_jwt_session, Claims};
use crate::auth::{PasswordStrength, hash_password, is_correct_password, LoginForm, RegistrationForm};
use crate::errors::DbErrMap;
use crate::mailer::Mailer;
use crate::routes::auth::{VerificationEntry, VERIFICATION_EXPIRY};
use crate::state::{AppState, JwtKeys};
use crate::{config::JwtConfiguration, errors::AppError, state::RdPool, AppRouter, AsyncRedisConn};

pub fn router() -> AppRouter {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_session))
        .route("/session", get(session))
}

async fn register(
    jar: CookieJar,
    State(mut rds): State<RdPool>,
    State(jwt_keys): State<JwtKeys>,
    State(mailer): State<Mailer>,
    State(db): State<PgPool>,
    Json(body): Json<RegistrationForm>, 
) -> crate::Result<impl IntoResponse> {
    // TODO: check for session
    body.check_password_strength()?;

    let password_hash = hash_password(body.password);

    let user_id = query!(
        r#"
        INSERT INTO users (login, password, email, verified)
        VALUES ($1, $2, $3, false)
        RETURNING id
        "#,
        &body.login.as_str(),
        password_hash,
        AsRef::<str>::as_ref(&body.email),
    )
    .fetch_one(&db)
    .await
    .map_db_err(|e| {
        e.unique(
            StatusCode::CONFLICT,
            "Cannot create user with provided data",
        )
    })?
    .id;

    let token_id = Uuid::new_v4();
    // TODO: reconsider changing order of sending email and creating a token entry in Redis
    mailer
        .send_verification_mail(token_id, &body.login, body.email, Some(VERIFICATION_EXPIRY))
        .await
        .context("Failed to send verification mail")?;
    VerificationEntry::set(&mut rds, token_id, user_id, VERIFICATION_EXPIRY).await?;

    let tokens = init_token_family(&mut rds, &jwt_keys, user_id).await?;

    Ok(tokens.add_cookies(jar))
}

async fn login(
    jar: CookieJar,
    State(jwt_keys): State<JwtKeys>,
    State(mut rds): State<RdPool>,
    State(db): State<PgPool>,
    Json(body): Json<LoginForm>,
) -> crate::Result<impl IntoResponse> {
    // TODO: check for session
    let (user_id, password_hash) = query!(
        r#"
    SELECT id, password FROM users
    WHERE login = $1
    "#,
        &body.login
    )
    .fetch_optional(&db)
    .await?
    .ok_or(AppError::exp(StatusCode::FORBIDDEN, "Invalid credentials"))
    .map(|r| (r.id, r.password))?;

    if let Some(password_hash) = password_hash {
        if is_correct_password(body.password, password_hash) {
            let tokens = init_token_family(&mut rds, &jwt_keys, user_id).await?;
            return Ok(tokens.add_cookies(jar));
        }
        // here it is possible to return exact error but this information is helpful for both users and hackers
    }
    Err(AppError::exp(
        StatusCode::FORBIDDEN,
        "Invalid login credentials",
    )) // precise cause of error is hidden from the end user
}

#[debug_handler(state = AppState)]
async fn refresh_session(
    State(jwt_keys): State<JwtKeys>,
    State(mut rds): State<RdPool>,
    jar: CookieJar,
) -> crate::Result<impl IntoResponse> {
    refresh_jwt_session(&mut rds, jar, jwt_keys).await
}

async fn logout(claims: Claims, State(mut rds): State<RdPool>) -> crate::Result<impl IntoResponse> {
    invalidate(&mut rds, claims.family).await?;
    Ok(Html("Successfully logged out"))
}

async fn session(claims: Claims) -> crate::Result<impl IntoResponse> {
    Ok(Html(format!("{}", claims.subject_id())))
}
