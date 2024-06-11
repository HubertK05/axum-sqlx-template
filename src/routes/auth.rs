use crate::errors::{AppError, DbErrMap};
use crate::mailer::templates::AccountVerificationMail;
use crate::mailer::Mailer;
use crate::state::RdPool;
use crate::{AppRouter, AsyncRedisConn};
use anyhow::Context;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{async_trait, Json, RequestPartsExt, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use lettre::Address;
use redis::{AsyncCommands, Expiry, FromRedisValue, RedisError, RedisResult, ToRedisArgs};
use serde::Deserialize;
use sqlx::types::Uuid;
use sqlx::PgPool;
use std::str::FromStr;
use time::Duration;

pub mod jwt;
mod oauth;

const VERIFICATION_EXPIRY: Duration = Duration::days(7);
const PASSWORD_CHANGE_EXPIRY: Duration = Duration::minutes(5);

// /verify endpoint is currently GET, because there is no frontend and the request goes directly to the backend
pub fn router() -> AppRouter {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/session", get(session))
        .route("/verify", get(verify_address))
        .route("/password", post(request_password_change))
        .route("/password/callback", post(change_password))
        .nest("/oauth2", oauth::router())
}

#[derive(Deserialize)]
struct RegistrationForm {
    login: String,
    email: Address,
    password: String,
}

async fn register(
    jar: CookieJar,
    State(mut rds): State<RdPool>,
    State(db): State<PgPool>,
    State(mailer): State<Mailer>,
    Json(body): Json<RegistrationForm>,
) -> crate::Result<impl IntoResponse> {
    // TODO: check for session
    let entropy = zxcvbn::zxcvbn(&body.password, &[&body.login]);
    if let Some(feedback) = entropy.feedback() {
        let warning = feedback
            .warning()
            .map_or(String::from("No warning. "), |w| w.to_string());
        let suggestions = feedback
            .suggestions()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        return Err(AppError::exp(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Password is too weak: {warning}{suggestions}"),
        ));
    }

    let password_hash = hash(body.password);

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
        .send_verification_mail(
            token_id,
            &body.login,
            body.email,
            Some(VERIFICATION_EXPIRY),
        )
        .await
        .context("Failed to send verification mail")?;
    VerificationEntry::set(&mut rds, token_id, user_id).await?;

    let session_id = ClientSession::set(&mut rds, &user_id).await?;

    Ok(SessionCookie::add(jar, &session_id).into_response())
}

#[derive(Deserialize)]
struct LoginForm {
    login: String,
    password: String,
}
async fn login(
    jar: CookieJar,
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
            let session_id = ClientSession::set(&mut rds, &user_id).await?;
            return Ok(SessionCookie::add(jar, &session_id));
        }
        // here it is possible to return exact error but this information is helpful for both users and hackers
    }
    Err(AppError::exp(
        StatusCode::FORBIDDEN,
        "Invalid login credentials",
    )) // precise cause of error is hidden from the end user
}

#[derive(Deserialize)]
struct VerificationToken {
    token: Uuid,
}

async fn verify_address(
    State(db): State<PgPool>,
    State(mut rds): State<RdPool>,
    Query(token): Query<VerificationToken>,
) -> crate::Result<impl IntoResponse> {
    let Some(user_id) = VerificationEntry::get(&mut rds, token.token).await? else {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid token"));
    };

    verify_account(&db, user_id).await?;
    VerificationEntry::delete(&mut rds, token.token).await?;

    Ok(())
}

#[derive(Deserialize)]
struct PasswordChangeRequestInput {
    email: Address,
}

async fn request_password_change(
    State(mut rds): State<RdPool>,
    State(mailer): State<Mailer>,
    Json(body): Json<PasswordChangeRequestInput>,
) -> crate::Result<impl IntoResponse> {
    let token = Uuid::new_v4();
    mailer
        .send_password_change_request_mail(token, body.email.clone(), Some(PASSWORD_CHANGE_EXPIRY))
        .await
        .context("Failed to send mail")?;
    VerificationEntry::set(&mut rds, token, body.email.to_string()).await?;

    Ok(())
}

#[derive(Deserialize)]
struct PasswordChangeTokenQuery {
    token: Uuid,
}

#[derive(Deserialize)]
struct PasswordChangeInput {
    password: String,
}

async fn change_password(
    State(db): State<PgPool>,
    State(mut rds): State<RdPool>,
    Query(q): Query<PasswordChangeTokenQuery>,
    Json(body): Json<PasswordChangeInput>,
) -> crate::Result<impl IntoResponse> {
    // TODO check password strength
    let Some(target_address): Option<String> = VerificationEntry::get(&mut rds, q.token).await?
    else {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Access denied"));
    };
    // TODO consider converting to Address
    // let email = Address::try_from(target_address).unwrap();
    VerificationEntry::delete(&mut rds, q.token).await?;
    let hashed_password = hash(body.password);

    update_password_by_email(&db, target_address, hashed_password).await?;

    Ok(())
}

async fn logout(claims: Claims, State(mut rds): State<RdPool>) -> crate::Result<impl IntoResponse> {
    ClientSession::invalidate(&mut rds, &claims.session_id).await?;
    Ok(Html("Successfully logged out"))
}

async fn session(claims: Claims) -> crate::Result<impl IntoResponse> {
    Ok(Html(format!("{}", claims.user_id)))
}

struct ClientSession;

impl ClientSession {
    async fn set(rds: &mut RdPool, user_id: &Uuid) -> Result<Uuid, RedisError> {
        let session_id = Uuid::new_v4();
        rds.set_ex(Self::key(&session_id), user_id, 60 * 10).await?;
        Ok(session_id)
    }

    async fn get(rds: &mut RdPool, session_id: &Uuid) -> Result<Option<Uuid>, RedisError> {
        let user_id: Option<Uuid> = rds
            .get_ex(Self::key(session_id), Expiry::EX(60 * 10))
            .await?;
        Ok(user_id)
    }

    async fn invalidate(rds: &mut RdPool, session_id: &Uuid) -> Result<(), RedisError> {
        rds.del(Self::key(session_id)).await?;
        Ok(())
    }

    fn key(session_id: &Uuid) -> String {
        format!("session:{session_id}")
    }
}
struct SessionCookie;

impl SessionCookie {
    fn add(jar: CookieJar, session_id: &Uuid) -> CookieJar {
        jar.add(Cookie::build((SESSION_COOKIE_NAME, session_id.to_string())).build())
    }
}
pub struct Claims {
    pub session_id: Uuid,
    pub user_id: Uuid,
}

const SESSION_COOKIE_NAME: &str = "session";

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
    RdPool: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = parts.extract::<CookieJar>().await.unwrap();

        let Some(cookie) = jar.get(SESSION_COOKIE_NAME) else {
            return Err(AppError::exp(
                StatusCode::FORBIDDEN,
                "Authentication required",
            ));
        };

        let session_id = Uuid::from_str(cookie.value())
            .map_err(|_| AppError::exp(StatusCode::FORBIDDEN, "Session id must be a valid UUID"))?;

        let mut rds = RdPool::from_ref(state);
        let Some(user_id): Option<Uuid> = ClientSession::get(&mut rds, &session_id).await? else {
            return Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid session"));
        };

        Ok(Self {
            session_id,
            user_id,
        })
    }
}

struct VerificationEntry;

impl VerificationEntry {
    async fn set<T: ToRedisArgs + Send + Sync>(
        rds: &mut impl AsyncRedisConn,
        token: Uuid,
        value: T,
    ) -> Result<(), AppError> {
        Ok(rds
            .set_ex(
                Self::key(token),
                value,
                VERIFICATION_EXPIRY.whole_seconds() as u64,
            )
            .await?)
    }

    /// Retrieves user_id from token
    async fn get<T: FromRedisValue>(rds: &mut impl AsyncRedisConn, token: Uuid) -> RedisResult<T> {
        rds.get(Self::key(token)).await
    }

    async fn delete(rds: &mut impl AsyncRedisConn, token: Uuid) -> RedisResult<bool> {
        rds.del(Self::key(token)).await
    }

    fn key(token: Uuid) -> String {
        format!("verification:token:{token}")
    }
}

fn hash(password: String) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    argon
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn is_correct_password(password: String, password_hash: String) -> bool {
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

async fn verify_account(db: &PgPool, user_id: Uuid) -> Result<(), AppError> {
    query!(
        r#"
            UPDATE users
            SET verified = true
            WHERE id = $1
        "#,
        user_id
    )
    .execute(db)
    .await?;

    Ok(())
}

async fn update_password_by_email(
    db: &PgPool,
    email: String,
    new_password_hash: String,
) -> Result<(), AppError> {
    query!(
        r#"
            UPDATE users
            SET password = $1
            WHERE email = $2
        "#,
        new_password_hash,
        email,
    )
    .execute(db)
    .await?;

    Ok(())
}
