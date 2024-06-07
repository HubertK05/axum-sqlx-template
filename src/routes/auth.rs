use crate::errors::AppError;
use crate::errors::AppError::Expected;
use crate::state::{AppState, RdPool};
use crate::AppRouter;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::{async_trait, Json, RequestPartsExt, Router};
use axum_extra::extract::CookieJar;
use redis::{AsyncCommands, Expiry, RedisError};
use serde::Deserialize;
use sqlx::types::Uuid;
use sqlx::PgPool;
use std::str::FromStr;
use axum::routing::{get, post};
use axum_extra::extract::cookie::Cookie;

mod oauth;

pub fn router() -> AppRouter {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/session", get(session))
        .nest("/oauth2", oauth::router())
}

#[derive(Deserialize)]
struct RegistrationForm {
    login: String,
    password: String,
}

async fn register(
    jar: CookieJar,
    State(mut rds): State<RdPool>,
    State(db): State<PgPool>,
    Json(body): Json<RegistrationForm>,
) -> crate::Result<impl IntoResponse> {
    // TODO: check for session
    let user_id = query!(
        r#"
    INSERT INTO users (login, password)
    VALUES ($1, $2)
    RETURNING id
    "#,
        &body.login,
        &body.password
    )
    .fetch_one(&db)
    .await?
    .id; // TODO: handle duplicate login error

    let session_id = Uuid::new_v4();
    rds.set_ex(format!("session:{session_id}"), user_id, 60 * 10)
        .await?;


    Ok(SessionCookie::add(jar, &session_id))
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
    let user_id = query!(
        r#"
    SELECT id FROM users
    WHERE login = $1 AND password = $2
    "#,
        &body.login,
        &body.password
    )
    .fetch_optional(&db)
    .await?
    .ok_or(AppError::exp(
        StatusCode::UNAUTHORIZED,
        "Invalid credentials",
    ))?
    .id;

    let session_id = ClientSession::set(&mut rds, &user_id).await?;

    Ok(SessionCookie::add(jar, &session_id))
}

async fn session(claims: Claims) -> crate::Result<impl IntoResponse> {
    Ok(Html(format!("{}", claims.user_id)))
}

struct ClientSession;

impl ClientSession {
    async fn set(rds: &mut RdPool, user_id: &Uuid) -> Result<Uuid, RedisError> {
        let session_id = Uuid::new_v4();
        rds.set_ex(Self::key(&session_id), user_id, 60*10).await?;
        Ok(session_id)
    }

    async fn get(rds: &mut RdPool, session_id: &Uuid) -> Result<Option<Uuid>, RedisError> {
        let user_id: Option<Uuid> = rds.get_ex(Self::key(session_id), Expiry::EX(60 * 10))
            .await?;
        Ok(user_id)
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
                StatusCode::UNAUTHORIZED,
                "Authentication required",
            ));
        };

        let session_id = Uuid::from_str(cookie.value()).map_err(|_| {
            AppError::exp(StatusCode::UNAUTHORIZED, "Session id must be a valid UUID")
        })?;

        let mut rds = RdPool::from_ref(state);
        let Some(user_id): Option<Uuid> = ClientSession::get(&mut rds, &session_id).await? else {
            return Err(AppError::exp(StatusCode::UNAUTHORIZED, "Invalid session"));
        };

        Ok(Self {
            session_id,
            user_id,
        })
    }
}
