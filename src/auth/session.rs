use crate::errors::AppError;
use crate::state::RdPool;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::{async_trait, RequestPartsExt};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use redis::{AsyncCommands, Expiry, RedisError};
use std::str::FromStr;
use time::Duration;
use uuid::Uuid;
use crate::auth::safe_cookie;
use crate::config::AbsoluteUri;

const SESSION_COOKIE_NAME: &str = "session";
const SESSION_MAX_AGE: Duration = Duration::days(7);
pub struct Session;

impl Session {
    pub async fn set<'c>(rds: &mut RdPool, user_id: &Uuid) -> Result<Cookie<'c>, RedisError> {
        let session_id = Uuid::new_v4();
        rds.set_ex(Self::key(&session_id), user_id, 60 * 10).await?;
        Ok(safe_cookie((SESSION_COOKIE_NAME, session_id.to_string()), SESSION_MAX_AGE))
    }

    pub async fn get(rds: &mut RdPool, session_id: &Uuid) -> Result<Option<Uuid>, RedisError> {
        let user_id: Option<Uuid> = rds
            .get_ex(Self::key(session_id), Expiry::EX(60 * 10))
            .await?;
        Ok(user_id)
    }

    pub async fn invalidate(rds: &mut RdPool, session_id: &Uuid) -> Result<(), RedisError> {
        rds.del(Self::key(session_id)).await?;
        Ok(())
    }

    fn key(session_id: &Uuid) -> String {
        format!("session:{session_id}")
    }
}

pub struct Claims {
    pub session_id: Uuid,
    pub user_id: Uuid,
}

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
        let Some(user_id): Option<Uuid> = Session::get(&mut rds, &session_id).await? else {
            return Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid session"));
        };

        Ok(Self {
            session_id,
            user_id,
        })
    }
}
