use crate::{errors::AppError, AppRouter, AsyncRedisConn};
use axum::Router;
use lettre::Address;
use redis::{FromRedisValue, RedisResult, ToRedisArgs};
use serde::Deserialize;
use sqlx::PgPool;
use time::Duration;
use uuid::Uuid;

mod jwt;
mod oauth;
mod session;
mod utils;
// TODO add configuration
const IS_JWT_AUTH: bool = true;

const VERIFICATION_EXPIRY: Duration = Duration::days(7);
const PASSWORD_CHANGE_EXPIRY: Duration = Duration::minutes(5);

// /verify endpoint is currently GET, because there is no frontend and the request goes directly to the backend
pub fn router() -> AppRouter {
    let mut router = Router::new()
        .nest("/oauth2", oauth::router())
        .merge(utils::router());

    if IS_JWT_AUTH {
        router = router.merge(jwt::router())
    } else {
        router = router.merge(session::router())
    }
    router
}
pub async fn verify_account(db: &PgPool, user_id: Uuid) -> Result<(), AppError> {
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

pub async fn update_password_by_email(
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

pub struct VerificationEntry;

impl VerificationEntry {
    pub async fn set<T: ToRedisArgs + Send + Sync>(
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
    pub async fn get<T: FromRedisValue>(
        rds: &mut impl AsyncRedisConn,
        token: Uuid,
    ) -> RedisResult<T> {
        rds.get(Self::key(token)).await
    }

    pub async fn delete(rds: &mut impl AsyncRedisConn, token: Uuid) -> RedisResult<bool> {
        rds.del(Self::key(token)).await
    }

    fn key(token: Uuid) -> String {
        format!("verification:token:{token}")
    }
}
