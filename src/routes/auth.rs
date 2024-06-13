use crate::{docutils::DocRouter, errors::AppError, state::AppState, AppRouter, AsyncRedisConn};
use axum::Router;
use lettre::Address;
use redis::{FromRedisValue, RedisResult, ToRedisArgs};
use serde::Deserialize;
use sqlx::PgPool;
use time::Duration;
use uuid::Uuid;

mod jwt;
mod oauth;
mod utils;

const VERIFICATION_EXPIRY: Duration = Duration::days(7);
const PASSWORD_CHANGE_EXPIRY: Duration = Duration::minutes(5);


pub fn router() -> DocRouter<AppState> {
    DocRouter::new()
        .nest("/oauth2", oauth::router())
        .merge(jwt::router())
        .merge(utils::router())
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
        expiry: Duration,
    ) -> Result<(), AppError> {
        Ok(rds
            .set_ex(Self::key(token), value, expiry.whole_seconds() as u64)
            .await?)
    }

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
