use crate::{docutils::DocRouter, state::AppState, AsyncRedisConn};
use redis::{FromRedisValue, RedisResult, ToRedisArgs};
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


pub struct VerificationEntry;

impl VerificationEntry {
    pub async fn set<T: ToRedisArgs + Send + Sync>(
        rds: &mut impl AsyncRedisConn,
        token: Uuid,
        value: T,
        expiry: Duration,
    ) -> crate::Result<()> {
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
