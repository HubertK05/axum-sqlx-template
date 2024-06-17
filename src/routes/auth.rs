use crate::{docutils::DocRouter, state::AppState, AsyncRedisConn};
use redis::{FromRedisValue, RedisResult, ToRedisArgs};
use sqlx::PgExecutor;
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
pub struct User;

impl User {
    pub async fn insert(db: impl PgExecutor<'_>, password: Option<String>) -> sqlx::Result<Uuid> {
        Ok(query!(
            r#"
        INSERT INTO users (password, verified)
        VALUES ($1, true)
        RETURNING id
        "#,
            password
        )
        .fetch_one(db)
        .await?
        .id)
    }
    async fn insert_unverified(
        db: impl PgExecutor<'_>,
        login: impl AsRef<str>,
        password_hash: impl AsRef<str>,
        email: impl AsRef<str>,
    ) -> sqlx::Result<Uuid> {
        let user_id = query!(
            r#"
        INSERT INTO users (login, password, email, verified)
        VALUES ($1, $2, $3, false)
        RETURNING id
        "#,
            login.as_ref(),
            password_hash.as_ref(),
            email.as_ref(),
        )
        .fetch_one(db)
        .await
        .map(|r| r.id)?;

        Ok(user_id)
    }

    pub async fn verify(db: impl PgExecutor<'_>, user_id: &Uuid) -> sqlx::Result<()> {
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
        db: impl PgExecutor<'_>,
        email: String,
        new_password_hash: String,
    ) -> sqlx::Result<()> {
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
    pub async fn select_login_by_email(
        db: impl PgExecutor<'_>,
        address: impl AsRef<str>,
    ) -> sqlx::Result<Option<String>> {
        let login = query!(
            r#"
        SELECT login
        FROM users
        WHERE email = $1
        "#,
            address.as_ref()
        )
        .fetch_one(db)
        .await?
        .login;

        Ok(login)
    }
    pub async fn select_password_by_login(
        db: impl PgExecutor<'_>,
        login: impl AsRef<str>,
    ) -> sqlx::Result<Option<(Uuid, Option<String>)>> {
        let res = query!(
            r#"
    SELECT id, password FROM users
    WHERE login = $1
    "#,
            login.as_ref()
        )
        .fetch_optional(db)
        .await?
        .map(|r| (r.id, r.password));

        Ok(res)
    }
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
