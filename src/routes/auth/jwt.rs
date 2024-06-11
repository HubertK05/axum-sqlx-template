use anyhow::Context;
use axum::http::StatusCode;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use redis::{aio::ConnectionLike, AsyncCommands, RedisResult};
use redis_test::MockRedisConnection;
use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;

use crate::{config::JwtConfiguration, errors::AppError, state::RdPool, AsyncRedisConn};

const JWT_ACCESS_TOKEN_EXPIRY: Duration = Duration::minutes(5);
const JWT_REFRESH_TOKEN_EXPIRY: Duration = Duration::days(7);

fn valid_token(family_id: Uuid) -> String {
    format!("token:{family_id}:valid_token")
}

#[derive(Serialize, Deserialize, Clone, Copy)]
struct Claims {
    jti: Uuid,
    sub: Uuid,
    exp: u64,
    family: Uuid,
}

impl Claims {
    fn family_root(user_id: Uuid) -> Self {
        let valid_until =
            jsonwebtoken::get_current_timestamp() + JWT_ACCESS_TOKEN_EXPIRY.whole_seconds() as u64;
        let token_id = Uuid::new_v4();

        Self {
            jti: token_id,
            sub: user_id,
            exp: valid_until,
            family: token_id,
        }
    }

    fn new_member(self) -> Self {
        let valid_until =
            jsonwebtoken::get_current_timestamp() + JWT_ACCESS_TOKEN_EXPIRY.whole_seconds() as u64;

        Self {
            jti: Uuid::new_v4(),
            sub: self.sub,
            exp: valid_until,
            family: self.family,
        }
    }
}

async fn init_token_family(
    rds: &mut impl AsyncRedisConn,
    jwt_secrets: JwtConfiguration,
    user_id: Uuid,
) -> Result<(String, String), AppError> {
    let refresh_claims = Claims::family_root(user_id);
    register_tokens(rds, jwt_secrets, refresh_claims).await
}

async fn continue_token_family(
    rds: &mut impl AsyncRedisConn,
    jwt_secrets: JwtConfiguration,
    refresh_claims: Claims,
) -> Result<(String, String), AppError> {
    let new_refresh_claims = refresh_claims.new_member();
    register_tokens(rds, jwt_secrets, new_refresh_claims).await
}

async fn register_tokens(
    rds: &mut impl AsyncRedisConn,
    jwt_secrets: JwtConfiguration,
    refresh_claims: Claims,
) -> Result<(String, String), AppError> {
    let refresh_token =
        encode_jwt(refresh_claims, jwt_secrets.refresh_secret).context("Failed to encode JWT")?;

    let access_claims = refresh_claims.new_member();
    let access_token =
        encode_jwt(access_claims, jwt_secrets.access_secret).context("Failed to encode JWT")?;

    TokenFamily::set_valid(rds, refresh_claims).await?;

    Ok((access_token, refresh_token))
}

async fn refresh(
    rds: &mut impl AsyncRedisConn,
    refresh_claims: Claims,
    jwt_secrets: JwtConfiguration,
) -> Result<(String, String), AppError> {
    if TokenFamily::is_valid_refresh_token(rds, refresh_claims).await? {
        continue_token_family(rds, jwt_secrets, refresh_claims.new_member()).await
    } else {
        TokenFamily::invalidate(rds, refresh_claims.family).await?;
        Err(AppError::exp(
            StatusCode::FORBIDDEN,
            "Invalid refresh token",
        ))
    }
}

struct TokenFamily;

impl TokenFamily {
    async fn is_valid(rds: &mut impl AsyncRedisConn, claims: Claims) -> RedisResult<bool> {
        Ok(rds.exists(valid_token(claims.family)).await?)
    }

    async fn is_valid_refresh_token(
        rds: &mut impl AsyncRedisConn,
        claims: Claims,
    ) -> RedisResult<bool> {
        let valid_token_id: Uuid = rds.get(valid_token(claims.family)).await?;

        Ok(valid_token_id == claims.jti)
    }

    async fn set_valid(rds: &mut impl AsyncRedisConn, claims: Claims) -> RedisResult<()> {
        Ok(rds
            .set(valid_token(claims.family), claims.jti.to_string())
            .await?)
    }

    async fn invalidate(rds: &mut impl AsyncRedisConn, family_id: Uuid) -> RedisResult<()> {
        Ok(rds.del(valid_token(family_id)).await?)
    }
}

fn encode_jwt(claims: Claims, secret: impl Into<String>) -> jsonwebtoken::errors::Result<String> {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.into().as_bytes()),
    )
}

fn decode_jwt<'a>(token: &str, secret: impl Into<String>) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::default();
    validation.leeway = 5;

    let res = decode(
        token,
        &DecodingKey::from_secret(secret.into().as_bytes()),
        &validation,
    )?;

    Ok(res.claims)
}

#[cfg(test)]
mod tests {
    use redis::cmd;
    use redis_test::MockCmd;
    use uuid::uuid;

    use super::*;

    const USER_ID: Uuid = uuid!("9e208e34-1bad-4983-a83e-83337b2ded28");

    const FAMILY_ID: Uuid = uuid!("fb6ce66d-6959-4fa4-b118-798e1113f59f");

    const JWT_ACCESS_SECRET: &str = "access";
    const JWT_REFRESH_SECRET: &str = "refresh";

    fn jwt_secrets() -> JwtConfiguration {
        JwtConfiguration {
            access_secret: JWT_ACCESS_SECRET.to_string(),
            refresh_secret: JWT_REFRESH_SECRET.to_string(),
        }
    }

    #[test]
    fn token_family_created_with_good_user_id() {
        let claims = Claims::family_root(USER_ID);

        assert_eq!(claims.sub, USER_ID);
    }

    #[test]
    fn token_family_continued_with_good_family_id() {
        let claims = Claims::family_root(USER_ID);
        let new_claims = claims.new_member();

        assert_eq!(claims.family, new_claims.family);
    }

    #[test]
    fn valid_token_passes_validation() {
        let claims = Claims::family_root(USER_ID);

        let token = encode_jwt(claims, JWT_ACCESS_SECRET).unwrap();
        let res = decode_jwt(&token, JWT_ACCESS_SECRET);

        assert!(res.is_ok());
    }

    #[test]
    fn invalid_token_fails_validation() {
        let claims = Claims::family_root(USER_ID);

        let token = encode_jwt(claims, JWT_ACCESS_SECRET).unwrap();
        let malformed_token = &token[..token.len() - 1];
        let res = decode_jwt(malformed_token, JWT_ACCESS_SECRET);

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn create_family_sets_correct_valid_token_in_redis() {
        let refresh_claims = Claims::family_root(USER_ID);

        let mut conn = MockRedisConnection::new(vec![MockCmd::new(
            cmd("SET")
                .arg(valid_token(refresh_claims.family))
                .arg(refresh_claims.jti.to_string()),
            Ok("OK"),
        )]);

        let res = register_tokens(&mut conn, jwt_secrets(), refresh_claims).await;
        dbg!(&res);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn continue_family_changes_correct_valid_token_in_redis() {
        let old_refresh_claims = Claims::family_root(USER_ID);
        let new_refresh_claims = old_refresh_claims.new_member();

        let mut conn = MockRedisConnection::new(vec![MockCmd::new(
            cmd("SET")
                .arg(valid_token(old_refresh_claims.family))
                .arg(old_refresh_claims.jti.to_string()),
            Ok("OK"),
        )]);

        let res = register_tokens(&mut conn, jwt_secrets(), new_refresh_claims).await;
        dbg!(&res);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn invlidate_family_removes_correct_valid_token_in_redis() {
        let mut conn = MockRedisConnection::new(vec![MockCmd::new(
            cmd("DEL").arg(valid_token(FAMILY_ID)),
            Ok("OK"),
        )]);

        let res = TokenFamily::invalidate(&mut conn, FAMILY_ID).await;
        dbg!(&res);
        assert!(res.is_ok());
    }
}
