use std::cmp::max;
use crate::config::{AbsoluteUri, JwtConfiguration};
use crate::errors::AppError;
use crate::state::JwtKeys;
use crate::AsyncRedisConn;
use anyhow::Context;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::{async_trait, RequestPartsExt};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use redis::{cmd, AsyncCommands, RedisResult};
use redis_test::{MockCmd, MockRedisConnection};
use serde::{Deserialize, Serialize};
use time::{Duration};
use uuid::Uuid;
use crate::auth::safe_cookie;

const JWT_ACCESS_TOKEN_EXPIRY: Duration = Duration::minutes(5);
const JWT_REFRESH_TOKEN_EXPIRY: Duration = Duration::days(7);
pub const JWT_ACCESS_COOKIE_NAME: &str = "jwt-access";
pub const JWT_REFRESH_COOKIE_NAME: &str = "jwt-refresh";

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Claims {
    jti: Uuid,
    sub: Uuid,
    exp: u64,
    pub family: Uuid,
}

#[derive(Debug)]
pub struct TokenPair {
    access: String,
    refresh: String,
}

impl TokenPair {
    pub fn add_cookies(self, jar: CookieJar) -> CookieJar {
        let access = safe_cookie(
            (JWT_ACCESS_COOKIE_NAME, self.access),
            JWT_ACCESS_TOKEN_EXPIRY
        );
        let refresh = safe_cookie(
            (JWT_REFRESH_COOKIE_NAME, self.refresh),
            JWT_REFRESH_TOKEN_EXPIRY
        );

        jar.add(access).add(refresh)
    }
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
            exp: valid_until,
            ..self
        }
    }

    pub fn subject_id(&self) -> Uuid {
        self.sub
    }

    pub fn token_id(&self) -> Uuid {
        self.jti
    }

    fn family_id(&self) -> Uuid {
        self.family
    }
}

pub async fn init_token_family(
    rds: &mut impl AsyncRedisConn,
    jwt_secrets: &JwtKeys,
    user_id: Uuid,
) -> Result<TokenPair, AppError> {
    let refresh_claims = Claims::family_root(user_id);
    register_tokens(rds, jwt_secrets, refresh_claims).await
}

async fn continue_token_family(
    rds: &mut impl AsyncRedisConn,
    jwt_secrets: &JwtKeys,
    refresh_claims: Claims,
) -> Result<TokenPair, AppError> {
    let new_refresh_claims = refresh_claims.new_member();
    register_tokens(rds, jwt_secrets, new_refresh_claims).await
}

async fn register_tokens(
    rds: &mut impl AsyncRedisConn,
    jwt_keys: &JwtKeys,
    refresh_claims: Claims,
) -> Result<TokenPair, AppError> {
    let refresh_token =
        encode_jwt(refresh_claims, jwt_keys.encoding_refresh()).context("Failed to encode JWT")?;

    let access_claims = refresh_claims.new_member();
    let access_token =
        encode_jwt(access_claims, jwt_keys.encoding_access()).context("Failed to encode JWT")?;

    TokenFamily::set_valid(rds, refresh_claims).await?;

    Ok(TokenPair {
        access: access_token,
        refresh: refresh_token,
    })
}

pub async fn refresh(
    rds: &mut impl AsyncRedisConn,
    refresh_claims: Claims,
    jwt_secrets: JwtKeys,
) -> Result<TokenPair, AppError> {
    if TokenFamily::is_valid_refresh_token(rds, refresh_claims).await? {
        continue_token_family(rds, &jwt_secrets, refresh_claims.new_member()).await
    } else {
        TokenFamily::invalidate(rds, refresh_claims.family).await?;
        Err(AppError::exp(
            StatusCode::FORBIDDEN,
            "Invalid refresh token",
        ))
    }
}

pub async fn invalidate(rds: &mut impl AsyncRedisConn, family_id: Uuid) -> RedisResult<()> {
    TokenFamily::invalidate(rds, family_id).await
}

pub struct TokenFamily;

impl TokenFamily {
    async fn is_valid(rds: &mut impl AsyncRedisConn, claims: Claims) -> RedisResult<bool> {
        rds.exists(Self::key(claims.family_id())).await
    }

    async fn is_valid_refresh_token(
        rds: &mut impl AsyncRedisConn,
        claims: Claims,
    ) -> RedisResult<bool> {
        let valid_token_id: Option<Uuid> = rds.get(Self::key(claims.family_id())).await?;

        Ok(valid_token_id.map_or(false, |id| id == claims.jti))
    }

    async fn set_valid(rds: &mut impl AsyncRedisConn, claims: Claims) -> RedisResult<()> {
        rds.set(Self::key(claims.family_id()), claims.token_id())
            .await
    }

    async fn invalidate(rds: &mut impl AsyncRedisConn, family_id: Uuid) -> RedisResult<()> {
        rds.del(Self::key(family_id)).await
    }

    fn key(family_id: Uuid) -> String {
        format!("token:{family_id}:valid_token")
    }
}

fn encode_jwt(claims: Claims, secret_key: &EncodingKey) -> jsonwebtoken::errors::Result<String> {
    encode(&Header::default(), &claims, secret_key)
}

pub fn decode_jwt(token: &str, secret_key: &DecodingKey) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::default();
    validation.leeway = 5;

    let res = decode(token, secret_key, &validation)?;

    Ok(res.claims)
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
    JwtKeys: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = parts.extract::<CookieJar>().await.unwrap();
        let jwt_keys = JwtKeys::from_ref(state);
        let Some(cookie) = jar.get(JWT_ACCESS_COOKIE_NAME) else {
            return Err(AppError::exp(
                StatusCode::FORBIDDEN,
                "Authentication required",
            ));
        };

        return match decode_jwt(cookie.value(), jwt_keys.decoding_access()) {
            Ok(claims) => Ok(claims),
            Err(e) => {
                match e.kind() {
                    ErrorKind::InvalidToken => {}     // not a valid JWT
                    ErrorKind::InvalidSignature => {} // JWT content changed
                    ErrorKind::ExpiredSignature => {} // JWT expired
                    _ => error!("{e}"),
                }
                Err(AppError::exp(
                    StatusCode::FORBIDDEN,
                    "Authentication required",
                ))
            }
        };
    }
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

    fn jwt_keys() -> JwtKeys {
        JwtKeys::new(JWT_ACCESS_SECRET, JWT_REFRESH_SECRET)
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

        let keys = jwt_keys();
        let token = encode_jwt(claims, keys.encoding_access()).unwrap();
        let res = decode_jwt(&token, keys.decoding_access());

        assert!(res.is_ok());
    }

    #[test]
    fn invalid_token_fails_validation() {
        let claims = Claims::family_root(USER_ID);

        let keys = jwt_keys();
        let token = encode_jwt(claims, keys.encoding_access()).unwrap();
        let malformed_token = &token[..token.len() - 1];
        let res = decode_jwt(malformed_token, keys.decoding_access());

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn create_family_sets_correct_valid_token_in_redis() {
        let refresh_claims = Claims::family_root(USER_ID);

        let mut conn = MockRedisConnection::new(vec![MockCmd::new(
            cmd("SET")
                .arg(format!("token:{}:valid_token", refresh_claims.family_id()))
                .arg(refresh_claims.token_id()),
            Ok("OK"),
        )]);

        let res = register_tokens(&mut conn, &jwt_keys(), refresh_claims).await;
        dbg!(&res);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn continue_family_changes_correct_valid_token_in_redis() {
        let old_refresh_claims = Claims::family_root(USER_ID);
        let new_refresh_claims = old_refresh_claims.new_member();

        let mut conn = MockRedisConnection::new(vec![MockCmd::new(
            cmd("SET")
                .arg(format!(
                    "token:{}:valid_token",
                    old_refresh_claims.family_id()
                ))
                .arg(old_refresh_claims.jti.to_string()),
            Ok("OK"),
        )]);

        let res = register_tokens(&mut conn, &jwt_keys(), new_refresh_claims).await;
        dbg!(&res);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn invlidate_family_removes_correct_valid_token_in_redis() {
        let mut conn = MockRedisConnection::new(vec![MockCmd::new(
            cmd("DEL").arg(format!("token:{FAMILY_ID}:valid_token")),
            Ok("OK"),
        )]);

        let res = TokenFamily::invalidate(&mut conn, FAMILY_ID).await;
        dbg!(&res);
        assert!(res.is_ok());
    }
}
