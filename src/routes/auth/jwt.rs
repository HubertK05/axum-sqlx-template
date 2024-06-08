use anyhow::Context;
use axum::http::StatusCode;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use redis::{AsyncCommands, RedisResult};
use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;

use crate::{config::JwtConfiguration, errors::AppError, state::RdPool};

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
        let valid_until = jsonwebtoken::get_current_timestamp() + JWT_ACCESS_TOKEN_EXPIRY.whole_seconds() as u64;
        let token_id = Uuid::new_v4();
        
        Self {
            jti: token_id,
            sub: user_id,
            exp: valid_until,
            family: token_id,
        }
    }

    fn new_member(self) -> Self {
        let valid_until = jsonwebtoken::get_current_timestamp() + JWT_ACCESS_TOKEN_EXPIRY.whole_seconds() as u64;

        Self {
            jti: Uuid::new_v4(),
            sub: self.sub,
            exp: valid_until,
            family: self.family,
        }
    }
}

async fn init_token_family(
    rds: &mut RdPool,
    jwt_secrets: JwtConfiguration,
    user_id: Uuid,
) -> Result<(String, String), AppError> {
    let refresh_claims = Claims::family_root(user_id);
    let refresh_token = encode_jwt(refresh_claims, jwt_secrets.refresh_secret).context("Failed to encode JWT")?;

    let access_claims = refresh_claims.new_member();
    let access_token = encode_jwt(access_claims, jwt_secrets.access_secret).context("Failed to encode JWT")?;

    TokenFamily::set_valid(rds, refresh_claims).await?;

    Ok((access_token, refresh_token))
}

async fn continue_token_family(
    rds: &mut RdPool,
    jwt_secrets: JwtConfiguration,
    refresh_claims: Claims,
) -> Result<(String, String), AppError> {
    let new_refresh_claims = refresh_claims.new_member();
    let refresh_token = encode_jwt(new_refresh_claims, jwt_secrets.refresh_secret).context("Failed to encode JWT")?;
    
    let access_claims = refresh_claims.new_member();
    let access_token = encode_jwt(access_claims, jwt_secrets.access_secret).context("Failed to encode JWT")?;

    TokenFamily::set_valid(rds, refresh_claims).await?;

    Ok((access_token, refresh_token))
}

async fn refresh(
    rds: &mut RdPool,
    refresh_claims: Claims,
    jwt_secrets: JwtConfiguration,
) -> Result<(String, String), AppError> {
    if TokenFamily::is_valid_refresh_token(rds, refresh_claims).await? {
        continue_token_family(rds, jwt_secrets, refresh_claims).await
    } else {
        TokenFamily::invalidate(rds, refresh_claims.family).await?;
        Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid refresh token"))
    }
}

struct TokenFamily;

impl TokenFamily {
    async fn is_valid(rds: &mut RdPool, claims: Claims) -> RedisResult<bool> {
        Ok(rds.exists(valid_token(claims.family)).await?)
    }
    
    async fn is_valid_refresh_token(rds: &mut RdPool, claims: Claims) -> RedisResult<bool> {
        let valid_token_id: Uuid = rds.get(valid_token(claims.family)).await?;

        Ok(valid_token_id == claims.jti)
    }

    async fn set_valid(rds: &mut RdPool, claims: Claims) -> RedisResult<()> {
        Ok(rds.set(valid_token(claims.family),claims.jti).await?)
    }

    async fn invalidate(rds: &mut RdPool, family_id: Uuid) -> RedisResult<()> {
        Ok(rds.del(valid_token(family_id)).await?)
    }
}

fn encode_jwt(claims: Claims, secret: String) -> jsonwebtoken::errors::Result<String> {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

fn decode_jwt<'a>(token: &str, secret: impl Into<&'a [u8]>) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::default();
    validation.leeway = 5;

    let res = decode(
        token,
        &DecodingKey::from_secret(secret.into()),
        &validation
    )?;

    Ok(res.claims)
}
