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

fn access_whitelist(family_id: Uuid) -> String {
    format!("token:{family_id}:access:whitelist")
}

fn unused_refresh_list(family_id: Uuid) -> String {
    format!("token:{family_id}:refresh:unused")
}

fn used_refresh_list(family_id: Uuid) -> String {
    format!("token:{family_id}:refresh:used")
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
    RefreshToken::add_to_unused(rds, refresh_claims).await?;
    let refresh_token = encode_jwt(refresh_claims, jwt_secrets.refresh_secret).context("Failed to encode JWT")?;

    let access_token = AccessToken::create_from_refresh(rds, refresh_claims, jwt_secrets.access_secret).await?;

    Ok((refresh_token, access_token))
}

async fn continue_token_family(
    rds: &mut RdPool,
    jwt_secrets: JwtConfiguration,
    refresh_claims: Claims,
) -> Result<(String, String), AppError> {
    let new_refresh_claims = refresh_claims.new_member();
    RefreshToken::add_to_unused(rds, new_refresh_claims).await?;
    let refresh_token = encode_jwt(new_refresh_claims, jwt_secrets.refresh_secret).context("Failed to encode JWT")?;
    
    let access_token = AccessToken::create_from_refresh(rds, refresh_claims, jwt_secrets.access_secret).await?;

    Ok((refresh_token, access_token))
}

async fn refresh(
    mut rds: RdPool,
    refresh_claims: Claims,
    jwt_secrets: JwtConfiguration,
) -> Result<(String, String), AppError> {
    if RefreshToken::is_in_unused_list(&mut rds, refresh_claims).await? {
        RefreshToken::remove_from_unused(&mut rds, refresh_claims).await?;
        RefreshToken::add_to_used(&mut rds, refresh_claims).await?;

        continue_token_family(&mut rds, jwt_secrets, refresh_claims).await
    } else if RefreshToken::is_in_used_list(&mut rds, refresh_claims).await? {
        invalidate_family(&mut rds, refresh_claims.family).await?;
        Err(AppError::exp(StatusCode::FORBIDDEN, "Refresh token reuse detected"))
    } else {
        Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid refresh token"))
    }
}

struct AccessToken;

impl AccessToken {
    async fn create_from_refresh(rds: &mut RdPool, refresh_claims: Claims, access_secret: String) -> Result<String, AppError> {
        let access_claims = refresh_claims.new_member();
        AccessToken::add_to_whitelist(rds, access_claims).await?;
        let access_token = encode_jwt(access_claims, access_secret).context("Failed to encode JWT")?;

        Ok(access_token)
    }

    async fn add_to_whitelist(rds: &mut RdPool, claims: Claims) -> RedisResult<()> {
        Ok(rds
            .hset(
                access_whitelist(claims.family),
                claims.jti,
                claims.exp,
            )
            .await?)
    }

    async fn is_in_whitelist(rds: &mut RdPool, claims: Claims) -> RedisResult<bool> {
        let res: bool = rds
            .hexists(
                access_whitelist(claims.family),
                claims.jti,
            )
            .await?;

        Ok(res)
    }
}

struct RefreshToken;

impl RefreshToken {
    async fn add_to_unused(rds: &mut RdPool, claims: Claims) -> RedisResult<()> {
        Ok(rds
            .hset(
                unused_refresh_list(claims.family),
                claims.jti,
                claims.exp,
            )
            .await?)
    }

    async fn remove_from_unused(rds: &mut RdPool, claims: Claims) -> RedisResult<()> {
        Ok(rds
            .hdel(
                unused_refresh_list(claims.family),
                claims.jti,
            )
            .await?)
    }

    async fn add_to_used(rds: &mut RdPool, claims: Claims) -> RedisResult<()> {
        Ok(rds
            .hset(
                used_refresh_list(claims.family),
                claims.jti,
                claims.exp,
            )
            .await?)
    }

    async fn is_in_unused_list(rds: &mut RdPool, claims: Claims) -> RedisResult<bool> {
        let res: bool = rds
            .hexists(
                unused_refresh_list(claims.family),
                claims.jti,
            )
            .await?;

        Ok(res)
    }

    async fn is_in_used_list(rds: &mut RdPool, claims: Claims) -> RedisResult<bool> {
        let res: bool = rds
            .hexists(
                used_refresh_list(claims.family),
                claims.jti,
            )
            .await?;

        Ok(res)
    }
}

async fn invalidate_family(rds: &mut RdPool, family_id: Uuid) -> RedisResult<()> {
    let _: () = rds.del(used_refresh_list(family_id)).await?;
    let _: () = rds.del(unused_refresh_list(family_id)).await?;
    let _: () = rds.del(access_whitelist(family_id)).await?;
    Ok(())
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

/*

Access tokens:
Tokens that are used for short-term, direct access to endpoints.
They can be used multiple times, but we need to be aware of the access token whitelist.
If the access token is not in the whitelist, reject.
Logging out removes all access tokens of a given origin from the whitelist.
Detected refresh token reuse has the same effect as logging out.

Access token storage:
In each token, we store its id, expiry and origin.
In Redis, we can store up to 2 items if we want to use a hashmap. We store token id and expiry.
And the hashmap is stored in the origin's Redis key. We are able to purge expired tokens
and clear the entire hashmap stored in a given origin.

Refresh tokens:
The thing gets more complicated with refresh token.
The idea is: we want to store refresh tokens in "unused" and "used" hashmaps, also in the refresh token origin's Redis key.
A fresh refresh token is added to the "unused" list. When used, it is moved to the "used" list.
When used again, all lists are deleted to invalidate all tokens of a given origin.
Logging out has the same effect.
Refresh tokens are stored alongside with expiry times. Tokens can be safely purged only from the "unused" list.

The lists should be stored in Redis keys as hashmaps as follows:
access token whitelist - token:{origin_id}:access:whitelist
refresh token unused unused - token:{origin_id}:refresh:unused
refresh token used list - token:{origin_id}:refresh:used

*/






