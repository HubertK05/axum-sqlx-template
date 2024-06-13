use crate::auth::{check_password_strength, hash_password};
use crate::docutils::{DocRouter, get, post};
use crate::errors::AppError;
use crate::mailer::Mailer;
use crate::routes::auth::{
    update_password_by_email, verify_account, VerificationEntry, PASSWORD_CHANGE_EXPIRY,
};
use crate::state::{AppState, RdPool};
use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::{Json};
use lettre::Address;
use serde::Deserialize;
use sqlx::PgPool;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

pub fn router() -> DocRouter<AppState> {
    DocRouter::new()
        .route("/verify", get(verify_address)) // is currently GET, because there is no frontend and the request goes directly to the backend
        .route("/password", post(request_password_change))
        .route("/password/callback", post(change_password))
}

#[derive(Deserialize, ToSchema)]
struct PasswordChangeRequestInput {
    email: Address,
}

async fn request_password_change(
    State(mut rds): State<RdPool>,
    State(mailer): State<Mailer>,
    Json(body): Json<PasswordChangeRequestInput>,
) -> crate::Result<()> {
    let token = Uuid::new_v4();
    mailer
        .send_password_change_request_mail(token, body.email.clone(), Some(PASSWORD_CHANGE_EXPIRY))
        .await
        .context("Failed to send mail")?;
    VerificationEntry::set(
        &mut rds,
        token,
        body.email.to_string(),
        PASSWORD_CHANGE_EXPIRY,
    )
    .await?;

    Ok(())
}

#[derive(Deserialize, IntoParams)]
struct PasswordChangeTokenQuery {
    token: Uuid,
}

#[derive(Deserialize, ToSchema)]
struct PasswordChangeInput {
    password: String,
}

async fn change_password(
    State(db): State<PgPool>,
    State(mut rds): State<RdPool>,
    Query(q): Query<PasswordChangeTokenQuery>,
    Json(body): Json<PasswordChangeInput>,
) -> crate::Result<()> {
    let Some(target_address): Option<String> = VerificationEntry::get(&mut rds, q.token).await?
    else {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Access denied"));
    };

    let login = query!(
        r#"
        SELECT login
        FROM users
        WHERE email = $1
        "#,
        target_address
    )
    .fetch_one(&db)
    .await?
    .login;

    let mut inputs = vec![target_address.as_ref()];
    inputs.extend(login.as_deref());

    check_password_strength(&body.password, inputs.as_slice())?;

    // TODO consider converting to Address
    // let email = Address::try_from(target_address).unwrap();
    VerificationEntry::delete(&mut rds, q.token).await?;
    let hashed_password = hash_password(body.password);

    update_password_by_email(&db, target_address, hashed_password).await?;

    Ok(())
}

#[derive(Deserialize, IntoParams)]
struct VerificationToken {
    token: Uuid,
}

async fn verify_address(
    State(db): State<PgPool>,
    State(mut rds): State<RdPool>,
    Query(token): Query<VerificationToken>,
) -> crate::Result<()> {
    let Some(user_id) = VerificationEntry::get(&mut rds, token.token).await? else {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid token"));
    };

    verify_account(&db, user_id).await?;
    VerificationEntry::delete(&mut rds, token.token).await?;

    Ok(())
}
