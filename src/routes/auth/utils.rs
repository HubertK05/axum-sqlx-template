use crate::auth::{check_password_strength, hash_password};
use crate::docutils::{get, post, DocRouter};
use crate::errors::AppError;
use crate::mailer::Mailer;
use crate::routes::auth::{
    update_password_by_email, verify_account, VerificationEntry, PASSWORD_CHANGE_EXPIRY,
};
use crate::state::{AppState, RdPool};
use crate::AsyncRedisConn;
use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
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
    State(rds): State<RdPool>,
    State(mailer): State<Mailer>,
    Json(body): Json<PasswordChangeRequestInput>,
) -> crate::Result<()> {
    setup_password_change(rds, mailer, body.email).await
}

async fn setup_password_change(
    mut rds: impl AsyncRedisConn,
    mailer: Mailer,
    email: Address,
) -> crate::Result<()> {
    let token = Uuid::new_v4();
    VerificationEntry::set(&mut rds, token, email.to_string(), PASSWORD_CHANGE_EXPIRY).await?;
    mailer
        .send_password_change_request_mail(token, email, Some(PASSWORD_CHANGE_EXPIRY))
        .await
        .context("Failed to send mail")?;

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
    State(rds): State<RdPool>,
    Query(q): Query<PasswordChangeTokenQuery>,
    Json(body): Json<PasswordChangeInput>,
) -> crate::Result<()> {
    try_change_password(db, rds, q.token, body.password).await
}

async fn try_change_password(
    db: PgPool,
    mut rds: impl AsyncRedisConn,
    token: Uuid,
    password: String,
) -> crate::Result<()> {
    let Some(target_address): Option<String> = VerificationEntry::get(&mut rds, token).await?
    else {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Access denied"));
    };

    let login = select_login_by_email(&db, &target_address).await?;

    let mut inputs = vec![target_address.as_ref()];
    inputs.extend(login.as_deref());

    check_password_strength(&password, inputs.as_slice())?;

    // TODO consider converting to Address
    // let email = Address::try_from(target_address).unwrap();
    VerificationEntry::delete(&mut rds, token).await?;
    let hashed_password = hash_password(password);

    update_password_by_email(&db, target_address, hashed_password).await?;

    Ok(())
}

async fn select_login_by_email(
    db: &PgPool,
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

#[derive(Deserialize, IntoParams)]
struct VerificationToken {
    token: Uuid,
}

async fn verify_address(
    State(db): State<PgPool>,
    State(rds): State<RdPool>,
    Query(token): Query<VerificationToken>,
) -> crate::Result<()> {
    try_verify_address(db, rds, token.token).await
}

async fn try_verify_address(
    db: PgPool,
    mut rds: impl AsyncRedisConn,
    token: Uuid,
) -> crate::Result<()> {
    let Some(user_id) = VerificationEntry::get(&mut rds, token).await? else {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid token"));
    };

    verify_account(&db, user_id).await?;
    VerificationEntry::delete(&mut rds, token).await?;

    Ok(())
}
