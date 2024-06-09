use crate::auth::session::Claims;
use crate::auth::session::Session;
use crate::auth::{hash_password, is_correct_password, LoginForm, RegistrationForm};
use crate::errors::{AppError, DbErrMap};
use crate::state::RdPool;
use crate::AppRouter;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use sqlx::PgPool;

pub fn router() -> AppRouter {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/session", get(session))
}

async fn register(
    jar: CookieJar,
    State(mut rds): State<RdPool>,
    State(db): State<PgPool>,
    Json(body): Json<RegistrationForm>,
) -> crate::Result<impl IntoResponse> {
    // TODO: check for session
    let entropy = zxcvbn::zxcvbn(&body.password, &[&body.login]);
    if let Some(feedback) = entropy.feedback() {
        let warning = feedback
            .warning()
            .map_or(String::from("No warning. "), |w| w.to_string());
        let suggestions = feedback
            .suggestions()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        return Err(AppError::exp(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Password is too weak: {warning}{suggestions}"),
        ));
    }

    let password_hash = hash_password(body.password);

    let user_id = query!(
        r#"
    INSERT INTO users (login, password)
    VALUES ($1, $2)
    RETURNING id
    "#,
        &body.login,
        password_hash
    )
    .fetch_one(&db)
    .await
    .map_db_err(|e| e.unique(StatusCode::CONFLICT, "Login is not available"))?
    .id;

    let session_cookie = Session::set(&mut rds, &user_id).await?;

    Ok(jar.add(session_cookie))
}

async fn login(
    jar: CookieJar,
    State(mut rds): State<RdPool>,
    State(db): State<PgPool>,
    Json(body): Json<LoginForm>,
) -> crate::Result<impl IntoResponse> {
    // TODO: check for session
    let (user_id, password_hash) = query!(
        r#"
    SELECT id, password FROM users
    WHERE login = $1
    "#,
        &body.login
    )
    .fetch_optional(&db)
    .await?
    .ok_or(AppError::exp(StatusCode::FORBIDDEN, "Invalid credentials"))
    .map(|r| (r.id, r.password))?;

    if let Some(password_hash) = password_hash {
        if is_correct_password(body.password, password_hash) {
            let session_cookie = Session::set(&mut rds, &user_id).await?;
            return Ok(jar.add(session_cookie));
        }
        // here it is possible to return exact error but this information is helpful for both users and hackers
    }
    Err(AppError::exp(
        StatusCode::FORBIDDEN,
        "Invalid login credentials",
    )) // precise cause of error is hidden from the end user
}

async fn logout(claims: Claims, State(mut rds): State<RdPool>) -> crate::Result<impl IntoResponse> {
    Session::invalidate(&mut rds, &claims.session_id).await?;
    Ok(Html("Successfully logged out"))
}

async fn session(claims: Claims) -> crate::Result<impl IntoResponse> {
    Ok(Html(format!("{}", claims.user_id)))
}

// TODO refresh and expiration mechanism