use crate::auth::jwt::{Session};
use crate::auth::oauth::{AuthProvider, OAuthClient, OAuthClients, OAuthUser};
use crate::docutils::{get, DocRouter};
use crate::errors::AppError;
use crate::AsyncRedisConn;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Redirect};
use axum::{debug_handler};
use axum_extra::extract::CookieJar;
use oauth2::basic::BasicTokenResponse;
use oauth2::{AuthorizationCode, CsrfToken, TokenResponse};
use redis::{AsyncCommands, RedisResult};
use serde::Deserialize;
use sqlx::types::Uuid;
use sqlx::{PgExecutor, PgPool};
use utoipa::IntoParams;

use crate::state::{AppState, JwtKeys, RdPool};

pub fn router() -> DocRouter<AppState> {
    DocRouter::new()
        .route("/github/callback", get(handle_github_callback))
        .route("/github", get(issue_url))
}

#[derive(Deserialize, IntoParams)]
struct OAuthQuery {
    code: AuthorizationCode,
    state: CsrfToken,
}

struct CsrfState;

impl CsrfState {
    async fn check(rds: &mut impl AsyncRedisConn, csrf_token: &CsrfToken) -> RedisResult<bool> {
        rds.del(Self::key(csrf_token)).await
    }

    async fn add(
        rds: &mut impl AsyncRedisConn,
        auth_provider: AuthProvider,
        csrf_token: &CsrfToken,
    ) -> RedisResult<()> {
        rds.set_ex(Self::key(csrf_token), auth_provider, 60 * 5)
            .await
    }

    fn key(csrf_token: &CsrfToken) -> String {
        format!("csrf:{}", csrf_token.secret())
    }
}

#[debug_handler(state = AppState)]
async fn handle_github_callback(
    jar: CookieJar,
    State(jwt_keys): State<JwtKeys>,
    State(rds): State<RdPool>,
    State(db): State<PgPool>,
    State(oauth): State<OAuthClients>,
    Query(query): Query<OAuthQuery>,
) -> crate::Result<(CookieJar, Html<String>)> {
    read_oauth_response(db, rds, oauth, jar, jwt_keys, query).await
}

async fn read_oauth_response(
    db: PgPool,
    mut rds: impl AsyncRedisConn,
    oauth: OAuthClients,
    jar: CookieJar,
    jwt_keys: JwtKeys,
    query: OAuthQuery
) -> crate::Result<(CookieJar, Html<String>)> {
    let is_matching_state: bool = CsrfState::check(&mut rds, &query.state).await?;
    if !is_matching_state {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid CSRF state"));
    }
    trace!("Matching CSRF state for {}", query.state.secret());

    let token: BasicTokenResponse = oauth.github.exchange_code(query.code).await?;
    let user = oauth.github.get_user(token.access_token()).await?;
    let subject_id = user.subject_id();
    let auth_provider = AuthProvider::Github;
    if let Some(user_id) =
        select_user_id_from_federated_credentials(&db, &auth_provider, &subject_id).await?
    {
        let jar = Session::set(&mut rds, jar, &jwt_keys, user_id).await?;
        trace!("{user_id} logged in with {auth_provider}");
        Ok((
            jar,
            Html(format!("<h1>Authenticated with {auth_provider}</h1>")),
        ))
    } else {
        let user_id =
            create_user_with_federated_credential(&db, &auth_provider, &subject_id).await?;
        let jar = Session::set(&mut rds, jar, &jwt_keys, user_id).await?;
        trace!("{user_id} registered with {auth_provider}");

        Ok((
            jar,
            Html(format!("<h1>Authenticated with {auth_provider}</h1>")),
        ))
    }
}

#[debug_handler(state = AppState)]
async fn issue_url(
    State(mut rds): State<RdPool>,
    State(oauth): State<OAuthClients>,
) -> crate::Result<axum::response::Redirect> {
    let (url, csrf_token) = oauth.github.get_url_and_state();
    trace!("Issued federated authentication method url");
    CsrfState::add(&mut rds, AuthProvider::Github, &csrf_token).await?;

    Ok(Redirect::to(url.as_str()))
}

async fn create_user_with_federated_credential(
    db: &PgPool,
    auth_provider: &AuthProvider,
    subject_id: &str,
) -> sqlx::Result<Uuid> {
    let mut tx = db.begin().await?;
    let user_id = insert_into_users(&mut *tx, None).await?;
    insert_into_federated_credentials(&mut *tx, &user_id, auth_provider, subject_id).await?;
    tx.commit().await?;
    Ok(user_id)
}

async fn select_user_id_from_federated_credentials(
    db: impl PgExecutor<'_>,
    provider: &AuthProvider,
    subject_id: &str,
) -> sqlx::Result<Option<Uuid>> {
    Ok(query!(
        r#"
    SELECT user_id
    FROM federated_credentials
    WHERE provider = $1 AND subject_id = $2
    "#,
        provider as _,
        subject_id
    )
    .fetch_optional(db)
    .await?
    .map(|r| r.user_id))
}

async fn insert_into_federated_credentials(
    db: impl PgExecutor<'_>,
    user_id: &Uuid,
    provider: &AuthProvider,
    subject_id: &str,
) -> sqlx::Result<()> {
    query!(
        r#"
    INSERT INTO federated_credentials (user_id, provider, subject_id)
    VALUES ($1, $2, $3)
    "#,
        user_id,
        provider as _,
        subject_id
    )
    .execute(db)
    .await?;
    Ok(())
}

async fn insert_into_users(
    db: impl PgExecutor<'_>,
    password: Option<String>,
) -> sqlx::Result<Uuid> {
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
