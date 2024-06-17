use crate::auth::jwt::Session;
use crate::auth::oauth::{AuthProvider, OAuthClient, OAuthClients, OAuthUser};
use crate::docutils::{get, DocRouter};
use crate::errors::AppError;
use crate::routes::auth::User;
use crate::AsyncRedisConn;
use axum::debug_handler;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Redirect};
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
    query: OAuthQuery,
) -> crate::Result<(CookieJar, Html<String>)> {
    // TODO: maybe handle logic inside CsrfState::check function
    let is_matching_state: bool = CsrfState::check(&mut rds, &query.state).await?;
    if !is_matching_state {
        return Err(AppError::exp(StatusCode::FORBIDDEN, "Invalid CSRF state"));
    }
    trace!("Matching CSRF state for {}", query.state.secret());

    let github_token: BasicTokenResponse = oauth.github.exchange_code(query.code).await?;
    let github_user = oauth.github.get_user(github_token.access_token()).await?;
    let auth_provider = oauth.github.key();
    let github_user_id = github_user.subject_id();

    let user_id = get_or_create_user(&db, &auth_provider, &github_user_id).await?;
    let jar = Session::set(&mut rds, jar, &jwt_keys, user_id).await?;

    Ok((
        jar,
        Html(format!("<h1>Authenticated with {auth_provider}</h1>")),
    ))
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

async fn get_or_create_user(
    db: &PgPool,
    auth_provider: &AuthProvider,
    subject_id: &str,
) -> sqlx::Result<Uuid> {
    let res = if let Some(user_id) =
        FederatedCredential::select_user_id(db, &auth_provider, subject_id).await?
    {
        trace!("Authenticating {user_id} with {auth_provider}");
        user_id
    } else {
        let user_id =
            create_user_with_federated_credentials(db, &auth_provider, subject_id).await?;
        trace!("Registering {user_id} with {auth_provider}");
        user_id
    };

    Ok(res)
}
struct FederatedCredential;

impl FederatedCredential {
    pub async fn insert(
        db: impl PgExecutor<'_>,
        user_id: impl AsRef<Uuid>,
        auth_provider: &AuthProvider,
        subject_id: impl AsRef<str>,
    ) -> sqlx::Result<()> {
        query!(
            r#"
    INSERT INTO federated_credentials (user_id, provider, subject_id)
    VALUES ($1, $2, $3)
    "#,
            user_id.as_ref(),
            auth_provider as _,
            subject_id.as_ref()
        )
        .execute(db)
        .await?;
        Ok(())
    }
    pub async fn select_user_id(
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
}

async fn create_user_with_federated_credentials(
    db: &PgPool,
    auth_provider: &AuthProvider,
    subject_id: impl AsRef<str>,
) -> sqlx::Result<Uuid> {
    let mut tx = db.begin().await?;
    let user_id = User::insert(&mut *tx, None).await?;
    FederatedCredential::insert(&mut *tx, &user_id, auth_provider, subject_id).await?;
    tx.commit().await?;
    Ok(user_id)
}
