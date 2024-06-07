use axum::{debug_handler, Router};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use oauth2::{AuthorizationCode, CsrfToken, TokenResponse};
use oauth2::basic::BasicTokenResponse;
use serde::Deserialize;
use sqlx::{PgExecutor, PgPool, Transaction};
use sqlx::types::Uuid;
use crate::AppRouter;

use crate::oauth::{AuthProvider, OAuthClient, OAuthClients, OAuthUser};
use crate::state::AppState;

pub fn router() -> AppRouter {
    Router::new().route("/github/callback", get(handle_github_callback))
}

#[derive(Deserialize)]
struct OAuthQuery {
    code: AuthorizationCode,
    state: CsrfToken
}

#[debug_handler(state = AppState)]
async fn handle_github_callback(State(db): State<PgPool>, State(oauth): State<OAuthClients>, Query(query): Query<OAuthQuery>) -> crate::Result<impl IntoResponse> {
    let token: BasicTokenResponse = oauth.github.exchange_code(query.code).await.unwrap();
    let user = oauth.github.get_user(token.access_token()).await.unwrap();
    let subject_id = user.subject_id();
    let auth_provider = AuthProvider::Github;
    if let Some(user_id) = select_user_id_from_federated_credentials(&db, &auth_provider, &subject_id).await? {
        trace!("{user_id} just logged in");
    } else {
        create_user_with_federated_credential(&db, &auth_provider, &subject_id).await?;
    }

    Ok(StatusCode::OK)
}


async fn create_user_with_federated_credential(db: &PgPool, auth_provider: &AuthProvider, subject_id: &str) -> sqlx::Result<()>{
    let mut tx = db.begin().await?;
    let user_id = insert_into_users(&mut *tx, None).await?;
    insert_into_federated_credentials(&mut *tx, &user_id, auth_provider, subject_id).await?;
    tx.commit().await?;
    Ok(())
}
async fn select_user_id_from_federated_credentials(db: impl PgExecutor<'_>, provider: &AuthProvider, subject_id: &str) -> sqlx::Result<Option<Uuid>> {
    Ok(query!(r#"
    SELECT user_id
    FROM federated_credentials
    WHERE provider = $1 AND subject_id = $2
    "#, provider as _, subject_id).fetch_optional(db).await?.map(|r| r.user_id))
}

async fn insert_into_federated_credentials(db: impl PgExecutor<'_>, user_id: &Uuid, provider: &AuthProvider, subject_id: &str) -> sqlx::Result<()> {
    query!(r#"
    INSERT INTO federated_credentials (user_id, provider, subject_id)
    VALUES ($1, $2, $3)
    "#, user_id, provider as _, subject_id).execute(db).await?;
    Ok(())
}
async fn insert_into_users(db: impl PgExecutor<'_>, password: Option<String>) -> sqlx::Result<Uuid> {
    Ok(query!(r#"
    INSERT INTO users (password)
    VALUES ($1)
    RETURNING id
    "#, password).fetch_one(db).await?.id)
}