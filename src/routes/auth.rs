use axum::Router;
use crate::AppRouter;

mod oauth;

pub fn router() -> AppRouter {
    Router::new().nest("/oauth2", oauth::router())
}
