use crate::AppRouter;
use axum::Router;

mod jwt;
mod oauth;
mod session;

// TODO add configuration
const IS_JWT_AUTH: bool = true;

pub fn router() -> AppRouter {
    let mut router = Router::new().nest("/oauth2", oauth::router());

    if IS_JWT_AUTH {
        router = router.merge(jwt::router())
    } else {
        router = router.merge(session::router())
    }
    router
}
