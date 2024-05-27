use crate::{
    errors::AppError,
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    http::Uri,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use reqwest::StatusCode;
use std::net::SocketAddr;
// use utoipa::OpenApi;
// use utoipa_swagger_ui::SwaggerUi;

// const SWAGGER_URI: &str = "/swagger-ui";

pub fn app(app_state: AppState) -> Router {
    let router: Router<AppState> = Router::new();

    // if app_state.env().is_dev() {
    //     router = add_swagger(router);
    // };

    router
        .route("/", get(home_page))
        .fallback(not_found)
        .with_state(app_state)
}

async fn home_page() -> impl IntoResponse {
    trace!("Welcome to the API home page!");
    (StatusCode::OK, Html("<h1>API home page</h1>"))
}

async fn not_found(
    uri: Uri,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Redirect, AppError> {
    let msg = format!("Endpoint not found: {uri}");
    debug!("IP: {}", addr.ip());
    Err(AppError::exp(StatusCode::NOT_FOUND, &msg))
}

// fn add_swagger(router: Router<AppState>) -> Router<AppState> {
//     info!("Enabling Swagger UI");
//     router.merge(SwaggerUi::new(SWAGGER_URI).url("/api-doc/openapi.json", doc::ApiDoc::openapi()))
// }
