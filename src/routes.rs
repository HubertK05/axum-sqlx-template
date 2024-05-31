use crate::{
    errors::AppError, state::AppState
};
use axum::{
    body::Body, extract::{ConnectInfo, State}, http::{Request, Response, Uri}, response::{Html, IntoResponse, Redirect}, routing::get, Router
};
use reqwest::StatusCode;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::Span;
use utoipa::openapi::{Info, PathsBuilder};
use utoipa_swagger_ui::SwaggerUi;
use std::{net::SocketAddr, time::Duration};

const SWAGGER_URI: &str = "/swagger-ui";

pub fn app(app_state: AppState) -> Router {
    let mut router: Router<AppState> = Router::new();

    if app_state.env().is_dev() {
        router = add_swagger(router);
    };

    router
        .route("/", get(home_page))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    tracing::info_span!("request", method = %request.method(), uri = %request.uri())
                })
                .on_response(|response: &Response<_>, latency: Duration, span: &Span| {
                    info!("Response status = {}, latency = {}ms", &response.status().as_u16(), latency.as_millis());
                }),
        )
        .layer(CorsLayer::permissive())
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

fn add_swagger(router: Router<AppState>) -> Router<AppState> {
    info!("Enabling Swagger UI");
    let empty_openapi = utoipa::openapi::OpenApi::new(Info::new("template", "0.1.0"), PathsBuilder::new());
    router.merge(SwaggerUi::new(SWAGGER_URI).url("/api-doc/openapi.json", empty_openapi))
}
