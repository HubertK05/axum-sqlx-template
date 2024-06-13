mod auth;

use crate::{docutils::{get, DocRouter}, errors::AppError, state::AppState
};
use axum::{
    body::Body,
    extract::ConnectInfo, http::{Request, Response, Uri}, response::{Html, Redirect},
    Router,
};
use axum::http::StatusCode;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::Span;
use utoipa::openapi::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use std::{time::Duration};

const SWAGGER_URI: &str = "/swagger-ui";

pub fn app(app_state: AppState) -> Router {
    let (mut documented_router, docs) = DocRouter::new()
        .route("/", get(home_page))
        .nest("/auth", auth::router())
        .finish_doc("template", "0.1.0");

    if app_state.env().is_dev() {
        documented_router = add_swagger(documented_router, docs);
    };

    documented_router
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

async fn home_page() -> Result<Html<&'static str>, AppError> {
    trace!("Welcome to the API home page!");
    Ok(Html("<h1>API home page</h1>"))
}

async fn not_found(
    uri: Uri,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
) -> Result<Redirect, AppError> {
    let msg = format!("Endpoint not found: {uri}");
    debug!("IP: {}", addr.ip());
    Err(AppError::exp(StatusCode::NOT_FOUND, msg))
}

fn add_swagger<S>(router: Router<S>, docs: OpenApi) -> Router<S>
where
    S: Clone + Send + Sync + 'static {
    info!("Enabling Swagger UI");
    router.merge(SwaggerUi::new(SWAGGER_URI).url("/api-doc/openapi.json", docs))
}
