use crate::{
    docutils::{get, DocumentedRouter, MyMethodRouter}, errors::AppError, state::AppState
};
use axum::{
    body::Body, extract::{ConnectInfo, Path, Query, State}, http::{Request, Response, Uri}, response::{Html, IntoResponse, Redirect}, Json, Router
};
use reqwest::StatusCode;
use serde::Deserialize;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::Span;
use utoipa::{openapi::{Info, OpenApi, PathsBuilder}, IntoParams, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use std::{net::SocketAddr, time::Duration};

const SWAGGER_URI: &str = "/swagger-ui";

pub fn app(app_state: AppState) -> Router {
    let (mut documented_router, docs) = DocumentedRouter::new("template", "0.1.0")
        .route("/", get(home_page).post(home_page))
        .finish_doc();

    let mut router: Router<AppState> = Router::new();

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

#[derive(Deserialize, IntoParams)]
pub struct PathParams {
    first: String
}

#[derive(Deserialize, IntoParams)]
pub struct QueryParams {
    first: String,
    second: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ReqBody {
    first: String,
    second: String,
}

async fn home_page(Path(p): Path<PathParams>, Query(q): Query<QueryParams>, Json(b): Json<ReqBody>) -> impl IntoResponse {
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

fn add_swagger<S>(router: Router<S>, docs: OpenApi) -> Router<S>
where
    S: Clone + Send + Sync + 'static {
    info!("Enabling Swagger UI");
    router.merge(SwaggerUi::new(SWAGGER_URI).url("/api-doc/openapi.json", docs))
}
