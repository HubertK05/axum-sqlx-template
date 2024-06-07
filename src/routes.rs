mod auth;

use crate::{errors::AppError, state::AppState};
use axum::{body::Body, extract::{ConnectInfo, State}, http::{Request, Response, Uri}, response::{Html, IntoResponse, Redirect}, routing::get, Router, debug_handler};
use reqwest::{Client, StatusCode};
use std::{net::SocketAddr, time::Duration};
use axum::extract::Query;
use axum::routing::post;
use oauth2::{AuthorizationCode, CsrfToken, TokenResponse};
use oauth2::basic::BasicTokenResponse;
use oauth2::url::Url;
use serde::Deserialize;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::Span;
use crate::oauth::{OAuthClient, OAuthClients};
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
        .nest("/auth", auth::router())
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

// fn add_swagger(router: Router<AppState>) -> Router<AppState> {
//     info!("Enabling Swagger UI");
//     router.merge(SwaggerUi::new(SWAGGER_URI).url("/api-doc/openapi.json", doc::ApiDoc::openapi()))
// }
