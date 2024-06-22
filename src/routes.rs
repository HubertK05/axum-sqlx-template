mod auth;
mod admin;

use crate::{
    docutils::{get, DocRouter},
    errors::AppError,
    state::{AppState, RdPool},
    AsyncRedisConn,
};
use axum::http::StatusCode;
use axum::{
    body::Body,
    debug_handler,
    extract::{ConnectInfo, Request, State},
    http::{Response, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect},
    Router,
};
use redis::{AsyncCommands, RedisResult};
use std::time::Duration;
use tokio::task::JoinSet;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::Span;
use utoipa::openapi::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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
        .nest("/admin", admin::router())
        .layer(middleware::from_fn_with_state(app_state.clone(), increment_visit_count))
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

async fn home_page() -> crate::Result<Html<&'static str>> {
    trace!("Welcome to the API home page!");
    Ok(Html("<h1>API home page</h1>"))
}

async fn not_found(
    uri: Uri,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
) -> crate::Result<Redirect> {
    let msg = format!("Endpoint not found: {uri}");
    debug!("IP: {}", addr.ip());
    Err(AppError::exp(StatusCode::NOT_FOUND, msg))
}

async fn increment_visit_count(
    State(rds): State<RdPool>,
    req: Request,
    next: Next,
) -> crate::Result<impl IntoResponse> {
    let path = req.uri().path().to_string();
    let _ = tokio::spawn(async move {
        let mut rds = rds;
        EndpointVisits::increment(&mut rds, path).await.unwrap();
       
    });
    Ok(next.run(req).await)
}

struct EndpointVisits;

impl EndpointVisits {
    async fn increment(
        rds: &mut impl AsyncRedisConn,
        endpoint: impl AsRef<str>,
    ) -> RedisResult<()> {
        rds.incr(Self::key(endpoint.as_ref()), 1).await
    }

    async fn get_all(rds: &mut RdPool) -> RedisResult<Vec<(String, i32)>> {
        let keys: Vec<String> = rds.keys("endpoint:*").await?;
        let mut tasks: JoinSet<(String, RedisResult<i32>)> = JoinSet::new();
        for key in keys {
            let mut task_rds = rds.clone();
            tasks.spawn(async move {
                let value = task_rds.get(&key).await;
                (key, value)
            });
        }

        let mut map = Vec::new();
        while let Some(Ok((key, value))) = tasks.join_next().await {
            let value = value?;
            map.push((key[9..key.len()-7].to_string(), value));
        }
        Ok(map)
    }

    fn key(endpoint: &str) -> String {
        format!("endpoint:{endpoint}:visits")
    }
}

fn add_swagger<S>(router: Router<S>, docs: OpenApi) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    info!("Enabling Swagger UI");
    router.merge(SwaggerUi::new(SWAGGER_URI).url("/api-doc/openapi.json", docs))
}
