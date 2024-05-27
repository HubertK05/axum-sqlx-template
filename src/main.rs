use axum_sqlx_template::routes::app;
use axum_sqlx_template::setup::address;
use axum_sqlx_template::state::AppState;
use dotenvy::dotenv;
use tokio::net::TcpListener;
// use server::setup::address;
// use server::{routes::app, state::AppState};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[macro_use]
pub extern crate tracing;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=debug,axum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    let addr = address();
    let listener = TcpListener::bind(addr).await.expect(&format!("Failed to bind to {addr}"));

    let app_state = AppState::new().await;
    info!("Constructed app state");
    info!("Environment: {}", app_state.env());

    let router = app(app_state);

    info!("listening on {}", &addr);

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}
