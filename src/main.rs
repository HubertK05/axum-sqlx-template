use axum_sqlx_template::{errors, setup::setup_globals};
use axum_sqlx_template::routes::app;
use axum_sqlx_template::setup::address;
use axum_sqlx_template::state::AppState;
use tokio::net::TcpListener;
// use server::setup::address;
// use server::{routes::app, state::AppState};

#[macro_use]
pub extern crate tracing;

pub type Result<T, E = errors::AppError> = std::result::Result<T, E>;

#[tokio::main]
async fn main() {
    setup_globals();
    
    let addr = address();
    let listener = TcpListener::bind(addr)
        .await
        .expect(&format!("Failed to bind to {addr}"));

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
