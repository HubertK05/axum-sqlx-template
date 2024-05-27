pub mod errors;
pub mod routes;
pub mod setup;
pub mod state;

use setup::{setup_globals, address};
use state::AppState;
use tokio::net::TcpListener;

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

    let router = routes::app(app_state);

    info!("listening on {}", &addr);

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}
