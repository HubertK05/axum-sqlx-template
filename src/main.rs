#[macro_use]
mod macros;

pub mod auth;
pub mod config;
pub mod docutils;
pub mod errors;
pub mod mailer;
mod miscutils;
pub mod routes;
pub mod setup;
pub mod state;
pub mod queries;

use axum::Router;
use config::load_config;
use listenfd::ListenFd;
use redis::aio::ConnectionLike;
use redis::AsyncCommands;
use setup::setup_globals;
use state::AppState;
use tokio::net::TcpListener;
use tokio::signal;

#[macro_use]
pub extern crate tracing;
#[macro_use]
pub extern crate sqlx;

pub type Result<T, E = errors::AppError> = std::result::Result<T, E>;
pub type AppRouter = Router<AppState>;

pub trait AsyncRedisConn: ConnectionLike + Send + Clone + AsyncCommands {}

impl<T> AsyncRedisConn for T where T: ConnectionLike + Send + Clone + AsyncCommands {}

#[tokio::main]
async fn main() {
    setup_globals();

    let config = load_config().unwrap();
    let listener = match ListenFd::from_env().take_tcp_listener(0).unwrap() {
        Some(listener) => {
            listener.set_nonblocking(true).unwrap();
            TcpListener::from_std(listener).unwrap()
        }
        None => TcpListener::bind(config.address).await.unwrap(),
    };

    let addr = listener.local_addr().unwrap();

    let app_state = AppState::new(&config).await;
    info!("Environment: {}", app_state.env());

    let router = routes::app(app_state);

    info!(
        "listening on {} with domain at {}",
        &addr, &config.domain_name
    );

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
