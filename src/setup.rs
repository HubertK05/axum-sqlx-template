use std::env;

use tracing_subscriber::{EnvFilter, FmtSubscriber};

pub fn setup_globals() {
    dotenvy::dotenv().ok();
    tracing_subscriber();
}

fn tracing_subscriber() {
    let subscriber = FmtSubscriber::builder()
        .pretty()
        .without_time()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or(
                    format!("{pkg}=trace", pkg = env!("CARGO_PKG_NAME")) // reads directly from Cargo.toml definition, RUST_LOG env will convert "-" to "_"
                        .parse()
                        .unwrap(),
                )
                .add_directive("axum::rejection=trace".parse().unwrap())
                .add_directive("sqlx=trace".parse().unwrap()),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // same but different
    // tracing_subscriber::registry()
    // .with(
    //     tracing_subscriber::EnvFilter::try_from_default_env()
    //     .unwrap_or(
    //         format!("{pkg}=trace", pkg = env!("CARGO_PKG_NAME")) // reads directly from Cargo.toml definition, RUST_LOG env will convert "-" to "_"
    //             .parse()
    //             .unwrap(),
    //     )
    //     .add_directive("axum::rejection=trace".parse().unwrap()),
    // )
    // .with(tracing_subscriber::fmt::layer().pretty()
    // .without_time())
    // .init();
}
