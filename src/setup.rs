use std::env;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, FmtSubscriber};


pub fn setup_globals() {
    dotenvy::dotenv().ok();
    tracing_subscriber();
}

fn tracing_subscriber() {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .pretty()
            .without_time()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or(
                        format!("{pkg}=trace", pkg = env!("CARGO_PKG_NAME")) // reads directly from Cargo.toml definition, RUST_LOG env will convert "-" to "_"
                            .parse()
                            .unwrap(),
                    )
                    .add_directive("axum::rejection=trace".parse().unwrap()),
            )
            .finish(),
    )
    .unwrap();

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
