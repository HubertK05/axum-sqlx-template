use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, FmtSubscriber};

const LOCAL_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);

pub fn address() -> SocketAddr {
    let addr: SocketAddr = env::var("ADDR")
        .map(|addr| {
            addr.parse().unwrap_or_else(|_| {
                error!("Failed to parse ADDR variable");
                LOCAL_ADDR
            })
        })
        .unwrap_or(LOCAL_ADDR);

    addr
}

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
            ).finish(),
    ).unwrap();

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