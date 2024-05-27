use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

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
