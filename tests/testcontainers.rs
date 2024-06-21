use dotenvy::dotenv;
use redis::AsyncCommands;
use testcontainers::core::ContainerPort;
use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage};
use testcontainers_modules::redis::REDIS_PORT;

#[tokio::test]
async fn manual_test_redis() {
    dotenv().ok();
    let container = GenericImage::new("redis", "7.2.4")
        .with_exposed_port(ContainerPort::Tcp(6379))
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
        .await
        .expect("Redis started");
    let ports = container.ports().await.unwrap();
    dbg!(&ports);
    let port = ports
        .map_to_host_port_ipv4(ContainerPort::Tcp(6379))
        .unwrap();
    container.start().await.unwrap();
    let mut redis = redis::Client::open(format!("redis://127.0.0.1:{port}/0"))
        .unwrap()
        .get_connection_manager()
        .await
        .unwrap();

    let _: () = redis.set("test", 1i32).await.unwrap();
    let v: i32 = redis.get("test").await.unwrap();
    assert_eq!(1i32, v);
}

#[tokio::test]
async fn automatic_test_redis() {
    dotenv().ok();
    let container = testcontainers_modules::redis::Redis::default()
        .start()
        .await
        .unwrap();
    let port = container
        .ports()
        .await
        .unwrap()
        .map_to_host_port_ipv4(REDIS_PORT)
        .unwrap();
    let mut redis = redis::Client::open(format!("redis://127.0.0.1:{port}/0"))
        .unwrap()
        .get_connection_manager()
        .await
        .unwrap();
    let _: () = redis.set("test", 1i32).await.unwrap();
    let v: i32 = redis.get("test").await.unwrap();
    assert_eq!(1i32, v);
}
