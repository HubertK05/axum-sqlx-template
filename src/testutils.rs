
#[cfg(test)]
pub mod tools {
    use redis::aio::ConnectionManager;
    use redis::Client;
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::redis::{Redis, REDIS_PORT};

    pub async fn get_redis() -> ConnectionManager {
        dotenvy::dotenv().ok();

        let redis = Redis::default().start().await.unwrap();
        let port = redis.ports().await.unwrap().map_to_host_port_ipv4(REDIS_PORT).unwrap();
        let redis = Client::open(format!("127.0.0.1:{port}/0")).unwrap().get_connection_manager().await.unwrap();
        redis
    }
}

#[cfg(test)]
mod tests {
    use crate::testutils::tools::get_redis;
    use redis::AsyncCommands;
    
    #[tokio::test]
    async fn example_isolated_test() {
        let mut rds = get_redis().await;
        let _: () = rds.set("test", 1i32).await.unwrap();
        let v: i32 = rds.get("test").await.unwrap();
        assert_eq!(1i32, v);
    }

}