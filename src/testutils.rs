#[cfg(test)]
pub mod tools {
    use redis::aio::ConnectionManager;
    use redis::{Client, Cmd, Pipeline, RedisFuture, Value};
    use testcontainers::runners::AsyncRunner;
    use testcontainers::ContainerAsync;
    use testcontainers_modules::redis::{Redis, REDIS_PORT};

    pub async fn get_redis() -> IsolatedRedis {
        dotenvy::dotenv().ok();

        let container = Redis::default().start().await.unwrap();
        
        let port = container
            .ports()
            .await
            .unwrap()
            .map_to_host_port_ipv4(REDIS_PORT)
            .unwrap();
        
        let redis = Client::open(format!("redis://127.0.0.1:{port}"))
            .unwrap()
            .get_connection_manager()
            .await
            .unwrap();

        IsolatedRedis::new(container, redis)
    }

    pub struct IsolatedRedis {
        redis: ConnectionManager,
        _container: ContainerAsync<Redis>,
    }

    impl IsolatedRedis {
        fn new(container: ContainerAsync<Redis>, connection: ConnectionManager) -> Self {
            Self {
                redis: connection,
                _container: container,
            }
        }
    }
    
    impl redis::aio::ConnectionLike for IsolatedRedis {
        fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
            self.redis.req_packed_command(cmd)
        }

        fn req_packed_commands<'a>(
            &'a mut self,
            cmd: &'a Pipeline,
            offset: usize,
            count: usize,
        ) -> RedisFuture<'a, Vec<Value>> {
            self.redis.req_packed_commands(cmd, offset, count)
        }

        fn get_db(&self) -> i64 {
            self.redis.get_db()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testutils::tools::get_redis;
    use redis::AsyncCommands;

    #[tokio::test]
    async fn example_isolated_test() {
        dotenvy::dotenv().ok();
        let mut rds = get_redis().await;
        let _: () = rds.set("test", 1i32).await.unwrap();
        let v: i32 = rds.get("test").await.unwrap();
        assert_eq!(1i32, v);
    }
}
