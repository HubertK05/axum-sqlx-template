use crate::auth::oauth::OAuthClients;
use crate::config::{AbsoluteUri, Configuration};
use crate::mailer::Mailer;
use axum::extract::FromRef;
use environment::Environment;
use jwt::JwtKeys;
use reqwest::Client;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use std::str::FromStr;
use std::time::Duration;
use tracing::log::LevelFilter;

pub mod environment;
pub mod jwt;
pub type RdPool = redis::aio::ConnectionManager;

#[derive(FromRef, Clone)]
pub struct AppState {
    db: PgPool,
    redis: RdPool,
    client: Client,
    oauth: OAuthClients,
    domain_name: AbsoluteUri,
    jwt_keys: JwtKeys,
    mailer: Mailer,
    environment: Environment,
}

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

impl AppState {
    pub async fn new(config: &Configuration) -> Self {
        let connection_options = PgConnectOptions::from_str(&config.database_url)
            .unwrap()
            .log_statements(LevelFilter::Trace)
            .log_slow_statements(LevelFilter::Warn, Duration::from_secs(1));

        let db = PgPoolOptions::new()
            .connect_with(connection_options)
            .await
            .unwrap();

        if config.environment.is_prod() {
            MIGRATOR.run(&db).await.expect("failed to run migrations");
            info!("Migration applied")
        };

        let client = Client::builder()
            .user_agent(APP_USER_AGENT)
            .build()
            .unwrap();

        let jwt_keys = JwtKeys::from_eddsa();

        let domain_name = config.domain_name.clone();

        let oauth = OAuthClients::new(client.clone(), &config.oauth, &domain_name);

        let redis = redis::Client::open(config.redis_url.to_string())
            .unwrap()
            .get_connection_manager()
            .await
            .unwrap();

        let mailer = Mailer::new(config.domain_name.to_string(), &config.smtp);

        trace!("Constructed app state");

        Self {
            db,
            redis,
            client,
            oauth,
            domain_name,
            jwt_keys,
            mailer,
            environment: config.environment,
        }
    }

    pub fn env(&self) -> Environment {
        self.environment
    }

    pub fn absolute_uri(&self) -> &AbsoluteUri {
        &self.domain_name
    }
}
