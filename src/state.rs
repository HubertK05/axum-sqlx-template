use crate::config::Configuration;
use crate::errors::AppError;
use crate::oauth::OAuthClients;
use anyhow::anyhow;
use axum::extract::FromRef;
use reqwest::Client;
use serde::de::{Error, Visitor};
use serde::Deserialize;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;
use tracing::log::LevelFilter;
use crate::mailer::Mailer;
// use crate::extensions::oauth2::OAuth;
// use crate::extensions::verification::Verification;
pub type RdPool = redis::aio::ConnectionManager;

#[derive(FromRef, Clone)]
pub struct AppState {
    db: PgPool,
    redis: RdPool,
    client: Client,
    oauth: OAuthClients,
    // verification: Verification,
    mailer: Mailer,
    environment: Environment,
}

const FRONTEND_URL: &str = "";

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

        let oauth = OAuthClients::new(client.clone(), &config.oauth, &config.public_domain);

        let redis = redis::Client::open(config.redis_url.to_string())
            .unwrap()
            .get_connection_manager()
            .await
            .unwrap();
        // let verification = Verification::new();

        let mailer = Mailer::new(FRONTEND_URL.to_string(), &config.smtp);

        Self {
            db,
            redis,
            client,
            oauth,
            // verification,
            mailer,
            environment: config.environment,
        }
    }

    pub fn env(&self) -> Environment {
        self.environment
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Environment {
    Development,
    Production,
}

struct EnvironmentVisitor;

impl<'de> Visitor<'de> for EnvironmentVisitor {
    type Value = Environment;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "`dev` or `development` to specify development environment, and `prod` or `production` to specify production environment.")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        v.try_into()
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(&v), &self))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }
}
impl<'de> Deserialize<'de> for Environment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(EnvironmentVisitor)
    }
}

impl Environment {
    pub fn is_dev(&self) -> bool {
        matches!(self, Self::Development)
    }

    pub fn is_prod(&self) -> bool {
        matches!(self, Self::Production)
    }
}

impl TryFrom<&str> for Environment {
    type Error = anyhow::Error;

    fn try_from(val: &str) -> Result<Self, Self::Error> {
        match val.to_lowercase().as_ref() {
            "dev" | "development" => Ok(Self::Development),
            "prod" | "production" => Ok(Self::Production),
            _ => Err(anyhow!("Use `dev` or `development` to specify development environment, and `prod` or `production` to specify production environment."))
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self::Development
    }
}

impl Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Development => write!(f, "development 🔨"),
            Self::Production => write!(f, "production 🚀"),
        }
    }
}
