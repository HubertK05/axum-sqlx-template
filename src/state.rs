use crate::auth::oauth::OAuthClients;
use crate::config::{AbsoluteUri, Configuration, JwtConfiguration};
use crate::errors::AppError;
use crate::mailer::Mailer;
use anyhow::anyhow;
use argon2::password_hash::Encoding;
use axum::extract::FromRef;
use jsonwebtoken::{DecodingKey, EncodingKey};
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
pub type RdPool = redis::aio::ConnectionManager;

#[derive(FromRef, Clone)]
pub struct AppState {
    db: PgPool,
    redis: RdPool,
    client: Client,
    oauth: OAuthClients,
    domain_name: AbsoluteUri,
    jwt_keys: JwtKeys,
    // verification: Verification,
    mailer: Mailer,
    environment: Environment,
}

const FRONTEND_URL: &str = "http://localhost:3000";

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

        let jwt_keys = JwtKeys::from(&config.jwt);

        let domain_name = config.domain_name.clone();

        let oauth = OAuthClients::new(client.clone(), &config.oauth, &domain_name);

        let redis = redis::Client::open(config.redis_url.to_string())
            .unwrap()
            .get_connection_manager()
            .await
            .unwrap();

        let mailer = Mailer::new(FRONTEND_URL.to_string(), &config.smtp);

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
}

#[derive(Clone)]
pub struct JwtKeys {
    encoding_access: EncodingKey,
    encoding_refresh: EncodingKey,
    decoding_access: DecodingKey,
    decoding_refresh: DecodingKey,
}

impl From<&JwtConfiguration> for JwtKeys {
    fn from(value: &JwtConfiguration) -> Self {
        Self::new(&value.access_secret, &value.refresh_secret)
    }
}

impl JwtKeys {
    pub fn new(access_secret: &str, refresh_secret: &str) -> Self {
        Self {
            encoding_access: EncodingKey::from_secret(access_secret.as_bytes()),
            encoding_refresh: EncodingKey::from_secret(refresh_secret.as_bytes()),
            decoding_access: DecodingKey::from_secret(access_secret.as_bytes()),
            decoding_refresh: DecodingKey::from_secret(refresh_secret.as_bytes()),
        }
    }
    pub fn encoding_access(&self) -> &EncodingKey {
        &self.encoding_access
    }
    pub fn encoding_refresh(&self) -> &EncodingKey {
        &self.encoding_refresh
    }
    pub fn decoding_access(&self) -> &DecodingKey {
        &self.decoding_access
    }
    pub fn decoding_refresh(&self) -> &DecodingKey {
        &self.decoding_refresh
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
