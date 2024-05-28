use anyhow::anyhow;
use axum::extract::FromRef;
use reqwest::Client;
use serde::de::Visitor;
use serde::Deserialize;
use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::fmt::Display;

use crate::config::Configuration;
use crate::errors::AppError;
// use crate::extensions::mail::Mailer;
// use crate::extensions::oauth2::OAuth;
// use crate::extensions::verification::Verification;

#[derive(FromRef, Clone)]
pub struct AppState {
    db: PgPool,
    client: Client,
    // oauth: Option<OAuth>,
    // verification: Verification,
    // mailer: Mailer,
    environment: Environment,
}

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

impl AppState {
    pub async fn new(config: &Configuration) -> Self {
        let db = PgPool::connect(&config.database_url).await.unwrap();

        if config.environment.is_prod() {
            MIGRATOR.run(&db).await.expect("failed to run migrations");
        };

        let client = Client::new();

        // let oauth = env::var("OAUTH")
        //     .map(|v| v.parse::<bool>().unwrap_or_default())
        //     .unwrap_or_default()
        //     .then_some(OAuth::new());

        // let verification = Verification::new();

        // let mailer = Mailer::new(frontend.url.clone());

        Self {
            db,
            client,
            // oauth,
            // verification,
            // mailer,
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
        formatter.write_str("Use `dev` or `development` to specify development environment, and `prod` or `production` to specify production environment.")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.try_into().map_err(|_| E::custom("invalid value"))
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

impl TryFrom<String> for Environment {
    type Error = anyhow::Error;

    fn try_from(val: String) -> Result<Self, Self::Error> {
        match &*val.to_lowercase() {
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
