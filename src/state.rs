use anyhow::anyhow;
use axum::extract::FromRef;
use reqwest::Client;
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

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum Environment {
    Development,
    Production,
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
    type Error = AppError;

    fn try_from(val: String) -> Result<Self, Self::Error> {
        match &*val.to_lowercase() {
            "dev" | "development" => Ok(Self::Development),
            "prod" | "production" => Ok(Self::Production),
            _ => Err(AppError::Unexpected(anyhow!("Use `dev` or `development` to specify development environment, and `prod` or `production` to specify production environment.")))
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
