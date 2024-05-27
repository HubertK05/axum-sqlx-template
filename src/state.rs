use anyhow::anyhow;
use axum::extract::FromRef;
use reqwest::Client;
use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::env;
use std::fmt::Display;

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
    pub async fn new() -> Self {
        let environment = env::var("ENVIRONMENT")
            .map(|env| Environment::try_from(env).unwrap())
            .unwrap_or_default();

        let url = env::var("DATABASE_URL").expect("missing DATABASE_URL variable");
        let db = PgPool::connect(&url).await.unwrap();

        if environment.is_prod() {
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
            environment,
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

impl Environment {
    pub fn is_dev(&self) -> bool {
        match self {
            Environment::Development => true,
            Environment::Production => false,
        }
    }

    pub fn is_prod(&self) -> bool {
        match self {
            Environment::Development => true,
            Environment::Production => false,
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = AppError;

    fn try_from(val: String) -> Result<Self, Self::Error> {
        match &*val.to_lowercase() {
            "dev" | "development" => Ok(Environment::Development),
            "prod" | "production" => Ok(Environment::Production),
            _ => Err(AppError::Unexpected(anyhow!("Use `dev` or `development` to specify development environment, and `prod` or `production` to specify production environment.")))
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Development
    }
}

impl Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Development => write!(f, "development 🔨"),
            Environment::Production => write!(f, "production 🚀"),
        }
    }
}
