use anyhow::Context;
use config::{Config, ConfigError, File, FileFormat};
use std::{
    collections::HashMap,
    env::{var, vars},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::state::Environment;

const REQUIRED: &[&str] = &["ADDRESS", "DATABASE_URL"];
const LOCAL_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);

#[derive(Debug)]
pub struct Configuration {
    pub environment: Environment,
    pub address: SocketAddr,
    pub database_url: String,
}

impl Configuration {
    fn from_env(environment: Environment) -> Self {
        let mut missing = vec![];
        let mut vars: HashMap<String, String> = vars().collect();
        for req_var in REQUIRED {
            if let Some(val) = vars.remove(*req_var) {
                if val.is_empty() {
                    missing.push(val);
                }
            } else {
                missing.push(req_var.to_string());
            }
        }
        if !missing.is_empty() {
            error!("Variables required: {missing:?}");
            panic!("Configuration missing");
        }
        let address: SocketAddr = var("ADDRESS")
            .unwrap()
            .parse()
            .expect("Invalid socket address");
        let database_url: String = var("DATABASE_URL").unwrap();

        Self {
            environment,
            address,
            database_url,
        }
    }

    fn from_file(environment: Environment, config: Config) -> Self {
        let address: SocketAddr = match config.get("address") {
            Ok(address) => address,
            Err(e) => {
                if matches!(e, ConfigError::NotFound(_)) {
                    LOCAL_ADDR
                } else {
                    unimplemented!()
                }
            }
        };

        let database_url: String = config
            .get("database_url")
            .context("invalid database_url")
            .unwrap();

        Self {
            environment,
            address,
            database_url,
        }
    }
}

pub fn load_config() -> Result<Configuration, anyhow::Error> {
    let environment: Environment = var("ENVIRONMENT")
        .map(|val| val.try_into().unwrap())
        .unwrap_or_default();
    match environment {
        Environment::Development => {
            let config = Config::builder()
                .add_source(File::new("config/settings", FileFormat::Toml))
                .build()?;

            Ok(Configuration::from_file(environment, config))
        }
        Environment::Production => Ok(Configuration::from_env(environment)),
    }
}
