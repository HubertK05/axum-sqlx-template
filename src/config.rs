use std::{convert::Infallible, net::SocketAddr};
use config::{Config, File, FileFormat};
use serde::Deserialize;

use crate::state::Environment;


#[derive(Debug, Deserialize)]
struct ConfigurationFile {
    environment: Option<String>,
    address: Option<SocketAddr>,
    database_url: String,
}

#[derive(Debug)]
pub struct Configuration {
    pub environment: Environment,
    pub address: SocketAddr,
    pub database_url: String,
}

impl TryFrom<ConfigurationFile> for Configuration {
    type Error = Infallible;

    fn try_from(value: ConfigurationFile) -> Result<Self, Self::Error> {
        let environment = value.environment.map(|val| val.try_into().expect("unsupported environment")).unwrap_or_default();
        Ok(Self {environment, address: value.address.unwrap_or("127.0.0.1:3000".parse().unwrap()), database_url: value.database_url})
    }
}

pub fn load_config() -> Result<Configuration, anyhow::Error> {
    let file = Config::builder()
        .add_source(File::new("config/settings", FileFormat::Toml))
        .build()?
        .try_deserialize::<ConfigurationFile>()?;

    let configuration = Configuration::try_from(file).unwrap();
    Ok(configuration)
}

