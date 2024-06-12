use crate::auth::oauth::AuthProvider;
use anyhow::{bail, Context};
use axum::http::uri::{PathAndQuery, Scheme};
use axum::http::Uri;
use config::{Config, ConfigError, File, FileFormat};
use oauth2::{ClientId, ClientSecret};
use serde::de::{Error, IntoDeserializer, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::{
    collections::HashMap,
    env::{var, vars},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::state::Environment;
const ADDRESS: &str = "ADDRESS";
const DATABASE_URL: &str = "DATABASE_URL";
const REDIS_URL: &str = "REDIS_URL";
const DOMAIN_NAME: &str = "DOMAIN_NAME";
const REQUIRED: &[&str] = &[ADDRESS, DATABASE_URL, DOMAIN_NAME, REDIS_URL];
const LOCAL_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000);

#[derive(Debug)]
pub struct Configuration {
    pub environment: Environment,
    pub address: SocketAddr,
    pub database_url: String,
    pub domain_name: AbsoluteUri,
    pub redis_url: String,
    pub oauth: OAuthConfiguration,
    pub jwt: JwtConfiguration,
    pub smtp: SmtpConfiguration,
}

#[derive(Debug, Deserialize)]
pub struct OAuthAccess {
    pub id: ClientId,
    pub secret: ClientSecret,
}

impl OAuthAccess {
    fn from_env(provider: AuthProvider) -> Self {
        let provider = provider.to_string().to_uppercase();
        let id = ClientId::new(var(format!("{provider}_CLIENT_ID")).unwrap());
        let secret = ClientSecret::new(var(format!("{provider}_CLIENT_SECRET")).unwrap());
        Self { id, secret }
    }
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfiguration {
    pub is_enabled: bool,
    pub github: OAuthAccess,
}

impl OAuthConfiguration {
    fn from_env() -> Self {
        Self {
            is_enabled: true,
            github: OAuthAccess::from_env(AuthProvider::Github),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfiguration {
    pub access_secret: String,
    pub refresh_secret: String,
}

impl JwtConfiguration {
    fn from_env() -> Self {
        Self {
            access_secret: var("JWT_ACCESS_SECRET").unwrap(),
            refresh_secret: var("JWT_REFRESH_SECRET").unwrap(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SmtpConfiguration {
    pub relay: String,
    pub email: String,
    pub password: String,
}

impl SmtpConfiguration {
    fn from_env() -> Self {
        Self {
            relay: var("SMTP_RELAY").unwrap(),
            email: var("SMTP_EMAIL").unwrap(),
            password: var("SMTP_PASSWORD").unwrap(),
        }
    }
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
        let address: SocketAddr = var(ADDRESS)
            .unwrap()
            .parse()
            .expect("Invalid socket address");

        let database_url: String = var(DATABASE_URL).unwrap();

        let redis_url: String = var(REDIS_URL).unwrap();

        let domain_name: AbsoluteUri = var(DOMAIN_NAME)
            .unwrap()
            .parse()
            .expect("Invalid URI format for DOMAIN_NAME");

        let oauth: OAuthConfiguration = OAuthConfiguration::from_env();

        let jwt: JwtConfiguration = JwtConfiguration::from_env();

        let smtp: SmtpConfiguration = SmtpConfiguration::from_env();

        Self {
            environment,
            address,
            database_url,
            redis_url,
            domain_name,
            oauth,
            jwt,
            smtp,
        }
    }

    fn from_file(environment: Environment, config: Config) -> Self {
        let address: SocketAddr = config.get(ADDRESS).unwrap_or_else(|e| {
            if matches!(e, ConfigError::NotFound(_)) {
                LOCAL_ADDR
            } else {
                panic!("{e}");
            }
        });

        let database_url: String = config.get(DATABASE_URL).unwrap();

        let redis_url: String = config.get(REDIS_URL).unwrap();

        let domain_name: AbsoluteUri = config.get(DOMAIN_NAME).unwrap_or_else(|e| {
            if matches!(e, ConfigError::NotFound(_)) {
                AbsoluteUri::from_addr(&address)
            } else {
                panic!("{e}");
            }
        });

        let oauth: OAuthConfiguration = config.get("oauth").unwrap();

        let jwt: JwtConfiguration = config.get("jwt").unwrap();

        let smtp: SmtpConfiguration = config.get("smtp").unwrap();

        Self {
            environment,
            address,
            database_url,
            redis_url,
            domain_name,
            oauth,
            jwt,
            smtp,
        }
    }
}

pub fn load_config() -> Result<Configuration, anyhow::Error> {
    let environment: Environment = var("ENVIRONMENT")
        .map(|val| val.as_str().try_into().unwrap())
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

#[derive(Debug, Clone)]
pub struct AbsoluteUri(Uri);

impl AbsoluteUri {
    fn from_addr(addr: &SocketAddr) -> Self {
        Self(
            Uri::builder()
                .scheme(Scheme::HTTP)
                .authority(addr.to_string())
                .path_and_query("/")
                .build()
                .unwrap(),
        )
    }

    fn uri(&self) -> String {
        format!(
            "{}://{}",
            self.0.scheme_str().unwrap(),
            self.0.authority().unwrap()
        )
    }

    fn domain(&self) -> String {
        self.0.host().unwrap().to_string()
    }
}

impl TryFrom<Uri> for AbsoluteUri {
    type Error = anyhow::Error;

    fn try_from(value: Uri) -> Result<Self, Self::Error> {
        if let Some(scheme) = value.scheme_str() {
            match scheme {
                "http" | "https" => (),
                _ => bail!("invalid URI protocol, expected http or https")
            }
        }
        if value.host().is_none() {
            bail!("use absolute domain name in URI")
        }
        Ok(Self(value))
    }
}

impl Display for AbsoluteUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain())
    }
}

impl FromStr for AbsoluteUri {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri: Uri = s.parse()?;
        uri.try_into()
    }
}

struct AbsoluteUriVisitor;

impl<'de> Visitor<'de> for AbsoluteUriVisitor {
    type Value = AbsoluteUri;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        write!(formatter, "absolute URI to the domain name")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let uri: Uri = v
            .parse()
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))?;
        uri.try_into().map_err(|e| E::custom(e))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_str(&v)
    }
}
impl<'de> Deserialize<'de> for AbsoluteUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(AbsoluteUriVisitor)
    }
}

#[test]
fn absolute_path_with_custom_protocol() {
    let s: String = String::from("x://abc/def");
    let v: Result<AbsoluteUri, serde::de::value::Error> =
        s.into_deserializer().deserialize_string(AbsoluteUriVisitor);

    assert!(v.is_err());
}

#[test]
fn absolute_path_with_http_protocol() {
    let s: String = String::from("http://abc/def");
    let v: Result<AbsoluteUri, serde::de::value::Error> =
        s.into_deserializer().deserialize_string(AbsoluteUriVisitor);
    assert!(v.is_ok())
}

#[test]
fn relative_path() {
    let s: String = String::from("/abc/def");
    let v: Result<AbsoluteUri, serde::de::value::Error> =
        s.into_deserializer().deserialize_string(AbsoluteUriVisitor);
    assert!(v.is_err())
}

#[test]
fn domain_only() {
    let s: String = String::from("tokio.rs");
    let v: Result<AbsoluteUri, serde::de::value::Error> =
        s.into_deserializer().deserialize_string(AbsoluteUriVisitor);
    assert!(v.is_ok())
}
