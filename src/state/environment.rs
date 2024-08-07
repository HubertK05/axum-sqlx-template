use std::fmt::Display;

use anyhow::anyhow;
use serde::{
    de::{Error, Visitor},
    Deserialize,
};

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
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))
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
