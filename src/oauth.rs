mod github;

use crate::config::{AbsoluteUri, OAuthAccess, OAuthConfiguration};
use axum::async_trait;
use oauth2::basic::{
    BasicClient, BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenResponse,
};
use oauth2::{
    basic::{BasicErrorResponseType, BasicTokenType},
    AccessToken, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointNotSet, EndpointSet, HttpClientError, IntrospectionUrl,
    RedirectUrl, RequestTokenError, RevocationUrl, Scope, StandardErrorResponse,
    StandardRevocableToken, StandardTokenResponse, TokenUrl,
};
use reqwest::header::USER_AGENT;
use reqwest::{Client, Url};
use serde::Deserialize;
use std::env;
use std::fmt::{Display, Formatter};
use axum::extract::FromRef;
use redis::{RedisWrite, ToRedisArgs};
use crate::oauth::github::GithubClient;

type CustomOAuthClient = oauth2::Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

#[derive(Clone, FromRef)]
pub struct OAuthClients {
    pub github: GithubClient
}

impl OAuthClients {
    pub fn new(client: Client, config: &OAuthConfiguration, public_domain: &AbsoluteUri) -> Self {
        Self {github: GithubClient::new(client.clone(), &config.github, public_domain)}
    }
}

#[derive(Type)]
#[sqlx(type_name = "credential_provider", rename_all = "snake_case")]
pub enum AuthProvider {
    Github,
    Google,
    Facebook,
    Discord,
}

impl Display for AuthProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let provider = match self {
            AuthProvider::Github => "github",
            AuthProvider::Google => "google",
            AuthProvider::Facebook => "facebook",
            AuthProvider::Discord => "discord",
        };
        write!(f, "{provider}",)
    }
}

impl ToRedisArgs for AuthProvider {
    fn write_redis_args<W>(&self, out: &mut W) where W: ?Sized + RedisWrite {
        out.write_arg_fmt(self);
    }
}

pub trait OAuthUser {
    fn subject_id(&self) -> String;

    fn username(&self) -> Option<String> {
        None
    }

    fn email(&self) -> Option<String> {
        None
    }
}

#[async_trait]
pub trait OAuthClient
where
    Self: Sized + Sync,
{
    type User: OAuthUser;
    type Error: std::error::Error + Send + Sync + 'static;

    fn key(&self) -> AuthProvider;

    fn get_url_and_state(&self) -> (Url, CsrfToken);

    async fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> Result<
        BasicTokenResponse,
        RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>,
    >;

    async fn get_user(
        &self,
        token: &AccessToken,
    ) -> Result<Self::User, Self::Error>;
}
