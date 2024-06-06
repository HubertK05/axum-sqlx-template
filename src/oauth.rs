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

type CustomClient = oauth2::Client<
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

pub trait OAuthUser {
    fn unique_id(&self) -> String;

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

#[derive(Deserialize, Debug)]
pub struct GithubUser {
    pub id: i32,
}

impl OAuthUser for GithubUser {
    fn unique_id(&self) -> String {
        self.id.to_string()
    }
}

#[derive(Clone)]
pub struct GithubClient {
    oauth_client: CustomClient,
    client: Client
}

impl GithubClient {
    pub fn new(client: Client, access: &OAuthAccess, public_domain: &AbsoluteUri) -> Self {
        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .expect("Invalid authorization endpoint URL");
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
            .expect("Invalid token endpoint URL");

        let oauth_client = BasicClient::new(access.id.clone())
            .set_client_secret(access.secret.clone())
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_auth_type(AuthType::BasicAuth)
            .set_redirect_uri(
                RedirectUrl::new(format!("{public_domain}/auth/oauth2/github/callback"))
                    .expect("Invalid redirect URL"),
            );

        Self {oauth_client, client}
    }
}

#[async_trait]
impl OAuthClient for GithubClient {
    type User = GithubUser;
    type Error = reqwest::Error;

    fn key(&self) -> AuthProvider {
        AuthProvider::Github
    }

    fn get_url_and_state(&self) -> (Url, CsrfToken) {
        self.oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("public_repo".to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .url()
    }

    async fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> Result<
        BasicTokenResponse,
        RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>,
    > {
        self.oauth_client.exchange_code(code).request_async(&self.client).await
    }

    async fn get_user(
        &self,
        token: &AccessToken,
    ) -> Result<Self::User, Self::Error> {
        self.client
            .get("https://api.github.com/user")
            .bearer_auth(token.secret())
            .send()
            .await?
            .json()
            .await
    }
}
