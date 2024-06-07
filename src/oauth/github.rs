use crate::config::{AbsoluteUri, OAuthAccess};
use crate::oauth::{AuthProvider, CustomOAuthClient, OAuthClient, OAuthUser};
use axum::async_trait;
use oauth2::basic::{BasicClient, BasicErrorResponse, BasicTokenResponse};
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthType, AuthUrl, AuthorizationCode, CsrfToken, HttpClientError, RedirectUrl,
    RequestTokenError, Scope, TokenUrl,
};
use reqwest::Client;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct GithubUser {
    pub id: i32,
}

impl OAuthUser for GithubUser {
    fn subject_id(&self) -> String {
        self.id.to_string()
    }
}

#[derive(Clone)]
pub struct GithubClient {
    oauth_client: CustomOAuthClient,
    client: Client,
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

        Self {
            oauth_client,
            client,
        }
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
        self.oauth_client
            .exchange_code(code)
            .request_async(&self.client)
            .await
    }

    async fn get_user(&self, token: &AccessToken) -> Result<Self::User, Self::Error> {
        self.client
            .get("https://api.github.com/user")
            .bearer_auth(token.secret())
            .send()
            .await?
            .json()
            .await
    }
}
