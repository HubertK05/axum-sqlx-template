pub mod templates;

use anyhow::Context;
use axum::extract::FromRef;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::Error;
use lettre::{Address, AsyncTransport, Message, Tokio1Executor};
use templates::AccountVerificationMail;
use templates::Mail;
use templates::PasswordChangeRequestMail;
use time::Duration;
use uuid::Uuid;

use crate::config::SmtpConfiguration;

const APP_NAME: &str = "Template";
const VERIFICATION_PATH: &str = "/auth/verify";
const PASSWORD_CHANGE_PATH: &str = "/auth/password/callback";

#[derive(FromRef, Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    address: Address,
    frontend_domain: String,
}

impl Mailer {
    pub fn new(frontend_domain: String, options: &SmtpConfiguration) -> Self {
        Self {
            transport: AsyncSmtpTransport::<Tokio1Executor>::relay(&*options.relay)
                .unwrap()
                .credentials(Credentials::new(
                    options.email.clone(),
                    options.password.clone(),
                ))
                .build(),
            address: options.email.parse().expect("Failed to parse email"),
            frontend_domain,
        }
    }

    async fn send_mail(&self, mail: impl Into<Mail>) -> Result<Response, Error> {
        let mail = mail.into();

        let res = self
            .transport
            .send(
                Message::builder()
                    .from(Mailbox::new(
                        Some(String::from(APP_NAME)),
                        self.address.clone(),
                    ))
                    .to(mail.to)
                    .subject(mail.subject)
                    .multipart(mail.body)
                    .unwrap(),
            )
            .await?;

        Ok(res)
    }

    pub async fn send_verification_mail(
        &self,
        token: Uuid,
        username: impl Into<String>,
        to: Address,
        expiry: Option<Duration>,
    ) -> Result<Response, Error> {
        let callback_url = format!("{}{VERIFICATION_PATH}?token={token}", self.frontend_domain);
        let mail = AccountVerificationMail::new(username, to, expiry, callback_url);

        self.send_mail(mail).await
    }

    pub async fn send_password_change_request_mail(
        &self,
        token: Uuid,
        to: Address,
        expiry: Option<Duration>,
    ) -> Result<Response, Error> {
        let callback_url = format!(
            "{}{PASSWORD_CHANGE_PATH}?token={token}",
            self.frontend_domain
        );
        let mail = PasswordChangeRequestMail::new(to, expiry, callback_url);

        self.send_mail(mail).await
    }
}
