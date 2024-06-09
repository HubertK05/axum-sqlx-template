pub mod templates;

use axum::extract::FromRef;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::Error;
use lettre::{Address, AsyncTransport, Message, Tokio1Executor};
use templates::Mail;

use crate::config::SmtpConfiguration;

const APP_NAME: &str = "Template";

#[derive(FromRef, Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    address: Address,
    domain: String,
}

impl Mailer {
    pub fn new(domain: String, options: &SmtpConfiguration) -> Self {
        Self {
            transport: AsyncSmtpTransport::<Tokio1Executor>::relay(&*options.relay)
                .unwrap()
                .credentials(Credentials::new(options.email.clone(), options.password.clone()))
                .build(),
            address: options.email.parse().expect("Failed to parse email"),
            domain,
        }
    }

    pub async fn send_mail(
        &self,
        mail: impl Into<Mail>,
    ) -> Result<Response, Error> {
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
}
