use lettre::{
    message::{Mailbox, MultiPart},
    Address,
};
use maud::html;
use time::Duration;

pub struct Mail {
    pub to: Mailbox,
    pub subject: String,
    pub body: MultiPart,
}

pub struct AccountVerificationMail {
    username: String,
    to: Address,
    duration: Option<Duration>,
    callback_uri: String,
}

impl AccountVerificationMail {
    pub fn new(
        username: impl Into<String>,
        to: Address,
        duration: Option<Duration>,
        callback_uri: String,
    ) -> Self {
        Self {
            username: username.into(),
            to,
            duration,
            callback_uri,
        }
    }
}

impl From<AccountVerificationMail> for Mail {
    fn from(val: AccountVerificationMail) -> Self {
        let duration = val.duration.map_or(html! {}, |duration| {
            html! {
                p { "You have " (duration) " to verify your account" }
            }
        });

        let body = html! {
            h1 {"Hello!"}
            (duration)
            a href={ (val.callback_uri) } {
                "Click here to verify your account"
            }
        }
        .into_string();

        Self {
            to: Mailbox::new(Some(val.username), val.to),
            subject: "Account verification".to_string(),
            body: MultiPart::alternative_plain_html(body.clone(), body),
        }
    }
}

pub struct PasswordChangeRequestMail {
    to: Address,
    duration: Option<Duration>,
    callback_uri: String,
}

impl PasswordChangeRequestMail {
    pub fn new(to: Address, duration: Option<Duration>, callback_uri: String) -> Self {
        Self {
            to,
            duration,
            callback_uri,
        }
    }
}

impl From<PasswordChangeRequestMail> for Mail {
    fn from(val: PasswordChangeRequestMail) -> Self {
        let duration = val.duration.map_or(html! {}, |duration| {
            html! {
                p { "This link is valid for " (duration) " after issue time." }
            }
        });

        let body = html! {
            h1 {"Hello!"}
            p { "This is a request for password change. No changes have been made to your account." }
            p { "If you did not intend to receive this message, you can safely ignore it. Only someone can get to your email account can change the password." }
            (duration)
            a href={ (val.callback_uri) } {
                "Click here to change your password"
            }
        }.into_string();

        Self {
            to: Mailbox::new(None, val.to),
            subject: "Password change request".to_string(),
            body: MultiPart::alternative_plain_html(body.clone(), body),
        }
    }
}
