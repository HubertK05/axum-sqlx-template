use lettre::{message::{Mailbox, MultiPart}, Address};
use maud::html;
use time::Duration;

pub struct Mail {
    pub to: Mailbox,
    pub subject: String,
    pub body: MultiPart,
}

pub struct AccountVerificationMail {
    username: Option<String>,
    to: Address,
    duration: Option<Duration>,
    callback_uri: String,
}

impl AccountVerificationMail {
    pub fn new(username: Option<impl Into<String>>, to: Address, duration: Option<Duration>, callback_uri: String) -> Self {
        Self {
            username: username.map(|x| x.into()),
            to,
            duration,
            callback_uri,
        }
    }
}

impl From<AccountVerificationMail> for Mail {
    fn from(val: AccountVerificationMail) -> Self {
        let duration = val.duration.map_or(html! {}, |duration| html! {
            p { "You have " (duration) " to verify your account" }
        });

        let body = html! {
            h1 {"Hello!"}
            (duration)
            a href={ (val.callback_uri) } {
                "Click here to verify your account"
            }
        }.into_string();
        
        Self {
            to: Mailbox::new(val.username, val.to),
            subject: "Account verification".to_string(),
            body: MultiPart::alternative_plain_html(body.clone(), body),
        }
    }
}
