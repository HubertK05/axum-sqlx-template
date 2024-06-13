use crate::errors::AppError;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, SameSite};
use lettre::Address;
use serde::Deserialize;
use time::Duration;
use utoipa::ToSchema;

pub mod jwt;
pub mod oauth;

pub fn hash_password(password: String) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    argon
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn is_correct_password(password: String, password_hash: String) -> bool {
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn safe_cookie<'c>(base: impl Into<Cookie<'c>>, max_age: Duration) -> Cookie<'c> {
    // TODO: sign cookie
    // TODO: add domain in production
    // As per the newer RFC 6265 it's no longer necessary to include the . in front of the domain
    // https://stackoverflow.com/questions/1062963/how-do-browser-cookie-domains-work
    // https://stackoverflow.com/questions/1134290/cookies-on-localhost-with-explicit-domain
    Cookie::build(base)
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(max_age)
        .build()
}

#[derive(Deserialize, ToSchema)]
pub struct RegistrationForm {
    pub login: String,
    pub email: Address,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginForm {
    pub login: String,
    pub password: String,
}

pub trait PasswordStrength {
    fn inputs(&self) -> Vec<&str>;
    fn password(&self) -> &str;

    fn check_password_strength(&self) -> crate::Result<()> {
        check_password_strength(self.password(), self.inputs().as_slice())
    }
}

impl PasswordStrength for RegistrationForm {
    fn inputs(&self) -> Vec<&str> {
        vec![self.email.as_ref(), self.login.as_str()]
    }
    fn password(&self) -> &str {
        self.password.as_str()
    }
}

impl PasswordStrength for LoginForm {
    fn inputs(&self) -> Vec<&str> {
        vec![self.login.as_str()]
    }
    fn password(&self) -> &str {
        self.password.as_str()
    }
}

pub fn check_password_strength(password: &str, inputs: &[&str]) -> crate::Result<()> {
    let entropy = zxcvbn::zxcvbn(password, inputs);
    if let Some(feedback) = entropy.feedback() {
        let warning = feedback
            .warning()
            .map_or(String::from("No warning. "), |w| w.to_string());
        let suggestions = feedback
            .suggestions()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        return Err(AppError::exp(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Password is too weak: {warning}{suggestions}"),
        ));
    }
    Ok(())
}
