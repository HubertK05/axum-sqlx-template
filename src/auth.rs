use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::Deserialize;

pub mod jwt;
pub mod oauth;
pub mod session;

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

#[derive(Deserialize)]
pub struct RegistrationForm {
    pub login: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub login: String,
    pub password: String,
}
