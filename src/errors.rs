use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use oauth2::basic::{BasicErrorResponse};
use oauth2::{HttpClientError, RequestTokenError};
use redis::RedisError;
use serde::Serialize;
use sqlx::{Error};
use thiserror::Error;
use tracing::{debug, error};
use typeshare::typeshare;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("{code} - {message}")]
    Expected { code: StatusCode, message: String },
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

#[typeshare]
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

impl ErrorResponse {
    fn json(error: String) -> Json<Self> {
        Json(Self { error })
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let error_message = self.to_string();
        let (code, message) = match self {
            AppError::Expected { code, message } => {
                debug!("{error_message}");
                (code, ErrorResponse::json(message))
            }
            AppError::Unexpected(_) => {
                error!("{error_message}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::json("Unexpected server error".into()),
                )
            }
        };
        (code, message).into_response()
    }
}

impl AppError {
    pub fn exp(code: StatusCode, message: &str) -> Self {
        Self::Expected {
            code,
            message: message.to_string(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: Error) -> Self {
        Self::Unexpected(anyhow!(value))
    }
}

impl From<RedisError> for AppError {
    fn from(value: RedisError) -> Self {
        Self::Unexpected(anyhow!(value))
    }
}

impl From<reqwest::Error> for AppError {
    fn from(value: reqwest::Error) -> Self {
        Self::Unexpected(anyhow!(value))
    }
}

impl From<RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>> for AppError {
    fn from(value: RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>) -> Self {
        Self::Unexpected(anyhow!(value))
    }
}
