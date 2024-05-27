use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use sqlx::error::{DatabaseError, ErrorKind};
use sqlx::{query, Error, PgPool};
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
    fn from(val: Error) -> Self {
        Self::Unexpected(anyhow!(val))
    }
}
