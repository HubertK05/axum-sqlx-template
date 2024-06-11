use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use oauth2::basic::BasicErrorResponse;
use oauth2::{HttpClientError, RequestTokenError};
use redis::RedisError;
use serde::Serialize;
use sqlx::error::ErrorKind;
use sqlx::Error;
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
    pub fn exp(code: StatusCode, message: impl Into<String>) -> Self {
        Self::Expected {
            code,
            message: message.into(),
        }
    }
}

pub trait DbErrMap<T> {
    fn map_db_err<O: FnOnce(DbErrMessage) -> DbErrMessage>(self, op: O) -> Result<T, DbErrMessage>;
}

impl<T> DbErrMap<T> for Result<T, sqlx::Error> {
    fn map_db_err<O: FnOnce(DbErrMessage) -> DbErrMessage>(self, op: O) -> Result<T, DbErrMessage> {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(op(DbErrMessage::new(e))),
        }
    }
}

pub struct DbErrMessage {
    pub err: AppError,
    pub kind: ErrorKind,
    pub name: String,
}

impl DbErrMessage {
    pub fn new(err: sqlx::Error) -> Self {
        let (kind, name) = if let Some(e) = err.as_database_error() {
            (e.kind(), e.constraint().unwrap_or_default().to_string())
        } else {
            (ErrorKind::Other, "".to_string())
        };

        Self {
            err: AppError::from(err),
            kind,
            name,
        }
    }

    pub fn fk(mut self, code: StatusCode, message: &str) -> Self {
        if self.kind == ErrorKind::ForeignKeyViolation {
            self.err = AppError::exp(code, message);
        }
        self
    }

    pub fn unique(mut self, code: StatusCode, message: &str) -> Self {
        if self.kind == ErrorKind::UniqueViolation {
            self.err = AppError::exp(code, message);
        }
        self
    }

    pub fn not_null(mut self, code: StatusCode, message: &str) -> Self {
        if self.kind == ErrorKind::NotNullViolation {
            self.err = AppError::exp(code, message);
        }
        self
    }

    pub fn check(mut self, code: StatusCode, message: &str) -> Self {
        if self.kind == ErrorKind::CheckViolation {
            self.err = AppError::exp(code, message);
        }
        self
    }
}

impl From<DbErrMessage> for AppError {
    fn from(value: DbErrMessage) -> Self {
        value.err
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
