//! Data validation error types

use std::{error, fmt};

use actix_web::ResponseError;

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub message: &'static str,
}

impl ValidationError {
    pub fn new(message: &'static str) -> Self {
        ValidationError { message }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "Validation error: {}", self.message)
    }
}

impl error::Error for ValidationError {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl ResponseError for ValidationError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::BAD_REQUEST
    }
}
