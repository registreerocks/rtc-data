//! Helper type definitions

use actix_http::body::Body;
use actix_http::error::Error;
use actix_http::Request;
use actix_web::dev::{Service, ServiceResponse};

/// Shorthand for the complicated [`Service`] type returned by [`actix_web::test::init_service`].
///
/// This uses the "trait aliasing" technique described here:
/// <https://www.worthe-it.co.za/blog/2017-01-15-aliasing-traits-in-rust.html>
pub(crate) trait WebService:
    Service<Request, Response = ServiceResponse<Body>, Error = Error>
{
}

impl<S> WebService for S where S: Service<Request, Response = ServiceResponse<Body>, Error = Error> {}
