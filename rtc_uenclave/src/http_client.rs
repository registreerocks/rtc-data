use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use ureq;
use ureq::Agent;

#[cfg(test)]
use mockall::*;

// 200 KB
const ERR_RESPONSE_READ_LIMIT: usize = 200 * 1_024;

#[cfg_attr(test, automock)]
pub(crate) trait HttpClient {
    fn post_json<Tbody, Tresp>(&self, uri: String, body: Tbody) -> Result<Tresp, HttpRequestError>
    where
        Self: Sized,
        Tbody: 'static + Serialize,
        Tresp: 'static + DeserializeOwned;
}

impl HttpClient for Agent {
    fn post_json<Tbody: Serialize, Tresp: DeserializeOwned>(
        &self,
        uri: String,
        body: Tbody,
    ) -> Result<Tresp, HttpRequestError> {
        let resp = self
            .post(&uri)
            .set("ContentType", "application/json")
            .send_json(serde_json::to_value(body)?)?
            .into_json()?;

        Ok(resp)
    }
}

#[derive(Debug, Error)]
pub enum HttpRequestError {
    #[error("HTTP request failed with status code: {} . {}", .0, .1)]
    Status(u16, String),
    #[error("HTTP request transport failed: {}", .0)]
    Transport(String),
    #[error("HTTP request IO failed: {}", .0)]
    IO(#[from] std::io::Error),
}

impl From<ureq::Error> for HttpRequestError {
    fn from(err: ureq::Error) -> Self {
        match err {
            ureq::Error::Status(code, resp) => HttpRequestError::Status(code, read_response(resp)),
            ureq::Error::Transport(err) => HttpRequestError::Transport(format!("{}", err)),
        }
    }
}

impl From<serde_json::Error> for HttpRequestError {
    fn from(err: serde_json::Error) -> Self {
        HttpRequestError::IO(err.into())
    }
}

fn read_response(resp: ureq::Response) -> String {
    use std::io::Read;

    let mut buf: Vec<u8> = vec![];
    let result = resp
        .into_reader()
        .take((ERR_RESPONSE_READ_LIMIT + 1) as u64)
        .read_to_end(&mut buf);

    match result {
        Ok(n) if n > ERR_RESPONSE_READ_LIMIT => "Response larger than the read limit".to_string(),
        Ok(_) => String::from_utf8_lossy(&buf).to_string(),
        Err(err) => format!("Failed to read response: {}", err),
    }
}
