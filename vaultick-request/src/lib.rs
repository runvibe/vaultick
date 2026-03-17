use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures_util::Stream;
use futures_util::StreamExt;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode};
use thiserror::Error;

pub type BoxError = Box<dyn Error>;
pub use reqwest::Client as AsyncClient;
pub use reqwest::Url;
pub use reqwest::blocking::Client as BlockingClient;

#[derive(Debug, Error)]
pub enum VaultickRequestError {
    #[error("invalid header {0:?}; expected the format 'Name: Value'")]
    InvalidHeaderFormat(String),
    #[error("header name cannot be empty")]
    EmptyHeaderName,
    #[error("invalid HTTP method {method:?}: {source}")]
    InvalidMethod {
        method: String,
        source: http::method::InvalidMethod,
    },
    #[error("invalid request header name {name:?}: {source}")]
    InvalidRequestHeaderName {
        name: String,
        source: http::header::InvalidHeaderName,
    },
    #[error("invalid request header value for {name}: {source}")]
    InvalidRequestHeaderValue {
        name: String,
        source: http::header::InvalidHeaderValue,
    },
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, VaultickRequestError>;

impl VaultickRequestError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Http(err) if err.is_timeout())
    }
}

#[derive(Debug, Clone)]
pub struct RequestTemplateIndex {
    canonical_keys: HashMap<String, String>,
}

impl RequestTemplateIndex {
    pub fn new<I>(keys: I) -> std::result::Result<Self, BoxError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut canonical_keys = HashMap::new();

        for key in keys {
            let normalized = key.to_ascii_lowercase();
            if let Some(existing_key) = canonical_keys.insert(normalized, key.clone()) {
                return Err(io::Error::other(format!(
                    "cannot use placeholder resolution because secrets {existing_key} and {key} collide"
                ))
                .into());
            }
        }

        Ok(Self { canonical_keys })
    }

    pub fn canonical_key(&self, key: &str) -> Option<&str> {
        self.canonical_keys
            .get(&key.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn keys(&self) -> Vec<String> {
        let mut keys = self.canonical_keys.values().cloned().collect::<Vec<_>>();
        keys.sort();
        keys
    }
}

pub fn replace_secret_placeholders<F>(
    input: &str,
    mut resolve_secret: F,
) -> std::result::Result<String, BoxError>
where
    F: FnMut(&str) -> std::result::Result<String, BoxError>,
{
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(start_offset) = input[cursor..].find('$') {
        let start = cursor + start_offset;
        output.push_str(&input[cursor..start]);

        let Some(first_char) = input[start + 1..].chars().next() else {
            output.push('$');
            cursor = start + 1;
            break;
        };

        if !is_secret_placeholder_start(first_char) {
            output.push('$');
            cursor = start + 1;
            continue;
        }

        let mut end = start + 1 + first_char.len_utf8();
        for ch in input[end..].chars() {
            if is_secret_placeholder_continue(ch) {
                end += ch.len_utf8();
            } else {
                break;
            }
        }

        let secret_key = &input[start + 1..end];
        output.push_str(&resolve_secret(secret_key)?);
        cursor = end;
    }

    output.push_str(&input[cursor..]);
    Ok(output)
}

pub fn collect_secret_placeholders(input: &str) -> Vec<String> {
    let mut placeholders = Vec::new();
    let mut cursor = 0;

    while let Some(start_offset) = input[cursor..].find('$') {
        let start = cursor + start_offset;
        let Some(first_char) = input[start + 1..].chars().next() else {
            break;
        };

        if !is_secret_placeholder_start(first_char) {
            cursor = start + 1;
            continue;
        }

        let mut end = start + 1 + first_char.len_utf8();
        for ch in input[end..].chars() {
            if is_secret_placeholder_continue(ch) {
                end += ch.len_utf8();
            } else {
                break;
            }
        }

        placeholders.push(input[start + 1..end].to_string());
        cursor = end;
    }

    placeholders
}

#[derive(Debug, Clone)]
pub struct Redactor {
    patterns: Vec<Vec<u8>>,
    pending: Vec<u8>,
}

impl Redactor {
    pub fn new(redacted_values: &[String]) -> Self {
        let mut patterns = redacted_values
            .iter()
            .filter(|value| !value.is_empty())
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        patterns.dedup();

        Self {
            patterns,
            pending: Vec::new(),
        }
    }

    pub fn redact_chunk(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();

        for byte in bytes {
            self.pending.push(*byte);
            flush_redaction_pending(&mut output, &mut self.pending, &self.patterns, false);
        }

        output
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let mut output = Vec::new();
        flush_redaction_pending(&mut output, &mut self.pending, &self.patterns, true);
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSpec {
    pub url: String,
    pub method: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Option<RequestBody>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<RequestBody>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBody {
    Text(String),
    Bytes(Vec<u8>),
}

impl ResolvedRequest {
    pub fn from_spec<F>(
        spec: &RequestSpec,
        mut resolve_secret: F,
    ) -> std::result::Result<Self, BoxError>
    where
        F: FnMut(&str) -> std::result::Result<String, BoxError>,
    {
        let url = replace_secret_placeholders(&spec.url, &mut resolve_secret)?;
        let method = parse_http_method(spec.method.as_deref().unwrap_or("GET"))
            .map_err(|err| Box::new(err) as BoxError)?;
        let mut headers = Vec::with_capacity(spec.headers.len());

        for (name, value) in &spec.headers {
            headers.push((
                name.clone(),
                replace_secret_placeholders(value, &mut resolve_secret)?,
            ));
        }

        let body = spec
            .body
            .as_ref()
            .map(|body| match body {
                RequestBody::Text(value) => {
                    replace_secret_placeholders(value, &mut resolve_secret).map(RequestBody::Text)
                }
                RequestBody::Bytes(value) => Ok(RequestBody::Bytes(value.clone())),
            })
            .transpose()?;

        Ok(Self {
            method,
            url,
            headers,
            body,
            timeout: spec.timeout,
        })
    }
}

pub fn parse_request_headers(headers: &[String]) -> Result<Vec<(String, String)>> {
    let mut parsed = Vec::with_capacity(headers.len());

    for header in headers {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| VaultickRequestError::InvalidHeaderFormat(header.clone()))?;

        let name = name.trim();
        if name.is_empty() {
            return Err(VaultickRequestError::EmptyHeaderName);
        }

        parsed.push((name.to_string(), value.trim().to_string()));
    }

    Ok(parsed)
}

pub fn parse_http_method(method: &str) -> Result<Method> {
    Method::from_bytes(method.trim().as_bytes()).map_err(|source| {
        VaultickRequestError::InvalidMethod {
            method: method.to_string(),
            source,
        }
    })
}

pub struct BlockingResponse {
    status: StatusCode,
    headers: HeaderMap,
    response: reqwest::blocking::Response,
}

impl BlockingResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn copy_redacted_to_writer(
        self,
        writer: &mut impl Write,
        redacted_values: &[String],
    ) -> io::Result<()> {
        stream_redacted_output(self.response, writer, redacted_values)
    }
}

pub struct AsyncResponse {
    status: StatusCode,
    headers: HeaderMap,
    response: reqwest::Response,
}

impl AsyncResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn into_redacted_stream(
        self,
        redacted_values: &[String],
    ) -> Pin<Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send>> {
        let mut upstream_stream = self.response.bytes_stream();
        let redacted_values = redacted_values.to_vec();
        Box::pin(async_stream::stream! {
            let mut redactor = Redactor::new(&redacted_values);

            while let Some(next_chunk) = upstream_stream.next().await {
                let chunk = match next_chunk {
                    Ok(chunk) => chunk,
                    Err(err) => {
                        yield Err::<Bytes, reqwest::Error>(err);
                        return;
                    }
                };
                let redacted = redactor.redact_chunk(&chunk);
                if !redacted.is_empty() {
                    yield Ok::<Bytes, reqwest::Error>(Bytes::from(redacted));
                }
            }

            let tail = redactor.finish();
            if !tail.is_empty() {
                yield Ok::<Bytes, reqwest::Error>(Bytes::from(tail));
            }
        })
    }
}

pub fn execute_blocking(request: &ResolvedRequest) -> Result<BlockingResponse> {
    let client = BlockingClient::builder().build()?;
    execute_blocking_with_client(&client, request)
}

pub fn execute_blocking_with_client(
    client: &BlockingClient,
    request: &ResolvedRequest,
) -> Result<BlockingResponse> {
    let mut builder = client.request(request.method.clone(), &request.url);
    for (name, value) in &request.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|source| {
            VaultickRequestError::InvalidRequestHeaderName {
                name: name.clone(),
                source,
            }
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|source| {
            VaultickRequestError::InvalidRequestHeaderValue {
                name: name.clone(),
                source,
            }
        })?;
        builder = builder.header(header_name, header_value);
    }

    if let Some(body) = &request.body {
        builder = builder.body(match body {
            RequestBody::Text(value) => value.clone().into_bytes(),
            RequestBody::Bytes(value) => value.clone(),
        });
    }
    if let Some(timeout) = request.timeout {
        builder = builder.timeout(timeout);
    }

    let response = builder.send()?;
    let status = response.status();
    let headers = response.headers().clone();

    Ok(BlockingResponse {
        status,
        headers,
        response,
    })
}

pub async fn execute_async(request: &ResolvedRequest) -> Result<AsyncResponse> {
    let client = AsyncClient::builder().build()?;
    execute_async_with_client(&client, request).await
}

pub async fn execute_async_with_client(
    client: &AsyncClient,
    request: &ResolvedRequest,
) -> Result<AsyncResponse> {
    let mut builder = client.request(request.method.clone(), &request.url);
    for (name, value) in &request.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|source| {
            VaultickRequestError::InvalidRequestHeaderName {
                name: name.clone(),
                source,
            }
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|source| {
            VaultickRequestError::InvalidRequestHeaderValue {
                name: name.clone(),
                source,
            }
        })?;
        builder = builder.header(header_name, header_value);
    }

    if let Some(body) = &request.body {
        builder = builder.body(match body {
            RequestBody::Text(value) => value.clone().into_bytes(),
            RequestBody::Bytes(value) => value.clone(),
        });
    }
    if let Some(timeout) = request.timeout {
        builder = builder.timeout(timeout);
    }

    let response = builder.send().await?;
    let status = response.status();
    let headers = response.headers().clone();

    Ok(AsyncResponse {
        status,
        headers,
        response,
    })
}

pub fn stream_redacted_output(
    mut reader: impl Read,
    writer: &mut impl Write,
    redacted_values: &[String],
) -> io::Result<()> {
    let mut redactor = Redactor::new(redacted_values);
    let mut buffer = [0_u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let redacted = redactor.redact_chunk(&buffer[..bytes_read]);
        writer.write_all(&redacted)?;
        writer.flush()?;
    }

    writer.write_all(&redactor.finish())?;
    writer.flush()
}

fn flush_redaction_pending(
    output: &mut Vec<u8>,
    pending: &mut Vec<u8>,
    patterns: &[Vec<u8>],
    eof: bool,
) {
    loop {
        if pending.is_empty() {
            return;
        }

        if let Some(pattern) = patterns
            .iter()
            .find(|pattern| pending.starts_with(pattern.as_slice()))
        {
            let waiting_for_longer_match = !eof
                && patterns.iter().any(|candidate| {
                    candidate.len() > pending.len() && candidate.starts_with(pending.as_slice())
                });

            if waiting_for_longer_match {
                return;
            }

            output.extend_from_slice(b"[REDACTED]");
            pending.drain(..pattern.len());
            continue;
        }

        let waiting_for_partial_match = !eof
            && patterns
                .iter()
                .any(|pattern| pattern.starts_with(pending.as_slice()));
        if waiting_for_partial_match {
            return;
        }

        output.push(pending[0]);
        pending.drain(..1);
    }
}

fn is_secret_placeholder_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_secret_placeholder_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::{
        Redactor, RequestBody, RequestSpec, RequestTemplateIndex, ResolvedRequest,
        collect_secret_placeholders, parse_http_method, parse_request_headers,
        replace_secret_placeholders,
    };
    use http::Method;

    #[test]
    fn request_template_index_detects_case_collisions() {
        let err = RequestTemplateIndex::new(vec!["TOKEN".to_string(), "token".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("collide"));
    }

    #[test]
    fn replace_secret_placeholders_resolves_multiple_values() {
        let rendered = replace_secret_placeholders("Bearer $token/$OTHER", |key| {
            Ok(match key {
                "token" => "abc".to_string(),
                "OTHER" => "xyz".to_string(),
                _ => unreachable!(),
            })
        })
        .unwrap();

        assert_eq!(rendered, "Bearer abc/xyz");
    }

    #[test]
    fn collect_secret_placeholders_ignores_invalid_dollar_sequences() {
        assert_eq!(
            collect_secret_placeholders("$TOKEN $5 $$ $other"),
            vec!["TOKEN".to_string(), "other".to_string()]
        );
    }

    #[test]
    fn redactor_masks_values_across_chunk_boundaries() {
        let mut redactor = Redactor::new(&["super-secret".to_string()]);
        let mut output = Vec::new();
        output.extend(redactor.redact_chunk(b"hello super-"));
        output.extend(redactor.redact_chunk(b"secret world"));
        output.extend(redactor.finish());

        assert_eq!(String::from_utf8(output).unwrap(), "hello [REDACTED] world");
    }

    #[test]
    fn request_validation_parses_headers_and_methods() {
        assert_eq!(
            parse_request_headers(&["Authorization: Bearer token".to_string()]).unwrap(),
            vec![("Authorization".to_string(), "Bearer token".to_string())]
        );
        assert_eq!(parse_http_method("POST").unwrap(), Method::POST);
    }

    #[test]
    fn resolved_request_replaces_placeholders() {
        let request = ResolvedRequest::from_spec(
            &RequestSpec {
                url: "https://example.com/$TOKEN".to_string(),
                method: Some("POST".to_string()),
                headers: vec![("Authorization".to_string(), "Bearer $TOKEN".to_string())],
                body: Some(RequestBody::Text("{\"token\":\"$TOKEN\"}".to_string())),
                timeout: None,
            },
            |key| {
                Ok(if key == "TOKEN" {
                    "secret".to_string()
                } else {
                    unreachable!()
                })
            },
        )
        .unwrap();

        assert_eq!(request.method, Method::POST);
        assert_eq!(request.url, "https://example.com/secret");
        assert_eq!(
            request.headers,
            vec![("Authorization".to_string(), "Bearer secret".to_string())]
        );
        assert_eq!(
            request.body,
            Some(RequestBody::Text("{\"token\":\"secret\"}".to_string()))
        );
    }
}
