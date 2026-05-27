use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use vaultick::Vaultick;
use vaultick_request::{
    AsyncResponse, BoxError, RequestBody, RequestSpec, RequestTemplateIndex, ResolvedRequest,
    execute_async_with_client, replace_secret_placeholders,
};

use crate::models::{
    ExecAllowPattern, ExecArguments, ExecExecution, ExecResult, RequestArguments, RequestExecution,
    RequestResult,
};

pub struct SecretResolver<'a> {
    vaultick: &'a Vaultick,
    workspace_ref: &'a str,
    private_key_path: &'a Path,
    secret_key_index: RequestTemplateIndex,
    secret_cache: HashMap<String, String>,
    redacted_values: Vec<String>,
}

impl<'a> SecretResolver<'a> {
    pub fn new(
        vaultick: &'a Vaultick,
        workspace_ref: &'a str,
        private_key_path: &'a Path,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            vaultick,
            workspace_ref,
            private_key_path,
            secret_key_index: RequestTemplateIndex::new(
                vaultick
                    .list_secrets(workspace_ref)?
                    .into_iter()
                    .map(|secret| secret.key),
            )?,
            secret_cache: HashMap::new(),
            redacted_values: Vec::new(),
        })
    }

    pub fn list_secret_keys(&self) -> Vec<String> {
        self.secret_key_index.keys()
    }

    pub fn resolve_template(&mut self, input: &str) -> Result<String, BoxError> {
        replace_secret_placeholders(input, |secret_key| {
            self.resolve_secret_value_by_placeholder(secret_key)
        })
    }

    pub fn into_redacted_values(self) -> Vec<String> {
        self.redacted_values
    }

    fn resolve_secret_value_by_placeholder(
        &mut self,
        secret_key: &str,
    ) -> Result<String, BoxError> {
        let resolved_key = self
            .secret_key_index
            .canonical_key(secret_key)
            .map(ToString::to_string)
            .ok_or_else(|| io::Error::other(format!("secret not found: {secret_key}")))?;

        self.resolve_secret_value(&resolved_key)
    }

    fn resolve_secret_value(&mut self, secret_key: &str) -> Result<String, BoxError> {
        if let Some(value) = self.secret_cache.get(secret_key) {
            return Ok(value.clone());
        }

        let private_key_pem = fs::read_to_string(self.private_key_path)?;
        let value = self
            .vaultick
            .get_secret(self.workspace_ref, secret_key, &private_key_pem)?;
        if !value.is_empty() && !self.redacted_values.iter().any(|item| item == &value) {
            self.redacted_values.push(value.clone());
        }
        self.secret_cache
            .insert(secret_key.to_string(), value.clone());
        Ok(value)
    }
}

pub fn parse_exec_arguments(value: Option<&Value>) -> Result<ExecArguments, BoxError> {
    let args = serde_json::from_value::<ExecArguments>(
        value
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default())),
    )?;
    if args.program.trim().is_empty() {
        return Err(io::Error::other("exec program cannot be empty").into());
    }
    Ok(args)
}

pub fn parse_request_arguments(value: Option<&Value>) -> Result<RequestArguments, BoxError> {
    let args = serde_json::from_value::<RequestArguments>(
        value
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default())),
    )?;
    if args.url.trim().is_empty() {
        return Err(io::Error::other("request url cannot be empty").into());
    }
    Ok(args)
}

pub fn resolve_exec_execution(
    vaultick: &Vaultick,
    workspace_ref: &str,
    private_key_path: &Path,
    allowlist: &[ExecAllowPattern],
    arguments: &ExecArguments,
) -> Result<ExecExecution, BoxError> {
    let requested_tokens = requested_command_tokens(&arguments.program, &arguments.args);
    if !command_allowed(allowlist, &requested_tokens) {
        return Err(io::Error::other(format!(
            "command is not allowed by exec allowlist: {}",
            requested_tokens.join(" ")
        ))
        .into());
    }

    let mut resolver = SecretResolver::new(vaultick, workspace_ref, private_key_path)?;
    let mut env_vars = Vec::new();

    if arguments.all {
        for secret_key in resolver.list_secret_keys() {
            let value = resolver.resolve_template(&format!("${secret_key}"))?;
            upsert_env_var(&mut env_vars, secret_key, value);
        }
    } else {
        for env_name in &arguments.env {
            let normalized_env_name = normalize_secret_key(env_name)?;
            if !is_valid_env_var_name(&normalized_env_name) {
                return Err(io::Error::other(format!(
                    "invalid environment variable name: {env_name}"
                ))
                .into());
            }

            let value = resolver.resolve_template(&format!("${normalized_env_name}"))?;
            upsert_env_var(&mut env_vars, normalized_env_name, value);
        }
    }

    for (name, raw_value) in &arguments.assignments {
        if !is_valid_env_var_name(name) {
            return Err(
                io::Error::other(format!("invalid environment variable name: {name}")).into(),
            );
        }
        let template = if raw_value.is_empty() {
            format!("${name}")
        } else {
            raw_value.clone()
        };
        let value = resolver.resolve_template(&template)?;
        upsert_env_var(&mut env_vars, name.to_string(), value);
    }

    Ok(ExecExecution {
        program: arguments.program.clone(),
        args: arguments.args.clone(),
        env_vars,
        redacted_values: resolver.into_redacted_values(),
    })
}

pub fn run_exec_execution(
    execution: &ExecExecution,
    max_output_bytes: usize,
) -> Result<ExecResult, BoxError> {
    let mut child = ProcessCommand::new(&execution.program);
    child.args(&execution.args);
    child.envs(execution.env_vars.iter().map(|(key, value)| (key, value)));
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());

    let mut child = child.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("failed to capture child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to capture child stderr"))?;

    let stdout_redactions = execution.redacted_values.clone();
    let stderr_redactions = execution.redacted_values.clone();

    let stdout_handle =
        thread::spawn(move || read_redacted_output(stdout, &stdout_redactions, max_output_bytes));
    let stderr_handle =
        thread::spawn(move || read_redacted_output(stderr, &stderr_redactions, max_output_bytes));

    let status = child.wait()?;
    let stdout = stdout_handle
        .join()
        .map_err(|_| io::Error::other("failed to join child stdout reader"))??;
    let stderr = stderr_handle
        .join()
        .map_err(|_| io::Error::other("failed to join child stderr reader"))??;

    Ok(ExecResult {
        program: execution.program.clone(),
        args: execution.args.clone(),
        exit_code: status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

pub fn resolve_request_execution(
    vaultick: &Vaultick,
    workspace_ref: &str,
    private_key_path: &Path,
    arguments: &RequestArguments,
) -> Result<RequestExecution, BoxError> {
    let mut resolver = SecretResolver::new(vaultick, workspace_ref, private_key_path)?;
    let request = ResolvedRequest::from_spec(
        &RequestSpec {
            url: arguments.url.clone(),
            method: arguments.method.clone(),
            headers: arguments.headers.clone().into_iter().collect(),
            body: arguments.body.clone().map(RequestBody::Text),
            timeout: arguments.timeout_ms.map(Duration::from_millis),
        },
        |secret_key| resolver.resolve_template(&format!("${secret_key}")),
    )?;

    Ok(RequestExecution {
        request,
        redacted_values: resolver.into_redacted_values(),
    })
}

pub async fn collect_request_result(
    response: AsyncResponse,
    request: &ResolvedRequest,
    redacted_values: &[String],
    max_output_bytes: usize,
    mut on_chunk: impl FnMut(String) + Send,
) -> Result<RequestResult, BoxError> {
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect::<HashMap<_, _>>();

    let mut body_bytes = Vec::new();
    let mut stream = response.into_redacted_stream(redacted_values);
    use futures_util::StreamExt;
    while let Some(next) = stream.next().await {
        let chunk = next?;
        if !chunk.is_empty() {
            extend_with_limit(&mut body_bytes, &chunk, max_output_bytes)?;
            on_chunk(String::from_utf8_lossy(&chunk).into_owned());
        }
    }

    Ok(RequestResult {
        url: request.url.clone(),
        method: request.method.as_str().to_string(),
        status: status.as_u16(),
        headers,
        body: String::from_utf8_lossy(&body_bytes).into_owned(),
        ok: status.is_success(),
    })
}

pub async fn execute_request(
    client: &vaultick_request::AsyncClient,
    execution: &RequestExecution,
    max_output_bytes: usize,
    mut on_chunk: impl FnMut(String) + Send,
) -> Result<RequestResult, BoxError> {
    let response = execute_async_with_client(client, &execution.request).await?;
    collect_request_result(
        response,
        &execution.request,
        &execution.redacted_values,
        max_output_bytes,
        move |chunk| {
            on_chunk(chunk);
        },
    )
    .await
}

pub fn requested_command_tokens(program: &str, args: &[String]) -> Vec<String> {
    let mut tokens = Vec::with_capacity(args.len() + 1);
    tokens.push(program.to_string());
    tokens.extend(args.iter().cloned());
    tokens
}

pub fn parse_exec_allow_patterns(inputs: &[String]) -> Result<Vec<ExecAllowPattern>, BoxError> {
    inputs
        .iter()
        .map(|raw| {
            let tokens = raw
                .split_whitespace()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if tokens.is_empty() {
                return Err(io::Error::other("exec allowlist entries cannot be empty").into());
            }
            Ok(ExecAllowPattern {
                raw: raw.clone(),
                tokens,
            })
        })
        .collect()
}

pub fn command_allowed(allowlist: &[ExecAllowPattern], requested_tokens: &[String]) -> bool {
    allowlist.iter().any(|pattern| {
        pattern.tokens.len() <= requested_tokens.len()
            && pattern
                .tokens
                .iter()
                .zip(requested_tokens.iter())
                .all(|(expected, actual)| expected == actual)
    })
}

fn read_redacted_output(
    mut reader: impl Read,
    redacted_values: &[String],
    max_output_bytes: usize,
) -> Result<Vec<u8>, io::Error> {
    let mut redactor = vaultick_request::Redactor::new(redacted_values);
    let mut buffer = [0_u8; 8192];
    let mut output = Vec::new();

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let redacted = redactor.redact_chunk(&buffer[..bytes_read]);
        extend_with_limit(&mut output, &redacted, max_output_bytes)?;
    }

    let tail = redactor.finish();
    extend_with_limit(&mut output, &tail, max_output_bytes)?;
    Ok(output)
}

fn extend_with_limit(output: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<(), io::Error> {
    if output.len().saturating_add(chunk.len()) > limit {
        return Err(io::Error::other(format!(
            "tool output exceeded limit of {limit} bytes"
        )));
    }

    output.extend_from_slice(chunk);
    Ok(())
}

fn normalize_secret_key(key: &str) -> Result<String, io::Error> {
    let normalized = key.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(io::Error::other("secret key cannot be empty"));
    }

    Ok(normalized)
}

fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(ch) if ch == '_' || ch.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn upsert_env_var(env_vars: &mut Vec<(String, String)>, name: String, value: String) {
    if let Some((_, existing_value)) = env_vars.iter_mut().find(|(key, _)| *key == name) {
        *existing_value = value;
    } else {
        env_vars.push((name, value));
    }
}

#[cfg(test)]
mod tests {
    use super::{command_allowed, parse_exec_allow_patterns, requested_command_tokens};

    #[test]
    fn command_allowlist_matches_prefix_tokens() {
        let allowlist =
            parse_exec_allow_patterns(&["git".to_string(), "aws s3".to_string()]).unwrap();
        assert!(command_allowed(
            &allowlist,
            &requested_command_tokens("git", &["status".to_string()])
        ));
        assert!(command_allowed(
            &allowlist,
            &requested_command_tokens("aws", &["s3".to_string(), "ls".to_string()])
        ));
        assert!(!command_allowed(
            &allowlist,
            &requested_command_tokens("bash", &["-lc".to_string(), "env".to_string()])
        ));
    }
}
