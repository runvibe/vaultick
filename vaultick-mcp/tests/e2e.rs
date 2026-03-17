use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use rsa::BigUint;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::RsaPublicKey;
use serde_json::{Value, json};
use ssh_key::PublicKey as SshPublicKey;
use tempfile::TempDir;
use vaultick::Vaultick;

const SSH_RSA_PUBLIC: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmjkeMm8k3JkNrf16eb5pG4bc77B6Mt3VN4saltsRV8vASpyWa/PlBgdaeldOaNJ5NK0gqU3KyiUNzHbdcc8572e7IUBDJS/rlaWARiSL4aos2VbNX0k56Z5zYp9m/bq5m9/mlb+PQkNBjIhimgpYNiq2TwBiYeA6tLb79cPtHA0cX5BLk/a5oUpLsiR4kI/f+Q98vVDKasKXXVh5YLkLobrruDB6er2A9fOcIUF0O4JCRLh/Dc161gE3fQrYTMQenbppZzfxrZfQ8YwLPvKjnqm+XRX+pbTtaJuj0EgTSzUK+EZxoSw8CNwiZpxrjwecTMVQ8w/srQmh4ABGuTqk0wP8HcI7hg+fpBv7kiejh5X/Oehxt+Puu85u9GVXb1a0av/vhJvUCBcuISvCA/z1wVJ0xdLhb1/ZiTDdTzyNbZQ0OQijzK+e1SlkNhp+3eGVZu3pNZvnTppwIXv3wg6kV1HodkWGgh1ayY7Buc52Z8okDYqvJat5CzOj5OaQNr/k= user@example.com
"#;

const SSH_RSA_PRIVATE: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEApo5HjJvJNyZDa39enm+aRuG3O+wejLd1TeLGpbbEVfLwEqclmvz5
QYHWnpXTmjSeTStIKlNysolDcx23XHPOe9nuyFAQyUv65WlgEYki+GqLNlWzV9JOemec2K
fZv26uZvf5pW/j0JDQYyIYpoKWDYqtk8AYmHgOrS2+/XD7RwNHF+QS5P2uaFKS7IkeJCP3
/kPfL1QymrCl11YeWC5C6G667gwenq9gPXznCFBdDuCQkS4fw3NetYBN30K2EzEHp26aWc
38a2X0PGMCz7yo56pvl0V/qW07Wibo9BIE0s1CvhGcaEsPAjcImaca48HnEzFUPMP7K0Jo
eAARrk6pNMD/B3CO4YPn6Qb+5Ino4eV/znocbfj7rvObvRlV29WtGr/74Sb1AgXLiErwgP
89cFSdMXS4W9f2Ykw3U88jW2UNDkIo8yvntUpZDYaft3hlWbt6TWb506acCF798IOpFdR6
HZFhoIdWsmOwbnOdmfKJA2KryWreQszo+TmkDa/5AAAFiD9lruM/Za7jAAAAB3NzaC1yc2
EAAAGBAKaOR4ybyTcmQ2t/Xp5vmkbhtzvsHoy3dU3ixqW2xFXy8BKnJZr8+UGB1p6V05o0
nk0rSCpTcrKJQ3Mdt1xzznvZ7shQEMlL+uVpYBGJIvhqizZVs1fSTnpnnNin2b9urmb3+a
Vv49CQ0GMiGKaClg2KrZPAGJh4Dq0tvv1w+0cDRxfkEuT9rmhSkuyJHiQj9/5D3y9UMpqw
pddWHlguQuhuuu4MHp6vYD185whQXQ7gkJEuH8NzXrWATd9CthMxB6dumlnN/Gtl9DxjAs
+8qOeqb5dFf6ltO1om6PQSBNLNQr4RnGhLDwI3CJmnGuPB5xMxVDzD+ytCaHgAEa5OqTTA
/wdwjuGD5+kG/uSJ6OHlf856HG34+67zm70ZVdvVrRq/++Em9QIFy4hK8ID/PXBUnTF0uF
vX9mJMN1PPI1tlDQ5CKPMr57VKWQ2Gn7d4ZVm7ek1m+dOmnAhe/fCDqRXUeh2RYaCHVrJj
sG5znZnyiQNiq8lq3kLM6Pk5pA2v+QAAAAMBAAEAAAGAa2MLEMaVCsDZ8WJzEDYmw5LewH
zyCYpz0J7ps4jOuBfl4DDy1yZKU4kyZpd1klRgyKKiad/Z8PD9kyhSxAJK3KHcCj1NRWx+
vRGfBk9kQ8T2Mzc4ZeRMAzHw9+PpSjtDqVIzHQ6yVRQ5t+ERAbLqqpqCZeQSN6QY2mHHZc
NF0Dh1yxqbcBd8Lvkmj+msjGLAj6kVKn/gDMrecqOs9vAE5bYXQkqAJ5ItvBdfIoYmKeRy
cZjKlAs7wkySaOOrX15ZZbg4fhRwZ5s+poCWX4FZPLFBMQ1MQVaeJbN2otxO2S+RSbdelw
6CJHMJRswg81H4EVsbv8uzj2vQbGIEcrdtZB01gCre8VIgq5sqV+NZGP4n4TgRnMpWqYzP
PA/Gg6GfJyGodm7N2cV2d2YmVvPT4FMl8/s3MmYj277GOz2YSDCy3Se+u2vS7VNF3/8Y3x
gGrevO2phFgElokwaBrD5SMTjFIWyxNZl+PhQ6eBasw9h0HqzsfhX1PaDwgQaRcI2dAAAA
wFRAWqZjrp4IADWnEAL0w1HX0ALDUgByXm3A/22QGjBLEDouoBZQeZbTGTWLW+pP60CY9T
BSjxK5jFDH3fyF/Er5JXuvmqcjXN9GdzSbd+UqQKXi9EEi0YzkCUGRTpkWnEi3CImNKYaW
VmB7fi62NUHgu9Vo5Pd0vsMTfQKlkcjHey4Yjdb3Lu9c/xknzeVzpMoNQ8K2xqlXIURRIu
HPaqXwW2XLnIYST595+inwXj8G87g+3KmUH1cWUOD7RoquTAAAAMEA0R564khkDTsgKTaR
iGVEzf4HeamqtWyPlia/HmZIv9mIvbCsfRGnPjQFYzbUrTkA/3GE7kBLhLrrEaKjAvmC2U
7vt1cDDsbXfZEV6u+Aq1dJoPW1kLKZ/96U+ZMN7bqyrzMwlbCKUEubMPERLc5R837QDQQz
Q9Qg0uL7iL1/iBt8iZDki5P9HShPzIwcB/vvwE0CklsvFZqan1Zwc+HJT9xuRy9IljvhbF
xUU4Vq0r95FuQsNudaUBiRDY2tA41zAAAAwQDL5Q5+zfXiyG52ypS+iwwFsJBB0rzd7rRn
LnEg6syDgOXWt3yFWDxQj47o1VfKvLbfroxyOF8PaTRevBWl3+yUnAdw0C15Rd01klYtpz
iGYuBTxUVNJpDeKmPMVV4aAQ4toK4wfRwR+FKpx1aOAvk9SbKo+Se3mUOykgytMhqiCEEJ
0TbQhcHQXDn0w2z4n9w8ZqdV5j9EbhYwKxNZlADwqDMhoua5FT3wLwPeMY6gkDkoKFPyAR
4JBdEVdmfK8eMAAAAQdXNlckBleGFtcGxlLmNvbQECAw==
-----END OPENSSH PRIVATE KEY-----
"#;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_vaultick-mcp")
}

struct TestEnv {
    _dir: TempDir,
    home: PathBuf,
    db_path: PathBuf,
    private_key_path: PathBuf,
    token: String,
}

impl TestEnv {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let ssh_dir = home.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();

        let private_key_path = ssh_dir.join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let db_path = dir.path().join("vaultick.db");
        let vaultick = Vaultick::open(&db_path).unwrap();
        let public_key_pem = ssh_public_key_to_pem(SSH_RSA_PUBLIC);
        vaultick
            .add_certificate("default", "id_rsa", &public_key_pem, None)
            .unwrap();
        vaultick
            .set_secret("default", "GITHUB_TOKEN", "super-secret-token", false)
            .unwrap();

        Self {
            _dir: dir,
            home,
            db_path,
            private_key_path,
            token: "test-token".to_string(),
        }
    }
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_initialize_and_list_tools() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let _guard = spawn_mcp_process(&env, &listen_addr, &["--allow-command", "git"]).await;

    let client = reqwest::Client::new();
    let initialize = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("authorization", format!("Bearer {}", env.token))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "test", "version": "1.0.0"}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(initialize.status(), StatusCode::OK);
    let session_id = initialize
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let initialized = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("authorization", format!("Bearer {}", env.token))
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(initialized.status(), StatusCode::ACCEPTED);

    let list = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("authorization", format!("Bearer {}", env.token))
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }))
        .send()
        .await
        .unwrap();
    let body: Value = list.json().await.unwrap();
    let tools = body["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert!(tools.iter().any(|tool| tool["name"] == "vaultick.exec"));
    assert!(tools.iter().any(|tool| tool["name"] == "vaultick.request"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_rejects_missing_token() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let _guard = spawn_mcp_process(&env, &listen_addr, &["--allow-command", "git"]).await;

    let response = reqwest::Client::new()
        .post(format!("http://{listen_addr}/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_exec_respects_allowlist() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let _guard = spawn_mcp_process(&env, &listen_addr, &["--allow-command", "git"]).await;
    let (client, session_id) = initialize_session(&env, &listen_addr).await;

    let response = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "vaultick.exec",
                "arguments": {
                    "program": "bash",
                    "args": ["-lc", "echo hi"],
                    "stream": false
                }
            }
        }))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["result"]["isError"], true);
    assert!(body["result"]["structuredContent"]["message"]
        .as_str()
        .unwrap()
        .contains("not allowed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_request_redacts_response_body() {
    let env = TestEnv::new();
    let upstream = spawn_upstream().await;
    let listen_addr = free_addr();
    let _guard = spawn_mcp_process(&env, &listen_addr, &["--allow-command", "git"]).await;
    let (client, session_id) = initialize_session(&env, &listen_addr).await;

    let response = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "vaultick.request",
                "arguments": {
                    "url": format!("http://{upstream}/echo"),
                    "headers": {
                        "Authorization": "Bearer $GITHUB_TOKEN"
                    }
                }
            }
        }))
        .send()
        .await
        .unwrap();

    let body: Value = response.json().await.unwrap();
    let text = body["result"]["structuredContent"]["body"].as_str().unwrap();
    assert!(text.contains("[REDACTED]"));
    assert!(!text.contains("super-secret-token"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_request_streams_sse_with_redacted_chunks() {
    let env = TestEnv::new();
    let upstream = spawn_sse_upstream().await;
    let listen_addr = free_addr();
    let _guard = spawn_mcp_process(&env, &listen_addr, &["--allow-command", "git"]).await;
    let (client, session_id) = initialize_session(&env, &listen_addr).await;

    let response = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("accept", "text/event-stream")
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "vaultick.request",
                "arguments": {
                    "url": format!("http://{upstream}/events"),
                    "headers": {
                        "Authorization": "Bearer $GITHUB_TOKEN"
                    },
                    "stream": true
                }
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("content-type").unwrap().to_str().unwrap(),
        "text/event-stream"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("[REDACTED]"));
    assert!(!body.contains("super-secret-token"));
    assert!(body.contains("\"id\":5"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_sse_endpoint_requires_existing_session() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let _guard = spawn_mcp_process(&env, &listen_addr, &["--allow-command", "git"]).await;

    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/mcp"))
        .header("authorization", format!("Bearer {}", env.token))
        .header("mcp-session-id", "missing-session")
        .header("mcp-protocol-version", "2025-06-18")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

async fn initialize_session(env: &TestEnv, listen_addr: &str) -> (reqwest::Client, String) {
    let client = reqwest::Client::new();
    let initialize = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("authorization", format!("Bearer {}", env.token))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "test", "version": "1.0.0"}
            }
        }))
        .send()
        .await
        .unwrap();
    let session_id = initialize
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let initialized = client
        .post(format!("http://{listen_addr}/mcp"))
        .header("authorization", format!("Bearer {}", env.token))
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(initialized.status(), StatusCode::ACCEPTED);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "authorization",
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", env.token)).unwrap(),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();
    (client, session_id)
}

async fn spawn_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/echo",
                get(|| async {
                    (
                        StatusCode::OK,
                        serde_json::json!({"token": "super-secret-token"}).to_string(),
                    )
                }),
            ),
        )
        .await
        .unwrap();
    });
    addr.to_string()
}

async fn spawn_sse_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/events",
                get(|| async move {
                    let stream = async_stream::stream! {
                        yield Ok::<_, std::io::Error>(Bytes::from_static(b"data: super-"));
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        yield Ok::<_, std::io::Error>(Bytes::from_static(b"secret-token\n\n"));
                    };
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            HeaderValue::from_static("text/event-stream"),
                        )],
                        axum::body::Body::from_stream(stream),
                    )
                        .into_response()
                }),
            ),
        )
        .await
        .unwrap();
    });
    addr.to_string()
}

async fn spawn_mcp_process(env: &TestEnv, listen_addr: &str, extra_args: &[&str]) -> ChildGuard {
    let mut command = Command::new(binary());
    command
        .arg("--listen")
        .arg(listen_addr)
        .arg("--token")
        .arg(&env.token)
        .arg("--db")
        .arg(&env.db_path)
        .arg("--workspace")
        .arg("default")
        .arg("--private-key")
        .arg(&env.private_key_path)
        .env("HOME", &env.home)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for arg in extra_args {
        command.arg(arg);
    }
    let child = command.spawn().unwrap();
    wait_for_server(listen_addr, child).await
}

async fn wait_for_server(listen_addr: &str, mut child: Child) -> ChildGuard {
    let client = reqwest::Client::new();
    for _ in 0..80 {
        if let Ok(Some(_)) = child.try_wait() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "vaultick-mcp exited early: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        if client
            .get(format!("http://{listen_addr}/mcp"))
            .header("authorization", "Bearer test-token")
            .header("mcp-session-id", "none")
            .header("mcp-protocol-version", "2025-06-18")
            .send()
            .await
            .is_ok()
        {
            return ChildGuard { child };
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("vaultick-mcp did not start listening on {listen_addr}");
}

fn free_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr.to_string()
}

fn ssh_public_key_to_pem(openssh: &str) -> String {
    let public_key = SshPublicKey::from_openssh(openssh).unwrap();
    let rsa_public = public_key.key_data().rsa().unwrap();
    let public_key = RsaPublicKey::new(
        BigUint::from_bytes_be(rsa_public.n.as_bytes()),
        BigUint::from_bytes_be(rsa_public.e.as_bytes()),
    )
    .unwrap();
    public_key.to_public_key_pem(LineEnding::LF).unwrap().to_string()
}
