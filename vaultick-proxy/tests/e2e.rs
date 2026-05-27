use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::{Json, Router};
use base64::Engine;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{BigUint, RsaPublicKey};
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
    env!("CARGO_BIN_EXE_vaultick-proxy")
}

struct TestEnv {
    _dir: TempDir,
    home: PathBuf,
    db_path: PathBuf,
    private_key_path: PathBuf,
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
        }
    }

    fn write_config(&self, contents: &str) -> PathBuf {
        let path = self.home.join("vaultick-proxy.yaml");
        fs::create_dir_all(&self.home).unwrap();
        fs::write(&path, contents).unwrap();
        path
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
async fn proxy_forwards_requests_and_redacts_response_body() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(upstream_router()).await;
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://{upstream}\n      method: \"{{{{request.method}}}}\"\n      path: /echo/{{{{request.path_tail}}}}\n      query: \"{{{{request.query}}}}\"\n      headers:\n        Authorization: \"Bearer $GITHUB_TOKEN\"\n        X-Forwarded-User: \"{{{{request.header.x-user-id}}}}\"\n      body: \"{{{{request.body}}}}\"\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    ));

    let _guard = spawn_proxy_process(&config_path, &listen_addr).await;

    let response = reqwest::Client::new()
        .post(format!("http://{listen_addr}/github/team?mode=test"))
        .header("x-user-id", "42")
        .body("payload")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("\"user\":\"42\""), "body was: {body}");
    assert!(body.contains("\"query\":\"mode=test\""), "body was: {body}");
    assert!(body.contains("\"body\":\"payload\""), "body was: {body}");
    assert!(body.contains("[REDACTED]"));
    assert!(!body.contains("super-secret-token"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_redacts_sse_streams() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(sse_router()).await;
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /events\n    forward:\n      base_url: http://{upstream}\n      path: /sse\n      headers:\n        Authorization: \"Bearer $GITHUB_TOKEN\"\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    ));

    let _guard = spawn_proxy_process(&config_path, &listen_addr).await;

    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/events"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );

    let body = response.text().await.unwrap();
    assert!(body.contains("data: [REDACTED]"));
    assert!(!body.contains("super-secret-token"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_fails_fast_when_config_references_unknown_secret() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://127.0.0.1:1\n      headers:\n        Authorization: \"Bearer $MISSING_SECRET\"\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
    ));

    let output = Command::new(binary())
        .args(["--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("secret not found: MISSING_SECRET"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_starts_from_inline_yaml_env_config() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(upstream_router()).await;
    let listen_addr = free_addr();
    let config = format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://{upstream}\n      path: /echo/{{{{request.path_tail}}}}\n      headers:\n        Authorization: \"Bearer $GITHUB_TOKEN\"\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    );

    let _guard = spawn_proxy_from_env(&env, &listen_addr, &config, None).await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/github/team"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_starts_from_inline_json_env_config() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(upstream_router()).await;
    let listen_addr = free_addr();
    let config = serde_json::json!({
        "listen": listen_addr,
        "db": env.db_path,
        "workspace": "default",
        "private_key": env.private_key_path,
        "routes": [{
            "match": { "path_prefix": "/github" },
            "forward": {
                "base_url": format!("http://{upstream_addr}"),
                "path": "/echo/{{request.path_tail}}",
                "headers": { "Authorization": "Bearer $GITHUB_TOKEN" }
            }
        }]
    })
    .to_string();

    let _guard = spawn_proxy_from_env(&env, &listen_addr, &config, None).await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/github/team"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_starts_from_env_path_config() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(upstream_router()).await;
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://{upstream}\n      path: /echo/{{{{request.path_tail}}}}\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    ));

    let _guard =
        spawn_proxy_from_env(&env, &listen_addr, config_path.to_str().unwrap(), None).await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/github/team"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_starts_from_env_base64_config() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(upstream_router()).await;
    let listen_addr = free_addr();
    let config = format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://{upstream}\n      path: /echo/{{{{request.path_tail}}}}\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(config);

    let _guard = spawn_proxy_from_env(&env, &listen_addr, &encoded, None).await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/github/team"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_starts_from_env_url_with_headers() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let remote_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    let saw_auth_header = Arc::new(AtomicBool::new(false));
    let config_yaml = format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://127.0.0.1:1\n      path: /echo/{{{{request.path_tail}}}}\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
    );

    let auth_probe = Arc::clone(&saw_auth_header);
    tokio::spawn(async move {
        axum::serve(
            remote_listener,
            Router::new().route(
                "/config",
                get(move |headers: axum::http::HeaderMap| {
                    let config_yaml = config_yaml.clone();
                    let auth_probe = Arc::clone(&auth_probe);
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        if auth == "Bearer config-token" {
                            auth_probe.store(true, Ordering::SeqCst);
                        }
                        (StatusCode::OK, config_yaml)
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });

    wait_for_http_url(&format!("http://{remote_addr}/config")).await;

    let _guard = spawn_proxy_from_env(
        &env,
        &listen_addr,
        &format!("http://{remote_addr}/config"),
        Some(r#"{"Authorization":"Bearer config-token"}"#),
    )
    .await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/missing"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(saw_auth_header.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_config_overrides_vaultick_config_env() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let cli_listen = free_addr();
    let cli_config = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes: []\n",
        listen = cli_listen,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
    ));
    let env_config = format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes: []\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
    );

    let _guard = spawn_proxy_with_cli_and_env(&env, &cli_listen, &cli_config, &env_config).await;
    let response = reqwest::Client::new()
        .get(format!("http://{cli_listen}/missing"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let env_port_still_closed = reqwest::Client::new()
        .get(format!("http://{listen_addr}/missing"))
        .send()
        .await;
    assert!(env_port_still_closed.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_fails_when_no_cli_config_or_vaultick_config_exist() {
    let env = TestEnv::new();
    let output = Command::new(binary())
        .env("HOME", &env.home)
        .env_remove("VAULTICK_CONFIG")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Pass --config <path> or define VAULTICK_CONFIG")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_returns_404_when_no_route_matches() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://127.0.0.1:1\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
    ));

    let _guard = spawn_proxy_process(&config_path, &listen_addr).await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/missing"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.text().await.unwrap(), "route not found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_rejects_request_body_over_configured_limit() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nmax_request_body_bytes: 4\nroutes:\n  - match:\n      path_prefix: /limited\n    forward:\n      base_url: http://127.0.0.1:1\n      path: /echo\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
    ));

    let _guard = spawn_proxy_process(&config_path, &listen_addr).await;
    let response = reqwest::Client::new()
        .post(format!("http://{listen_addr}/limited"))
        .body("12345")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("request body too large")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_returns_502_when_upstream_is_unreachable() {
    let env = TestEnv::new();
    let listen_addr = free_addr();
    let upstream_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://{upstream}\n      path: /echo\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    ));

    let _guard = spawn_proxy_process(&config_path, &listen_addr).await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/github"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("upstream request failed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_returns_504_when_upstream_times_out() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(timeout_router()).await;
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /slow\n    forward:\n      base_url: http://{upstream}\n      path: /sleep\n      timeout_ms: 20\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    ));

    let _guard = spawn_proxy_process(&config_path, &listen_addr).await;
    let response = reqwest::Client::new()
        .get(format!("http://{listen_addr}/slow"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(response.text().await.unwrap().contains("timed out"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_returns_500_when_request_body_template_needs_utf8() {
    let env = TestEnv::new();
    let upstream_addr = spawn_upstream(upstream_router()).await;
    let listen_addr = free_addr();
    let config_path = env.write_config(&format!(
        "listen: {listen}\ndb: {db}\nworkspace: default\nprivate_key: {key}\nroutes:\n  - match:\n      path_prefix: /github\n    forward:\n      base_url: http://{upstream}\n      path: /echo\n      body: \"{{{{request.body}}}}\"\n",
        listen = listen_addr,
        db = env.db_path.display(),
        key = env.private_key_path.display(),
        upstream = upstream_addr,
    ));

    let _guard = spawn_proxy_process(&config_path, &listen_addr).await;
    let response = reqwest::Client::new()
        .post(format!("http://{listen_addr}/github"))
        .body(vec![0xff, 0xfe, 0xfd])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(response.text().await.unwrap().contains("not valid UTF-8"));
}

async fn spawn_upstream(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr.to_string()
}

async fn spawn_proxy_process(config_path: &Path, listen_addr: &str) -> ChildGuard {
    let child = Command::new(binary())
        .args(["--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_proxy(listen_addr, child).await
}

async fn spawn_proxy_from_env(
    env: &TestEnv,
    listen_addr: &str,
    config_value: &str,
    config_headers: Option<&str>,
) -> ChildGuard {
    let mut command = Command::new(binary());
    command
        .env("HOME", &env.home)
        .env("VAULTICK_CONFIG", config_value)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(headers) = config_headers {
        command.env("VAULTICK_CONFIG_HEADERS", headers);
    }
    let child = command.spawn().unwrap();
    wait_for_proxy(listen_addr, child).await
}

async fn spawn_proxy_with_cli_and_env(
    env: &TestEnv,
    listen_addr: &str,
    config_path: &Path,
    env_config: &str,
) -> ChildGuard {
    let child = Command::new(binary())
        .args(["--config", config_path.to_str().unwrap()])
        .env("HOME", &env.home)
        .env("VAULTICK_CONFIG", env_config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_proxy(listen_addr, child).await
}

fn upstream_router() -> Router {
    Router::new().route(
        "/echo/{*tail}",
        any(|request: Request<Body>| async move {
            let auth = request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let user = request
                .headers()
                .get("x-forwarded-user")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let query = request.uri().query().unwrap_or_default().to_string();
            let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                .await
                .unwrap();
            let payload = String::from_utf8(body.to_vec()).unwrap();

            Json(serde_json::json!({
                "auth": auth,
                "user": user,
                "query": query,
                "body": payload,
            }))
            .into_response()
        }),
    )
}

fn sse_router() -> Router {
    Router::new().route(
        "/sse",
        get(|| async move {
            let stream = async_stream::stream! {
                yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"data: super-"));
                tokio::time::sleep(Duration::from_millis(50)).await;
                yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"secret-token\n\n"));
            };

            (
                [(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/event-stream"),
                )],
                Body::from_stream(stream),
            )
        }),
    )
}

fn timeout_router() -> Router {
    Router::new().route(
        "/sleep",
        get(|| async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            (StatusCode::OK, "slow")
        }),
    )
}

async fn wait_for_proxy(listen_addr: &str, mut child: Child) -> ChildGuard {
    let client = reqwest::Client::new();
    let url = format!("http://{listen_addr}/__health");

    for _ in 0..50 {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "proxy exited early with status {status}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        match client.get(&url).send().await {
            Ok(_) => return ChildGuard { child },
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }

    let output = child.wait_with_output().unwrap();
    panic!(
        "proxy did not start listening on {listen_addr}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wait_for_http_url(url: &str) {
    let client = reqwest::Client::new();

    for _ in 0..50 {
        match client.get(url).send().await {
            Ok(_) => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }

    panic!("HTTP endpoint did not start listening on {url}");
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr.to_string()
}

fn ssh_public_key_to_pem(input: &str) -> String {
    let public_key = SshPublicKey::from_openssh(input).unwrap();
    let rsa_key = public_key.key_data().rsa().unwrap();
    let rsa_public = RsaPublicKey::new(
        BigUint::try_from(&rsa_key.n).unwrap(),
        BigUint::try_from(&rsa_key.e).unwrap(),
    )
    .unwrap();

    rsa_public.to_public_key_pem(LineEnding::LF).unwrap()
}
