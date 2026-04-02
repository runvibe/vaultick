use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

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
    env!("CARGO_BIN_EXE_vaultick")
}

struct TestEnv {
    _dir: TempDir,
    home: PathBuf,
    vaultick_home: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let ssh_dir = home.join(".ssh");
        let vaultick_home = dir.path().join("vaultick-home");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::create_dir_all(&vaultick_home).unwrap();
        fs::write(ssh_dir.join("id_rsa"), SSH_RSA_PRIVATE).unwrap();
        fs::write(ssh_dir.join("id_rsa.pub"), SSH_RSA_PUBLIC).unwrap();

        Self {
            _dir: dir,
            home,
            vaultick_home,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary());
        command.env("HOME", &self.home);
        command.env("VAULTICK_HOME", &self.vaultick_home);
        command
    }

    fn setup_default_rsa(&self) {
        let output = self
            .command()
            .args([
                "rsa",
                "add",
                "--label",
                "id_rsa",
                "--cert",
                self.home.join(".ssh").join("id_rsa.pub").to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_success(&output);
    }
}

#[test]
fn secret_set_and_get_metadata_are_case_insensitive_and_store_uppercase() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    let set_output = env
        .command()
        .args(["secret", "set", "google_token", "super-secret-token"])
        .output()
        .unwrap();
    assert_success(&set_output);
    assert_eq!(String::from_utf8_lossy(&set_output.stdout), "");

    let get_output = env
        .command()
        .args(["secret", "get", "GoOgLe_ToKeN"])
        .output()
        .unwrap();
    assert_success(&get_output);
    let stdout = String::from_utf8_lossy(&get_output.stdout);
    assert!(stdout.contains("KEY"));
    assert!(stdout.contains("SECRET ID"));
    assert!(stdout.contains("GOOGLE_TOKEN"));
    assert!(!stdout.contains("secret\t"));
}

#[test]
fn secret_get_and_list_support_json_output() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    assert_success(
        &env.command()
            .args(["secret", "set", "google_token", "super-secret-token"])
            .output()
            .unwrap(),
    );

    let get_output = env
        .command()
        .args(["secret", "get", "google_token", "--json"])
        .output()
        .unwrap();
    assert_success(&get_output);
    let get_json: serde_json::Value = serde_json::from_slice(&get_output.stdout).unwrap();
    assert_eq!(get_json["key"], "GOOGLE_TOKEN");
    assert!(get_json["id"].is_string());
    assert!(get_json["workspace_id"].is_string());

    let list_output = env
        .command()
        .args(["secret", "list", "--json"])
        .output()
        .unwrap();
    assert_success(&list_output);
    let list_json: serde_json::Value = serde_json::from_slice(&list_output.stdout).unwrap();
    assert!(list_json.is_object());
    assert_eq!(list_json["limit"], 10);
    assert_eq!(list_json["offset"], 0);
    assert_eq!(list_json["count"], 1);
    assert!(list_json["items"].is_array());
    assert_eq!(list_json["items"].as_array().unwrap().len(), 1);
    assert_eq!(list_json["items"][0]["key"], "GOOGLE_TOKEN");
}

#[test]
fn secret_list_renders_table_and_paginates_by_default() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    for index in 0..12 {
        assert_success(
            &env.command()
                .args([
                    "secret",
                    "set",
                    &format!("secret_{index:02}"),
                    &format!("value-{index}"),
                ])
                .output()
                .unwrap(),
        );
    }

    let list_output = env.command().args(["secret", "list"]).output().unwrap();
    assert_success(&list_output);
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("limit: 10  offset: 0  count: 10"));
    assert!(stdout.contains("KEY"));
    assert!(stdout.contains("SECRET ID"));
    assert!(stdout.contains("SECRET_00"));
    assert!(stdout.contains("SECRET_09"));
    assert!(!stdout.contains("SECRET_10"));
    assert!(!stdout.contains("secret\t"));
}

#[test]
fn secret_list_offset_returns_next_page() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    for index in 0..12 {
        assert_success(
            &env.command()
                .args([
                    "secret",
                    "set",
                    &format!("secret_{index:02}"),
                    &format!("value-{index}"),
                ])
                .output()
                .unwrap(),
        );
    }

    let offset_output = env
        .command()
        .args(["secret", "list", "--offset", "10"])
        .output()
        .unwrap();
    assert_success(&offset_output);
    let stdout = String::from_utf8_lossy(&offset_output.stdout);
    assert!(stdout.contains("limit: 10  offset: 10  count: 2"));
    assert!(stdout.contains("SECRET_10"));
    assert!(stdout.contains("SECRET_11"));
    assert!(!stdout.contains("SECRET_09"));
}

#[test]
fn secret_list_json_supports_limit_and_offset() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    for index in 0..12 {
        assert_success(
            &env.command()
                .args([
                    "secret",
                    "set",
                    &format!("secret_{index:02}"),
                    &format!("value-{index}"),
                ])
                .output()
                .unwrap(),
        );
    }

    let list_output = env
        .command()
        .args(["secret", "list", "--limit", "5", "--offset", "5", "--json"])
        .output()
        .unwrap();
    assert_success(&list_output);
    let list_json: serde_json::Value = serde_json::from_slice(&list_output.stdout).unwrap();
    assert_eq!(list_json["limit"], 5);
    assert_eq!(list_json["offset"], 5);
    assert_eq!(list_json["count"], 5);
    assert_eq!(list_json["items"].as_array().unwrap().len(), 5);
    assert_eq!(list_json["items"][0]["key"], "SECRET_05");
    assert_eq!(list_json["items"][4]["key"], "SECRET_09");
}

#[test]
fn secret_set_requires_overwrite_flag_for_existing_key() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    assert_success(
        &env.command()
            .args(["secret", "set", "google_token", "first"])
            .output()
            .unwrap(),
    );

    let conflict = env
        .command()
        .args(["secret", "set", "GOOGLE_TOKEN", "second"])
        .output()
        .unwrap();
    assert_failure(&conflict);
    assert!(
        String::from_utf8_lossy(&conflict.stderr).contains("--overwrite"),
        "stderr was: {}",
        String::from_utf8_lossy(&conflict.stderr)
    );

    let overwrite = env
        .command()
        .args(["secret", "set", "google_token", "second", "--overwrite"])
        .output()
        .unwrap();
    assert_success(&overwrite);
}

#[test]
fn secret_set_env_file_imports_keys_as_uppercase() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    let env_file = env.home.join("secrets.env");
    fs::write(
        &env_file,
        "github_token=ghp_123\nexport aws_access_key_id=\"AKIA123\"\n",
    )
    .unwrap();

    let import = env
        .command()
        .args(["secret", "set", "--env-file", env_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success(&import);
    let stdout = String::from_utf8_lossy(&import.stdout);
    assert!(stdout.contains("\tGITHUB_TOKEN\t"));
    assert!(stdout.contains("\tAWS_ACCESS_KEY_ID\t"));
}

#[test]
fn secret_set_env_file_skip_existing_preserves_existing_keys() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    assert_success(
        &env.command()
            .args(["secret", "set", "github_token", "original-token"])
            .output()
            .unwrap(),
    );

    let env_file = env.home.join("skip.env");
    fs::write(
        &env_file,
        "github_token=new-token\naws_access_key_id=AKIA123\n",
    )
    .unwrap();

    let import = env
        .command()
        .args([
            "secret",
            "set",
            "--env-file",
            env_file.to_str().unwrap(),
            "--skip-existing",
        ])
        .output()
        .unwrap();
    assert_success(&import);

    let stdout = String::from_utf8_lossy(&import.stdout);
    assert!(stdout.contains("skipped existing secret GITHUB_TOKEN"));
    assert!(stdout.contains("\tAWS_ACCESS_KEY_ID\t"));

    let conflict = env
        .command()
        .args(["secret", "set", "GITHUB_TOKEN", "new-token"])
        .output()
        .unwrap();
    assert_failure(&conflict);
    assert!(
        String::from_utf8_lossy(&conflict.stderr).contains("--overwrite"),
        "stderr was: {}",
        String::from_utf8_lossy(&conflict.stderr)
    );
}

#[test]
fn secret_set_file_accepts_binary_content() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    let binary_path = env.home.join("payload.bin");
    fs::write(&binary_path, [0x00, 0xff, 0x41, 0x42]).unwrap();

    let set_output = env
        .command()
        .args([
            "secret",
            "set",
            "binary_blob",
            "--file",
            binary_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&set_output);
    assert_eq!(String::from_utf8_lossy(&set_output.stdout), "");

    let get_output = env
        .command()
        .args(["secret", "get", "BINARY_BLOB"])
        .output()
        .unwrap();
    assert_success(&get_output);
    let stdout = String::from_utf8_lossy(&get_output.stdout);
    assert!(stdout.contains("KEY"));
    assert!(stdout.contains("BINARY_BLOB"));
}

#[test]
fn request_redacts_response_body_and_fails_on_non_success_status() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    assert_success(
        &env.command()
            .args(["secret", "set", "GITHUB_TOKEN", "super-secret-token"])
            .output()
            .unwrap(),
    );

    let server = TestHttpServer::spawn_once(|mut stream, request| {
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer super-secret-token")
        );

        write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ntoken=super-secret-token",
            "token=super-secret-token".len()
        )
        .unwrap();
    });

    let output = env
        .command()
        .args([
            "request",
            "--url",
            &server.url("/"),
            "--method",
            "POST",
            "--header",
            "Authorization: Bearer $GITHUB_TOKEN",
        ])
        .output()
        .unwrap();

    assert_failure(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "token=[REDACTED]");
}

#[test]
fn request_supports_json_data_and_sse_redaction() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    assert_success(
        &env.command()
            .args(["secret", "set", "GITHUB_TOKEN", "super-secret-token"])
            .output()
            .unwrap(),
    );

    let server = TestHttpServer::spawn_once(|mut stream, request| {
        assert!(request.starts_with("GET /stream?token=super-secret-token HTTP/1.1"));

        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        stream.write_all(b"data: super-").unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(10));
        stream.write_all(b"secret-token\n\n").unwrap();
        stream.flush().unwrap();
    });

    let output = env
        .command()
        .args([
            "request",
            "--data",
            &format!(
                "{{\"url\":\"{}\",\"headers\":{{\"Authorization\":\"Bearer $GITHUB_TOKEN\"}},\"body\":\"{{\\\"token\\\":\\\"$GITHUB_TOKEN\\\"}}\"}}",
                server.url("/stream?token=$GITHUB_TOKEN")
            ),
        ])
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "data: [REDACTED]\n\n"
    );
}

#[cfg(unix)]
#[test]
fn exec_redacts_secret_output_from_child_process() {
    let env = TestEnv::new();
    env.setup_default_rsa();

    assert_success(
        &env.command()
            .args(["secret", "set", "github_token", "super-secret-token"])
            .output()
            .unwrap(),
    );

    let output = env
        .command()
        .args([
            "exec",
            "--env",
            "github_token",
            "--",
            "sh",
            "-c",
            "printf '%s\\n' \"$GITHUB_TOKEN\"",
        ])
        .output()
        .unwrap();
    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "[REDACTED]\n");
    assert!(!stdout.contains("super-secret-token"));
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "expected failure, got success\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct TestHttpServer {
    listener: TcpListener,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl TestHttpServer {
    fn spawn_once(handler: impl FnOnce(TcpStream, String) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cloned = listener.try_clone().unwrap();
        let join_handle = thread::spawn(move || {
            let (mut stream, _) = cloned.accept().unwrap();
            let request = read_http_request(&mut stream);
            handler(stream, request);
        });

        Self {
            listener,
            join_handle: Some(join_handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!(
            "http://{}/{}",
            self.listener.local_addr().unwrap(),
            path.trim_start_matches('/')
        )
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        if let Some(join_handle) = self.join_handle.take() {
            let _ = join_handle.join();
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buffer = [0_u8; 4096];
    let mut request = Vec::new();

    loop {
        let bytes_read = stream.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }

        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|chunk| chunk == b"\r\n\r\n") {
            break;
        }
    }

    String::from_utf8_lossy(&request).into_owned()
}
