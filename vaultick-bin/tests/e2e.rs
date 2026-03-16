use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

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
    assert!(stdout.contains("\tGOOGLE_TOKEN\t"));
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
    assert!(String::from_utf8_lossy(&get_output.stdout).contains("\tBINARY_BLOB\t"));
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
