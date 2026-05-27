# Vaultick Remote SSH And Zstd File Compression Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the remote SSH CLI mode together with zstd compression for file-backed secrets.

**Architecture:** Remote mode dispatches CLI commands over SSH stdio and keeps SQLite local to the remote host. File compression is decided by the initiating CLI client for `secret set --file`, then the remote host stores the already-prepared payload and compression metadata. Reads return normal decompressed bytes by default, with raw payload export available through `--no-uncompress`.

**Tech Stack:** Rust 2024, clap, serde/serde_json, rusqlite, AES-GCM, RSA-OAEP, zstd `0.13`, Cargo workspace tests.

---

## File Structure

- Existing remote files from the merged remote plan:
  - `vaultick-bin/src/commands/remote.rs`: SSH stdio request/response and local payload capture.
  - `vaultick-bin/src/commands/mod.rs`: CLI parsing and local command execution.
- Compression implementation files:
  - Create `vaultick-lib/src/compression.rs`: compression metadata types, zstd level validation, compress/decompress helpers.
  - Modify `vaultick-lib/src/lib.rs`: add compression metadata persistence, write/read APIs, schema usage.
  - Modify `vaultick-lib/migrations/0001_initial.sql`: add compression columns to `secrets`.
  - Add `vaultick-lib/migrations/0002_secret_compression.sql`: development migration for existing databases.
  - Modify `vaultick-lib/Cargo.toml`: add `zstd`.
  - Modify `vaultick-bin/src/commands/mod.rs`: add CLI flags and output handling.
  - Modify `vaultick-bin/src/commands/remote.rs`: send prepared compressed payload/metadata for remote file set and return raw payload/metadata for remote output get.
  - Modify `vaultick-bin/tests/e2e.rs`: local and fake-SSH remote round trips.

## Task 1: Compression Metadata In Storage

**Files:**
- Create: `vaultick-lib/src/compression.rs`
- Modify: `vaultick-lib/src/lib.rs`
- Modify: `vaultick-lib/Cargo.toml`
- Modify: `vaultick-lib/migrations/0001_initial.sql`
- Create: `vaultick-lib/migrations/0002_secret_compression.sql`

- [ ] **Step 1: Write failing storage tests**

Add tests in `vaultick-lib/src/lib.rs`:

```rust
#[test]
fn compressed_secret_bytes_roundtrip_to_original_bytes() {
    let store = test_store_with_certificate();
    let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(32);
    let prepared = compression::prepare_secret_payload(
        &payload,
        compression::CompressionMode::Try { level: 10 },
    )
    .unwrap();
    assert_eq!(prepared.compression, compression::Compression::Zstd);

    store
        .set_secret_prepared_bytes(
            "team-a",
            "archive",
            &prepared.payload,
            prepared.compression,
            prepared.original_size,
            false,
        )
        .unwrap();

    let decrypted = store.get_secret_bytes("team-a", "archive", KEY_1).unwrap();
    assert_eq!(decrypted, payload);
}
```

Add a second test proving raw reads return the stored zstd payload:

```rust
#[test]
fn raw_secret_bytes_return_stored_payload_without_decompression() {
    let store = test_store_with_certificate();
    let payload = b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".repeat(64);
    let prepared = compression::prepare_secret_payload(
        &payload,
        compression::CompressionMode::Force { level: 10 },
    )
    .unwrap();

    store
        .set_secret_prepared_bytes(
            "team-a",
            "archive",
            &prepared.payload,
            prepared.compression,
            prepared.original_size,
            false,
        )
        .unwrap();

    let raw = store.get_secret_raw_bytes("team-a", "archive", KEY_1).unwrap();
    assert_eq!(raw.payload, prepared.payload);
    assert_eq!(raw.compression, compression::Compression::Zstd);
}
```

- [ ] **Step 2: Run red tests**

Run: `cargo test -p vaultick compressed_secret_bytes_roundtrip_to_original_bytes raw_secret_bytes_return_stored_payload_without_decompression`

Expected: fail because compression module and prepared/raw APIs do not exist.

- [ ] **Step 3: Implement storage support**

Implement:

- `Compression::{None, Zstd}`
- `CompressionMode::{None, Try { level }, Force { level }}`
- `PreparedSecretPayload { payload, compression, original_size }`
- `RawSecretBytes { payload, compression, original_size }`
- zstd level validation for `1..=22`
- `prepare_secret_payload`
- `decompress_secret_payload`
- `set_secret_prepared_bytes`
- `get_secret_raw_bytes`
- schema columns `compression` and `original_size`

- [ ] **Step 4: Run green tests**

Run: `cargo test -p vaultick compressed_secret_bytes_roundtrip_to_original_bytes raw_secret_bytes_return_stored_payload_without_decompression`

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add vaultick-lib/src/lib.rs vaultick-lib/src/compression.rs vaultick-lib/Cargo.toml vaultick-lib/migrations/0001_initial.sql vaultick-lib/migrations/0002_secret_compression.sql Cargo.lock
git commit -m "feat(lib): store zstd compression metadata"
```

## Task 2: Local CLI Compression Flags And Output

**Files:**
- Modify: `vaultick-bin/src/commands/mod.rs`
- Modify: `vaultick-bin/tests/e2e.rs`

- [ ] **Step 1: Write failing CLI tests**

Add unit tests for parsing:

```rust
#[test]
fn secret_set_file_parses_compression_flags() {
    let cli = Cli::try_parse_from([
        "vaultick",
        "secret",
        "set",
        "ARCHIVE",
        "--file",
        "archive.tar",
        "--compress",
        "--compress-level",
        "22",
    ])
    .unwrap();
    let Command::Secret(command) = cli.command else { panic!("expected secret command") };
    let SecretSubcommand::Set { compress, compress_level, no_compress, .. } = command.command else {
        panic!("expected secret set")
    };
    assert!(compress);
    assert_eq!(compress_level, Some(22));
    assert!(!no_compress);
}
```

Add E2E tests:

```rust
#[test]
fn secret_set_file_compresses_and_get_output_restores_original_file() {
    // create repetitive file, set with --file, get with --output, compare bytes.
}
```

- [ ] **Step 2: Run red tests**

Run: `cargo test -p vaultick-bin compression secret_set_file_compresses_and_get_output_restores_original_file`

Expected: fail because flags and `--output` do not exist.

- [ ] **Step 3: Implement CLI support**

Implement:

- `--compress`, `--no-compress`, `--compress-level N` on `secret set`
- `VAULTICK_COMPRESSION_LEVEL`
- `--output PATH` and `--no-uncompress` on `secret get`
- default level 10
- level validation `1..=22`
- local set file compression before calling the storage write API
- local output file write with default decompression and raw mode

- [ ] **Step 4: Run green tests**

Run: `cargo test -p vaultick-bin compression secret_set_file_compresses_and_get_output_restores_original_file`

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add vaultick-bin/src/commands/mod.rs vaultick-bin/tests/e2e.rs
git commit -m "feat(cli): compress file secrets with zstd"
```

## Task 3: Remote Compression On Client

**Files:**
- Modify: `vaultick-bin/src/commands/remote.rs`
- Modify: `vaultick-bin/src/commands/mod.rs`
- Modify: `vaultick-bin/tests/e2e.rs`

- [ ] **Step 1: Write failing remote tests**

Add fake-SSH E2E tests:

```rust
#[test]
fn remote_secret_set_file_sends_compressed_payload_from_client() {
    // set a repetitive local file through -r and assert get --output restores original bytes.
}

#[test]
fn remote_secret_get_output_decompresses_on_client() {
    // set compressed file remotely, get --output remotely, compare bytes.
}
```

- [ ] **Step 2: Run red tests**

Run: `cargo test -p vaultick-bin remote_secret_set_file_sends_compressed_payload_from_client remote_secret_get_output_decompresses_on_client`

Expected: fail because remote protocol does not carry compression metadata or output payloads.

- [ ] **Step 3: Implement remote protocol support**

Implement:

- remote request payload for already-compressed `secret set --file`;
- remote request metadata fields `compression` and `original_size`;
- remote raw get response for `secret get --output`;
- local client decompression/output writing after remote response;
- `--no-uncompress` applied on the initiating client.

- [ ] **Step 4: Run green tests**

Run: `cargo test -p vaultick-bin remote_secret_set_file_sends_compressed_payload_from_client remote_secret_get_output_decompresses_on_client`

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add vaultick-bin/src/commands/remote.rs vaultick-bin/src/commands/mod.rs vaultick-bin/tests/e2e.rs
git commit -m "feat(cli): handle remote file compression on client"
```

## Task 4: Final Verification And Publication

**Files:**
- Add: `docs/superpowers/plans/2026-05-27-vaultick-remote-zstd-implementation.md`

- [ ] **Step 1: Commit unified plan**

Run:

```sh
git add docs/superpowers/plans/2026-05-27-vaultick-remote-zstd-implementation.md
git commit -m "docs: unify remote and zstd implementation plan"
```

- [ ] **Step 2: Run workspace verification**

Run:

```sh
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
```

Expected: all pass.

- [ ] **Step 3: Push branch and open combined PR**

Run:

```sh
git push -u origin codex/vaultick-remote-zstd-implementation
gh pr create --draft --base main --head codex/vaultick-remote-zstd-implementation
```

Expected: a draft PR that supersedes the previous remote-only and zstd-design draft PRs.

## Self-Review

- Remote SSH spec is covered by the merged remote implementation and final verification.
- Zstd file compression spec is covered by storage metadata, CLI local behavior, and remote-client behavior.
- `exec` and `request` remain explicitly unsupported in remote mode from the remote implementation plan.
- No placeholders remain; intentionally omitted implementation details are scoped to the code tasks above.
