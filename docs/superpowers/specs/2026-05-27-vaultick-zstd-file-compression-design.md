# Vaultick Zstd File Compression Design

## Context

Vaultick stores secret values as encrypted bytes in SQLite. Today `secret set
--file <path>` reads the file bytes and passes them to `Vaultick::set_secret_bytes`,
which encrypts those bytes directly with AES-256-GCM.

For large file secrets, storing the original bytes directly can waste disk space.
Compression must happen before encryption because encrypted bytes are not
compressible.

## Goal

Add native zstd compression for file-backed secrets:

```sh
vaultick secret set BACKUP --file ./backup.tar
vaultick secret set BACKUP --file ./backup.tar --compress
vaultick secret set BACKUP --file ./backup.tar --compress-level 22
vaultick secret set BACKUP --file ./backup.tar --no-compress

vaultick secret get BACKUP --output ./backup.tar
vaultick secret get BACKUP --output ./stored-payload.zst --no-uncompress
```

The default should favor storage savings without forcing compression when it
does not help.

## Non-Goals

- Do not compress inline text secrets by default.
- Do not compress `--env-file` entries by default.
- Do not preserve compatibility with old binaries that do not understand the new
  schema.
- Do not infer compression state from ciphertext or plaintext bytes.
- Do not add remote-object storage or streaming archive formats in this change.

## User Interface

`secret set --file` gets three compression controls:

```text
default:
  try zstd at level 10, unless VAULTICK_COMPRESSION_LEVEL is set
  store compressed payload only if it is smaller than the original bytes

--compress:
  force zstd at level 10, unless VAULTICK_COMPRESSION_LEVEL is set
  even if compressed bytes are larger

--compress-level N:
  use zstd level N
  store compressed payload only if it is smaller than the original bytes

--compress --compress-level N:
  force zstd at level N

--no-compress:
  store original bytes
  conflicts with --compress and --compress-level
```

Compression level precedence:

```text
1. --compress-level N
2. VAULTICK_COMPRESSION_LEVEL
3. default level 10
```

`--no-compress` disables compression regardless of `VAULTICK_COMPRESSION_LEVEL`.

Compression levels should accept the regular zstd range:

```text
1..=22
```

Invalid levels should fail before reading the file:

```text
invalid compression level: expected 1..=22
```

`secret get` gets file-output controls:

```text
--output PATH:
  write the secret bytes to PATH instead of rendering metadata/table output

--no-uncompress:
  when used with --output, write the stored decrypted payload without zstd
  decompression
```

By default, `get_secret_bytes` and `secret get --output` return the original file
bytes. If the row is marked as zstd-compressed, Vaultick decrypts and
decompresses automatically.

## Persistence

The `secrets` table should store compression metadata explicitly:

```sql
compression TEXT NOT NULL CHECK (compression IN ('none', 'zstd'))
original_size INTEGER
```

Rules:

- `compression = 'none'`: `ciphertext` contains encrypted original bytes.
- `compression = 'zstd'`: `ciphertext` contains encrypted zstd bytes.
- `original_size` is required when `compression = 'zstd'`.
- `original_size` is `NULL` when `compression = 'none'`.

This can break old binaries and old databases. The implementation should update
the current initial schema and add a migration file for existing development
databases. It does not need to make old binaries work against new databases.

## Library And CLI Behavior

Add a small compression module shared by the CLI and storage path with clear
responsibilities:

- decide whether to compress file bytes;
- call `zstd` with the selected level;
- validate levels;
- decompress zstd payloads when reading.

The storage layer should encrypt only the final stored payload and persist the
compression metadata it is given:

```text
file bytes
  -> compression decision
  -> stored payload
  -> AES-256-GCM encryption
  -> SQLite ciphertext
```

Reading reverses that:

```text
SQLite ciphertext
  -> AES-256-GCM decrypt
  -> compression metadata check
  -> optional zstd decompression
  -> original bytes
```

The public library API should expose both modes:

- normal read: decrypted and decompressed bytes;
- raw read: decrypted stored payload without decompression;
- write with explicit compression metadata for remote clients that already
  compressed the payload before sending it to the remote host.

## Security

Compression before encryption leaks compressed size, which can reveal limited
information about plaintext length and compressibility. This feature is scoped to
file-backed secrets, where the user controls the file being stored. It should not
be applied automatically to request templates or mixed attacker-controlled data.

The implementation must not log plaintext, compressed payloads, or decompressed
payloads.

## Remote SSH Mode

Remote SSH mode should compress and decompress on the initiating CLI client.

For remote `secret set --file`:

```text
local CLI reads file
  -> local CLI applies compression decision
  -> local CLI sends stored payload plus compression metadata over SSH
  -> remote process encrypts and writes that payload/metadata to SQLite
```

For remote `secret get --output`:

```text
remote process decrypts and returns stored payload plus compression metadata
  -> local CLI decompresses unless --no-uncompress is set
  -> local CLI writes the output file
```

This keeps the external CLI behavior identical while reducing bytes sent over
SSH and keeping compression CPU on the client machine instead of the
`192.168.88.240` host.

## Errors

Expected errors:

- invalid compression level;
- invalid `VAULTICK_COMPRESSION_LEVEL`;
- `--compress` combined with `--no-compress`;
- `--compress-level` combined with `--no-compress`;
- `--no-uncompress` without `--output`;
- zstd decompression failure for rows marked `compression = 'zstd'`;
- missing `original_size` for zstd-compressed rows.

## Testing

Unit tests should cover:

- default file compression stores zstd only when smaller;
- `--compress` forces zstd;
- `--no-compress` stores `none`;
- `--compress-level` validates `1..=22`;
- `VAULTICK_COMPRESSION_LEVEL` is used when `--compress-level` is absent;
- `get_secret_bytes` returns original bytes for zstd rows;
- raw get returns compressed stored payload for zstd rows;
- invalid compression metadata returns clear errors.

CLI E2E tests should cover:

- `secret set --file` followed by `secret get --output` round-trips the original
  file;
- `--no-compress` stores and restores the original file;
- `--compress --compress-level 22` forces zstd;
- `secret get --output stored.zst --no-uncompress` writes the compressed payload;
- remote `secret set --file` sends the compressed payload over SSH when zstd wins;
- remote `secret get --output` decompresses on the local CLI client.

## Implementation Notes

Use the Rust `zstd` crate:

```toml
zstd = "0.13"
```

Prefer the simple bulk API for this first implementation because current
`secret set --file` already reads the whole file into memory.
