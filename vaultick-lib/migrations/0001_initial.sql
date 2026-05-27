PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS rsa_certificates (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    label TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    UNIQUE(workspace_id, fingerprint_sha256)
);

CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    key TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    compression TEXT NOT NULL DEFAULT 'none' CHECK (compression IN ('none', 'zstd')),
    original_size INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (
        (compression = 'none' AND original_size IS NULL)
        OR
        (compression = 'zstd' AND original_size IS NOT NULL)
    ),
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    UNIQUE(workspace_id, key)
);

CREATE TABLE IF NOT EXISTS secret_recipients (
    secret_id TEXT NOT NULL,
    rsa_certificate_id TEXT NOT NULL,
    wrapped_key BLOB NOT NULL,
    PRIMARY KEY (secret_id, rsa_certificate_id),
    FOREIGN KEY(secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    FOREIGN KEY(rsa_certificate_id) REFERENCES rsa_certificates(id) ON DELETE CASCADE
);

PRAGMA user_version = 2;
