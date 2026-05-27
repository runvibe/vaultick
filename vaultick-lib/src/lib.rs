use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rsa::BigUint;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rusqlite::types::Type;
use rusqlite::{Connection, ErrorCode, OptionalExtension, Row, params};
use sha2::{Digest, Sha256};
use ssh_key::PrivateKey as SshPrivateKey;
use thiserror::Error;
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::nom::AsBytes;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

pub mod compression;

const INITIAL_SCHEMA: &str = include_str!("../migrations/0001_initial.sql");

const DEFAULT_WORKSPACE_NAME: &str = "default";
const DEFAULT_SSH_PRIVATE_KEY_NAME: &str = "id_rsa";

pub type Result<T> = std::result::Result<T, VaultickError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaCertificate {
    pub id: String,
    pub workspace_id: String,
    pub label: String,
    pub cert_pem: String,
    pub fingerprint_sha256: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    pub id: String,
    pub workspace_id: String,
    pub key: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Error)]
pub enum VaultickError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("{entity} not found: {reference}")]
    NotFound {
        entity: &'static str,
        reference: String,
    },
    #[error("workspace has no RSA certificates")]
    WorkspaceHasNoCertificates,
    #[error("private key does not match any RSA certificate allowed for this secret")]
    IncompatiblePrivateKey,
    #[error("certificate removal would orphan existing secrets")]
    CertificateInUse,
    #[error("{0}")]
    AutoPrivateKeyLookup(String),
    #[error("{0}")]
    Validation(String),
}

#[derive(Debug, Clone)]
struct SecretRecord {
    metadata: SecretMetadata,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    compression: compression::Compression,
    original_size: Option<u64>,
}

#[derive(Debug, Clone)]
struct SecretRecipient {
    wrapped_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PrivateKeyCandidate {
    label: String,
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct ParsedCertificate {
    public_key: RsaPublicKey,
    fingerprint_sha256: String,
}

pub struct Vaultick {
    conn: RefCell<Connection>,
}

impl Vaultick {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let is_new_database = !path.exists() || path == Path::new(":memory:");
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let vaultick = Self {
            conn: RefCell::new(conn),
        };
        vaultick.init_schema(is_new_database)?;
        Ok(vaultick)
    }

    pub fn create_workspace(&self, name: &str) -> Result<Workspace> {
        let conn = self.conn.borrow();
        let id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO workspaces (id, name) VALUES (?1, ?2)",
            params![id, name],
        )
        .map_err(|err| map_constraint(err, format!("workspace already exists: {name}")))?;

        Self::resolve_workspace(&conn, &id)
    }

    pub fn list_workspaces(&self) -> Result<Vec<Workspace>> {
        let conn = self.conn.borrow();
        let mut stmt =
            conn.prepare("SELECT id, name, created_at FROM workspaces ORDER BY name ASC")?;
        let rows = stmt.query_map([], workspace_from_row)?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(VaultickError::from)
    }

    pub fn get_workspace(&self, workspace_ref: &str) -> Result<Workspace> {
        let conn = self.conn.borrow();
        Self::resolve_workspace(&conn, workspace_ref)
    }

    pub fn delete_workspace(&self, workspace_ref: &str) -> Result<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction()?;
        let workspace = Self::resolve_workspace(&tx, workspace_ref)?;
        tx.execute(
            "DELETE FROM workspaces WHERE id = ?1",
            params![workspace.id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn add_certificate(
        &self,
        workspace_ref: &str,
        label: &str,
        cert_pem: &str,
        rewrap_private_key_pem: Option<&str>,
    ) -> Result<RsaCertificate> {
        let parsed = parse_public_material(cert_pem)?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction()?;
        let workspace = Self::resolve_workspace(&tx, workspace_ref)?;
        let existing_certs = Self::list_certificates_for_workspace(&tx, &workspace.id)?;
        let secret_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM secrets WHERE workspace_id = ?1",
            params![workspace.id],
            |row| row.get(0),
        )?;

        if secret_count > 0 && !existing_certs.is_empty() && rewrap_private_key_pem.is_none() {
            return Err(VaultickError::Validation(
                "rewrap private key is required when adding a certificate to a workspace with existing secrets"
                    .to_string(),
            ));
        }

        let certificate_id = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO rsa_certificates (id, workspace_id, label, cert_pem, fingerprint_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                certificate_id,
                workspace.id,
                label,
                cert_pem,
                parsed.fingerprint_sha256
            ],
        )
        .map_err(|err| {
            map_constraint(
                err,
                format!(
                    "certificate already exists in workspace: {}",
                    workspace.name
                ),
            )
        })?;

        if secret_count > 0 && !existing_certs.is_empty() {
            let private_key_pem = rewrap_private_key_pem.expect("checked above");
            let private_key = parse_private_key(private_key_pem)?;
            let secrets = Self::list_secret_records_for_workspace(&tx, &workspace.id)?;

            for secret in secrets {
                let recipients = Self::list_secret_recipients(&tx, &secret.metadata.id)?;
                let dek = unwrap_secret_key(&private_key, &recipients)?;
                let wrapped_key = wrap_secret_key(&parsed.public_key, &dek)?;
                tx.execute(
                    "INSERT INTO secret_recipients (secret_id, rsa_certificate_id, wrapped_key)
                     VALUES (?1, ?2, ?3)",
                    params![secret.metadata.id, certificate_id, wrapped_key],
                )?;
            }
        }

        let certificate = Self::resolve_certificate(&tx, &workspace.id, &certificate_id)?;
        tx.commit()?;
        Ok(certificate)
    }

    pub fn list_certificates(&self, workspace_ref: &str) -> Result<Vec<RsaCertificate>> {
        let conn = self.conn.borrow();
        let workspace = Self::resolve_workspace(&conn, workspace_ref)?;
        Self::list_certificates_for_workspace(&conn, &workspace.id)
    }

    pub fn delete_certificate(&self, workspace_ref: &str, cert_ref: &str) -> Result<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction()?;
        let workspace = Self::resolve_workspace(&tx, workspace_ref)?;
        let certificate = Self::resolve_certificate(&tx, &workspace.id, cert_ref)?;
        let would_orphan = tx.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM secret_recipients sr
                WHERE sr.rsa_certificate_id = ?1
                  AND NOT EXISTS (
                      SELECT 1
                      FROM secret_recipients other
                      WHERE other.secret_id = sr.secret_id
                        AND other.rsa_certificate_id <> ?1
                  )
             )",
            params![certificate.id],
            |row| row.get::<_, bool>(0),
        )?;

        if would_orphan {
            return Err(VaultickError::CertificateInUse);
        }

        tx.execute(
            "DELETE FROM rsa_certificates WHERE id = ?1 AND workspace_id = ?2",
            params![certificate.id, workspace.id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_secret(
        &self,
        workspace_ref: &str,
        key: &str,
        value: &str,
        overwrite: bool,
    ) -> Result<SecretMetadata> {
        self.set_secret_bytes(workspace_ref, key, value.as_bytes(), overwrite)
    }

    pub fn set_secret_bytes(
        &self,
        workspace_ref: &str,
        key: &str,
        value: &[u8],
        overwrite: bool,
    ) -> Result<SecretMetadata> {
        self.set_secret_prepared_bytes(
            workspace_ref,
            key,
            value,
            compression::Compression::None,
            None,
            overwrite,
        )
    }

    pub fn set_secret_prepared_bytes(
        &self,
        workspace_ref: &str,
        key: &str,
        value: &[u8],
        compression: compression::Compression,
        original_size: Option<u64>,
        overwrite: bool,
    ) -> Result<SecretMetadata> {
        validate_compression_metadata(compression, original_size)?;
        let key = normalize_secret_key(key)?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction()?;
        let workspace = Self::resolve_workspace(&tx, workspace_ref)?;
        let certificates = Self::list_certificates_for_workspace(&tx, &workspace.id)?;

        if certificates.is_empty() {
            return Err(VaultickError::WorkspaceHasNoCertificates);
        }

        let public_keys = certificates
            .iter()
            .map(|certificate| {
                parse_public_material(&certificate.cert_pem).map(|parsed| parsed.public_key)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut rng = OsRng;
        let mut dek = [0_u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut dek);

        let mut nonce = [0_u8; 12];
        rng.fill_bytes(&mut nonce);

        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|err| VaultickError::Crypto(format!("invalid data encryption key: {err}")))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value,
                    aad: secret_key_aad(&key),
                },
            )
            .map_err(|err| VaultickError::Crypto(format!("failed to encrypt secret: {err}")))?;

        let wrapped_keys = public_keys
            .iter()
            .map(|public_key| wrap_secret_key(public_key, &dek))
            .collect::<Result<Vec<_>>>()?;

        let existing_secret = Self::find_secret_by_key(&tx, &workspace.id, &key)?;
        let secret_id = existing_secret
            .as_ref()
            .map(|secret| secret.metadata.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        if existing_secret.is_some() {
            if !overwrite {
                return Err(VaultickError::Validation(format!(
                    "secret already exists in workspace: {key}; use --overwrite to update it"
                )));
            }
            tx.execute(
                "UPDATE secrets
                 SET nonce = ?1,
                     ciphertext = ?2,
                     compression = ?3,
                     original_size = ?4,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?5",
                params![
                    nonce.to_vec(),
                    ciphertext,
                    compression.as_str(),
                    original_size.map(i64::try_from).transpose().map_err(|_| {
                        VaultickError::Validation("original_size is too large".to_string())
                    })?,
                    secret_id
                ],
            )?;
            tx.execute(
                "DELETE FROM secret_recipients WHERE secret_id = ?1",
                params![secret_id],
            )?;
        } else {
            tx.execute(
                "INSERT INTO secrets (id, workspace_id, key, nonce, ciphertext, compression, original_size)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    secret_id,
                    workspace.id,
                    key,
                    nonce.to_vec(),
                    ciphertext,
                    compression.as_str(),
                    original_size.map(i64::try_from).transpose().map_err(|_| {
                        VaultickError::Validation("original_size is too large".to_string())
                    })?
                ],
            )
            .map_err(|err| {
                map_constraint(
                    err,
                    format!("secret key already exists in workspace: {key}"),
                )
            })?;
        }

        for (certificate, wrapped_key) in certificates.iter().zip(wrapped_keys.iter()) {
            tx.execute(
                "INSERT INTO secret_recipients (secret_id, rsa_certificate_id, wrapped_key)
                 VALUES (?1, ?2, ?3)",
                params![secret_id, certificate.id, wrapped_key],
            )?;
        }

        let metadata = Self::resolve_secret_metadata(&tx, &workspace.id, &key)?;
        tx.commit()?;
        Ok(metadata)
    }

    pub fn get_secret(
        &self,
        workspace_ref: &str,
        key: &str,
        private_key_pem: &str,
    ) -> Result<String> {
        let plaintext = self.get_secret_bytes(workspace_ref, key, private_key_pem)?;
        String::from_utf8(plaintext)
            .map_err(|err| VaultickError::Crypto(format!("secret is not valid UTF-8: {err}")))
    }

    pub fn get_secret_bytes(
        &self,
        workspace_ref: &str,
        key: &str,
        private_key_pem: &str,
    ) -> Result<Vec<u8>> {
        let private_key = parse_private_key(private_key_pem)?;
        let key = normalize_secret_key(key)?;
        let raw = self.decrypt_secret_with_private_key(workspace_ref, &key, &private_key)?;
        compression::decompress_secret_payload(&raw.payload, raw.compression, raw.original_size)
    }

    pub fn get_secret_raw_bytes(
        &self,
        workspace_ref: &str,
        key: &str,
        private_key_pem: &str,
    ) -> Result<compression::RawSecretBytes> {
        let private_key = parse_private_key(private_key_pem)?;
        let key = normalize_secret_key(key)?;
        self.decrypt_secret_with_private_key(workspace_ref, &key, &private_key)
    }

    pub fn get_secret_auto<P: AsRef<Path>>(
        &self,
        workspace_ref: &str,
        key: &str,
        ssh_dir: P,
    ) -> Result<String> {
        let private_key_pem =
            self.resolve_auto_private_key_pem_for_workspace(workspace_ref, ssh_dir)?;
        self.get_secret(workspace_ref, key, &private_key_pem)
    }

    pub fn get_secret_bytes_auto<P: AsRef<Path>>(
        &self,
        workspace_ref: &str,
        key: &str,
        ssh_dir: P,
    ) -> Result<Vec<u8>> {
        let private_key_pem =
            self.resolve_auto_private_key_pem_for_workspace(workspace_ref, ssh_dir)?;
        self.get_secret_bytes(workspace_ref, key, &private_key_pem)
    }

    pub fn get_secret_raw_bytes_auto<P: AsRef<Path>>(
        &self,
        workspace_ref: &str,
        key: &str,
        ssh_dir: P,
    ) -> Result<compression::RawSecretBytes> {
        let private_key_pem =
            self.resolve_auto_private_key_pem_for_workspace(workspace_ref, ssh_dir)?;
        self.get_secret_raw_bytes(workspace_ref, key, &private_key_pem)
    }

    pub fn get_secret_metadata(&self, workspace_ref: &str, key: &str) -> Result<SecretMetadata> {
        let key = normalize_secret_key(key)?;
        let conn = self.conn.borrow();
        let workspace = Self::resolve_workspace(&conn, workspace_ref)?;
        Self::resolve_secret_metadata(&conn, &workspace.id, &key)
    }

    fn decrypt_secret_with_private_key(
        &self,
        workspace_ref: &str,
        key: &str,
        private_key: &RsaPrivateKey,
    ) -> Result<compression::RawSecretBytes> {
        let conn = self.conn.borrow();
        let workspace = Self::resolve_workspace(&conn, workspace_ref)?;
        let secret = Self::find_secret_by_key(&conn, &workspace.id, key)?.ok_or_else(|| {
            VaultickError::NotFound {
                entity: "secret",
                reference: key.to_string(),
            }
        })?;
        let recipients = Self::list_secret_recipients(&conn, &secret.metadata.id)?;
        let dek = unwrap_secret_key(private_key, &recipients)?;

        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|err| VaultickError::Crypto(format!("invalid data encryption key: {err}")))?;
        let payload = cipher
            .decrypt(
                Nonce::from_slice(secret.nonce.as_slice()),
                Payload {
                    msg: secret.ciphertext.as_ref(),
                    aad: secret_key_aad(key),
                },
            )
            .map_err(|err| VaultickError::Crypto(format!("failed to decrypt secret: {err}")))?;
        Ok(compression::RawSecretBytes {
            payload,
            compression: secret.compression,
            original_size: secret.original_size,
        })
    }

    fn resolve_auto_private_key_pem_for_workspace<P: AsRef<Path>>(
        &self,
        workspace_ref: &str,
        ssh_dir: P,
    ) -> Result<String> {
        let ssh_dir = ssh_dir.as_ref();
        let certificates = self.list_certificates(workspace_ref)?;
        let candidates = discover_secret_get_private_key_candidates(ssh_dir, &certificates);

        if candidates.is_empty() {
            return Err(VaultickError::AutoPrivateKeyLookup(format!(
                "no private key matching any certificate label was found in {}, and {} was not available; define --private-key",
                ssh_dir.display(),
                ssh_dir.join(DEFAULT_SSH_PRIVATE_KEY_NAME).display()
            )));
        }

        let mut attempted = Vec::new();
        let workspace_public_keys = certificates
            .iter()
            .map(|certificate| {
                parse_public_material(&certificate.cert_pem).map(|parsed| parsed.public_key)
            })
            .collect::<Result<Vec<_>>>()?;

        for candidate in candidates {
            match fs::read_to_string(&candidate.path) {
                Ok(private_key_pem) => match parse_private_key(&private_key_pem) {
                    Ok(private_key) => {
                        if workspace_public_keys.iter().any(|certificate_public_key| {
                            *certificate_public_key == private_key.to_public_key()
                        }) {
                            return Ok(private_key_pem);
                        }

                        attempted.push(format!(
                            "{} ({}) did not match any certificate saved in the workspace",
                            candidate.label,
                            candidate.path.display()
                        ));
                    }
                    Err(err) => attempted.push(format!(
                        "{} ({}) did not work: {}",
                        candidate.label,
                        candidate.path.display(),
                        summarize_secret_lookup_error(&err)
                    )),
                },
                Err(err) => attempted.push(format!(
                    "{} ({}) could not be read: {}",
                    candidate.label,
                    candidate.path.display(),
                    err
                )),
            }
        }

        Err(VaultickError::AutoPrivateKeyLookup(format!(
            "automatic private key lookup failed. Tried {}. define --private-key",
            attempted.join("; ")
        )))
    }

    pub fn list_secrets(&self, workspace_ref: &str) -> Result<Vec<SecretMetadata>> {
        let conn = self.conn.borrow();
        let workspace = Self::resolve_workspace(&conn, workspace_ref)?;
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, key, created_at, updated_at
             FROM secrets
             WHERE workspace_id = ?1
             ORDER BY key ASC",
        )?;
        let rows = stmt.query_map(params![workspace.id], secret_metadata_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(VaultickError::from)
    }

    pub fn list_secrets_paginated(
        &self,
        workspace_ref: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<SecretMetadata>> {
        let conn = self.conn.borrow();
        let workspace = Self::resolve_workspace(&conn, workspace_ref)?;
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, key, created_at, updated_at
             FROM secrets
             WHERE workspace_id = ?1
             ORDER BY key ASC
             LIMIT ?2
             OFFSET ?3",
        )?;
        let rows = stmt.query_map(
            params![workspace.id, limit as i64, offset as i64],
            secret_metadata_from_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(VaultickError::from)
    }

    pub fn delete_secret(&self, workspace_ref: &str, key: &str) -> Result<()> {
        let key = normalize_secret_key(key)?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction()?;
        let workspace = Self::resolve_workspace(&tx, workspace_ref)?;
        let secret = Self::find_secret_by_key(&tx, &workspace.id, &key)?.ok_or_else(|| {
            VaultickError::NotFound {
                entity: "secret",
                reference: key.clone(),
            }
        })?;
        tx.execute(
            "DELETE FROM secrets WHERE id = ?1",
            params![secret.metadata.id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn init_schema(&self, create_default_workspace: bool) -> Result<()> {
        let conn = self.conn.borrow();
        conn.execute_batch(INITIAL_SCHEMA)?;

        if create_default_workspace {
            let default_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO workspaces (id, name) VALUES (?1, ?2)",
                params![default_id, DEFAULT_WORKSPACE_NAME],
            )
            .map_err(|err| {
                map_constraint(
                    err,
                    format!("workspace already exists: {DEFAULT_WORKSPACE_NAME}"),
                )
            })?;
        }

        Ok(())
    }

    fn resolve_workspace(conn: &Connection, workspace_ref: &str) -> Result<Workspace> {
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at
             FROM workspaces
             WHERE id = ?1 OR name = ?1
             ORDER BY CASE WHEN id = ?1 THEN 0 ELSE 1 END
             LIMIT 1",
        )?;
        stmt.query_row(params![workspace_ref], workspace_from_row)
            .optional()?
            .ok_or_else(|| VaultickError::NotFound {
                entity: "workspace",
                reference: workspace_ref.to_string(),
            })
    }

    fn resolve_certificate(
        conn: &Connection,
        workspace_id: &str,
        cert_ref: &str,
    ) -> Result<RsaCertificate> {
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, label, cert_pem, fingerprint_sha256, created_at
             FROM rsa_certificates
             WHERE workspace_id = ?1
               AND (id = ?2 OR fingerprint_sha256 = ?2)
             ORDER BY CASE WHEN id = ?2 THEN 0 ELSE 1 END
             LIMIT 1",
        )?;
        stmt.query_row(params![workspace_id, cert_ref], certificate_from_row)
            .optional()?
            .ok_or_else(|| VaultickError::NotFound {
                entity: "certificate",
                reference: cert_ref.to_string(),
            })
    }

    fn resolve_secret_metadata(
        conn: &Connection,
        workspace_id: &str,
        key: &str,
    ) -> Result<SecretMetadata> {
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, key, created_at, updated_at
             FROM secrets
             WHERE workspace_id = ?1 AND key = ?2
             LIMIT 1",
        )?;
        stmt.query_row(params![workspace_id, key], secret_metadata_from_row)
            .optional()?
            .ok_or_else(|| VaultickError::NotFound {
                entity: "secret",
                reference: key.to_string(),
            })
    }

    fn list_certificates_for_workspace(
        conn: &Connection,
        workspace_id: &str,
    ) -> Result<Vec<RsaCertificate>> {
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, label, cert_pem, fingerprint_sha256, created_at
             FROM rsa_certificates
             WHERE workspace_id = ?1
             ORDER BY created_at ASC, label ASC",
        )?;
        let rows = stmt.query_map(params![workspace_id], certificate_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(VaultickError::from)
    }

    fn find_secret_by_key(
        conn: &Connection,
        workspace_id: &str,
        key: &str,
    ) -> Result<Option<SecretRecord>> {
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, key, nonce, ciphertext, compression, original_size, created_at, updated_at
             FROM secrets
             WHERE workspace_id = ?1 AND key = ?2
             LIMIT 1",
        )?;
        stmt.query_row(params![workspace_id, key], secret_record_from_row)
            .optional()
            .map_err(VaultickError::from)
    }

    fn list_secret_records_for_workspace(
        conn: &Connection,
        workspace_id: &str,
    ) -> Result<Vec<SecretRecord>> {
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, key, nonce, ciphertext, compression, original_size, created_at, updated_at
             FROM secrets
             WHERE workspace_id = ?1
             ORDER BY key ASC",
        )?;
        let rows = stmt.query_map(params![workspace_id], secret_record_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(VaultickError::from)
    }

    fn list_secret_recipients(conn: &Connection, secret_id: &str) -> Result<Vec<SecretRecipient>> {
        let mut stmt = conn.prepare(
            "SELECT wrapped_key
             FROM secret_recipients
             WHERE secret_id = ?1",
        )?;
        let rows = stmt.query_map(params![secret_id], |row| {
            Ok(SecretRecipient {
                wrapped_key: row.get(0)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(VaultickError::from)
    }
}

fn workspace_from_row(row: &Row<'_>) -> rusqlite::Result<Workspace> {
    Ok(Workspace {
        id: row.get(0)?,
        name: row.get(1)?,
        created_at: row.get(2)?,
    })
}

fn certificate_from_row(row: &Row<'_>) -> rusqlite::Result<RsaCertificate> {
    Ok(RsaCertificate {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        label: row.get(2)?,
        cert_pem: row.get(3)?,
        fingerprint_sha256: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn secret_metadata_from_row(row: &Row<'_>) -> rusqlite::Result<SecretMetadata> {
    Ok(SecretMetadata {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        key: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn secret_record_from_row(row: &Row<'_>) -> rusqlite::Result<SecretRecord> {
    let compression: String = row.get(5)?;
    let compression =
        compression
            .parse::<compression::Compression>()
            .map_err(|err| match err {
                VaultickError::Validation(message) => rusqlite::Error::FromSqlConversionFailure(
                    5,
                    Type::Text,
                    Box::new(std::io::Error::other(message)),
                ),
                other => rusqlite::Error::FromSqlConversionFailure(
                    5,
                    Type::Text,
                    Box::new(std::io::Error::other(other.to_string())),
                ),
            })?;
    let original_size: Option<i64> = row.get(6)?;
    let original_size = original_size
        .map(u64::try_from)
        .transpose()
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(6, Type::Integer, Box::new(err)))?;

    Ok(SecretRecord {
        metadata: SecretMetadata {
            id: row.get(0)?,
            workspace_id: row.get(1)?,
            key: row.get(2)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        },
        nonce: row.get(3)?,
        ciphertext: row.get(4)?,
        compression,
        original_size,
    })
}

fn validate_compression_metadata(
    compression: compression::Compression,
    original_size: Option<u64>,
) -> Result<()> {
    match (compression, original_size) {
        (compression::Compression::None, None) => Ok(()),
        (compression::Compression::None, Some(_)) => Err(VaultickError::Validation(
            "original_size must be empty when compression is none".to_string(),
        )),
        (compression::Compression::Zstd, Some(_)) => Ok(()),
        (compression::Compression::Zstd, None) => Err(VaultickError::Validation(
            "original_size is required when compression is zstd".to_string(),
        )),
    }
}

fn parse_public_material(input: &str) -> Result<ParsedCertificate> {
    if let Ok((_, pem)) = parse_x509_pem(input.as_bytes()) {
        let der_bytes = pem.contents.as_bytes();
        if let Ok((_, cert)) = X509Certificate::from_der(der_bytes) {
            let public_key = RsaPublicKey::from_public_key_der(cert.public_key().raw)
                .map_err(|err| VaultickError::InvalidCertificate(err.to_string()))?;
            return build_parsed_certificate(public_key);
        }
    }

    if let Ok(public_key) = RsaPublicKey::from_public_key_pem(input) {
        return build_parsed_certificate(public_key);
    }

    if let Ok(public_key) = RsaPublicKey::from_pkcs1_pem(input) {
        return build_parsed_certificate(public_key);
    }

    Err(VaultickError::InvalidCertificate(
        "expected an RSA X.509 certificate or RSA public key PEM".to_string(),
    ))
}

fn parse_private_key(private_key_pem: &str) -> Result<RsaPrivateKey> {
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(private_key_pem) {
        return Ok(key);
    }

    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(private_key_pem) {
        return Ok(key);
    }

    if let Ok(ssh_key) = SshPrivateKey::from_openssh(private_key_pem) {
        let rsa_keypair = ssh_key.key_data().rsa().ok_or_else(|| {
            VaultickError::InvalidPrivateKey("private key is not RSA".to_string())
        })?;

        return ssh_rsa_keypair_to_private_key(rsa_keypair);
    }

    Err(VaultickError::InvalidPrivateKey(
        "expected an RSA private key in PKCS#1, PKCS#8, or OpenSSH format".to_string(),
    ))
}

fn build_parsed_certificate(public_key: RsaPublicKey) -> Result<ParsedCertificate> {
    let der = public_key
        .to_public_key_der()
        .map_err(|err| VaultickError::InvalidCertificate(err.to_string()))?;

    Ok(ParsedCertificate {
        public_key,
        fingerprint_sha256: hex::encode(Sha256::digest(der.as_bytes())),
    })
}

fn ssh_rsa_keypair_to_private_key(keypair: &ssh_key::private::RsaKeypair) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_components(
        BigUint::try_from(&keypair.public.n)
            .map_err(|err| VaultickError::InvalidPrivateKey(err.to_string()))?,
        BigUint::try_from(&keypair.public.e)
            .map_err(|err| VaultickError::InvalidPrivateKey(err.to_string()))?,
        BigUint::try_from(&keypair.private.d)
            .map_err(|err| VaultickError::InvalidPrivateKey(err.to_string()))?,
        vec![
            BigUint::try_from(&keypair.private.p)
                .map_err(|err| VaultickError::InvalidPrivateKey(err.to_string()))?,
            BigUint::try_from(&keypair.private.q)
                .map_err(|err| VaultickError::InvalidPrivateKey(err.to_string()))?,
        ],
    )
    .map_err(|err| VaultickError::InvalidPrivateKey(err.to_string()))
}

fn discover_label_private_key_candidates(
    ssh_dir: &Path,
    certificates: &[RsaCertificate],
) -> Vec<PrivateKeyCandidate> {
    let mut candidates = Vec::new();

    for certificate in certificates {
        let label = certificate.label.trim();
        if label.is_empty() {
            continue;
        }

        let path = ssh_dir.join(label);
        if path.is_file() {
            candidates.push(PrivateKeyCandidate {
                label: label.to_string(),
                path,
            });
        }
    }

    candidates
}

fn discover_secret_get_private_key_candidates(
    ssh_dir: &Path,
    certificates: &[RsaCertificate],
) -> Vec<PrivateKeyCandidate> {
    let mut candidates = discover_label_private_key_candidates(ssh_dir, certificates);

    if candidates.is_empty() {
        let fallback_path = ssh_dir.join(DEFAULT_SSH_PRIVATE_KEY_NAME);
        if fallback_path.is_file() {
            candidates.push(PrivateKeyCandidate {
                label: DEFAULT_SSH_PRIVATE_KEY_NAME.to_string(),
                path: fallback_path,
            });
        }
    }

    candidates
}

fn summarize_secret_lookup_error(err: &VaultickError) -> String {
    match err {
        VaultickError::IncompatiblePrivateKey => "private key did not match the secret".to_string(),
        VaultickError::InvalidPrivateKey(message) => format!("invalid private key: {message}"),
        VaultickError::NotFound {
            entity: "secret",
            reference,
        } => format!("secret not found: {reference}"),
        _ => err.to_string(),
    }
}

fn normalize_secret_key(key: &str) -> Result<String> {
    let normalized = key.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(VaultickError::Validation(
            "secret key cannot be empty".to_string(),
        ));
    }

    Ok(normalized)
}

fn secret_key_aad(key: &str) -> &[u8] {
    key.as_bytes()
}

fn wrap_secret_key(public_key: &RsaPublicKey, dek: &[u8]) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    public_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), dek)
        .map_err(|err| VaultickError::Crypto(format!("failed to wrap secret key: {err}")))
}

fn unwrap_secret_key(
    private_key: &RsaPrivateKey,
    recipients: &[SecretRecipient],
) -> Result<Vec<u8>> {
    for recipient in recipients {
        if let Ok(dek) = private_key.decrypt(Oaep::new::<Sha256>(), &recipient.wrapped_key) {
            return Ok(dek);
        }
    }

    Err(VaultickError::IncompatiblePrivateKey)
}

fn map_constraint(err: rusqlite::Error, message: String) -> VaultickError {
    match &err {
        rusqlite::Error::SqliteFailure(code, _) if code.code == ErrorCode::ConstraintViolation => {
            VaultickError::Validation(message)
        }
        _ => VaultickError::Database(err),
    }
}

fn _blob_len_error(expected: usize, found: usize, column: usize) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid blob length: expected {expected}, found {found}"),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use ssh_key::PublicKey as SshPublicKey;
    use tempfile::TempDir;

    const CERT_1: &str = r#"-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUTm6UaZyTz/KpG8pvoMGOt24PENgwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOdmFsdGljay10ZXN0LTEwHhcNMjYwMzE2MTQwNjM0WhcN
MjcwMzE2MTQwNjM0WjAZMRcwFQYDVQQDDA52YWx0aWNrLXRlc3QtMTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAI9oxf+NjNa6UZO/WqQboCiR1fumUzUx
LqSF+SqfLjPYiBunRRMw5Eh59oBKBHbSyUbZp/U72+dqM/nvqiQEPcImJfxbKy1k
ykGXXr8+sTXdtydzbHXkURE6vDI0ZOeMjH2FF0xOCyZQ9HCdlosfCUfW8VLUbB+z
WWSKL1XExUkvsfbUNk+8DeDig91NdlCqUZ6T4onedsAkjO3thgpcHr/dnTt9Ul4u
l0gu+8NW/yMS3IIXYKIeS3TGtB/7uALI0xMmKkZqWgIcJTNmZKO+QgLV8yLezgjn
BCBWqH98WjdUr2CQms56RY5nvA4uMV/o4/9ZnFrRcWgsQzTHzRv5cgsCAwEAAaNT
MFEwHQYDVR0OBBYEFIQ6VxlGi3YBnd/J98QbZV3QPH+qMB8GA1UdIwQYMBaAFIQ6
VxlGi3YBnd/J98QbZV3QPH+qMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAIc2cNLX9KUfD+g5zX48eMXiwykfwsMalufMKH7DDBKZ6GPTUvr+vd2f
RR5bDoXfrYz5mzCXRtt2xWQjDgM5S2Ljb5sP1JZl2wMYloZ4VsEgVhxKmOtSei55
snWZBDenLABtoIS8LTRPBZAAD/+zr4RWrks4gPouOJCK2iy0j545/+EtiklI5/53
i2W8kfZQuStlQsdYnDwfyKEzDHWgfXIg4GbUTmC/8tJHJb/E8qyoM/NNK840XCb1
CgeM/RKUaHreh86NZNaPnMe6iQSpECMcM0gjBFXCp+EJlwENxbmn8yspv9AgfIlg
GDqWNEihkWwMMvZPykCLMSLtYK59fxs=
-----END CERTIFICATE-----
"#;

    const KEY_1: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCPaMX/jYzWulGT
v1qkG6AokdX7plM1MS6khfkqny4z2Igbp0UTMORIefaASgR20slG2af1O9vnajP5
76okBD3CJiX8WystZMpBl16/PrE13bcnc2x15FEROrwyNGTnjIx9hRdMTgsmUPRw
nZaLHwlH1vFS1Gwfs1lkii9VxMVJL7H21DZPvA3g4oPdTXZQqlGek+KJ3nbAJIzt
7YYKXB6/3Z07fVJeLpdILvvDVv8jEtyCF2CiHkt0xrQf+7gCyNMTJipGaloCHCUz
ZmSjvkIC1fMi3s4I5wQgVqh/fFo3VK9gkJrOekWOZ7wOLjFf6OP/WZxa0XFoLEM0
x80b+XILAgMBAAECggEAAjCujlNAbg41ELyWEj1SqGhnGm7/2eAdhj6a4x9OyOMH
eDn7Fdxj9XdnX+cW0Xm/h2kIAk3l8zLRW/NgoH33M34W/Yj8PgxYdRY1ZR1uN2m3
4JXrk+h1MO/y7EpAjnqDePybznr3+0pExsG90CzHY/NCo1vetYfl5ZpL/sUdNxuR
ENEPa5I7vKTGng7+QpqlB6p3ZwHHVQuCtAgzM8gwHMyiWY3E1LjAZopkfG3Ir7+w
Y+EFo/uv77rorA6wdNnk5U8i8pqCiqNNE3Go1AM7RyVvqla9Izj0auPJ8FidW8So
eez90prZunBr6UIDI4kZBJvy7BdoEVVHxI0kJh6UgQKBgQDHSI+XUc/vxlxbY/+h
Ypm0YsHZscVCGuTcJo6GSkc50fA8s0sHm9hmd6Rv1hokMF66yjC24g3Be7MWS13Y
UdxMCbN4qQJ+Ywr/Va+lHRh0zwCr+prLJONlG3t3u4CmR+fSbMQWgEzqZpublJhg
jZbs+9eGFUu4m/OQI2bKhqL7FQKBgQC4OVG/Om4dBtcr11uBT148Pq1xDMUOEaa+
/eAaskFebLaTPZga1SSufqlf5O1WWZlEukSgSQvmFiHWQFF3HMU0B4HcXfE6P3LB
eC7VuE8iTnppxcZrMvBjYOGvewgcws2KGmojGfDolJrCJf7df53fgDEKqo3AkODj
BpMTe6GAnwKBgHkgV3aoGXUp4hUCcOwM3FPR+vVwoe8OHbDaFqL1Htm8CwM6Dw6u
4RdW/TGktvrsE4gBQR7Hw4iowS95266SAw6MjvN19rgPRy3vTPVU+/pzn3rotZFn
+HcJ/z/FTerDpdo2lfD/RsDqYQZtiTiWlvewE03CP+YTlDU171KGByYJAoGABRLn
Eno8gCYpFPcIeSZDdStQwZVVdA6+ZfI+Et4n+L7LxIBkyRBnwzqP1alLdB5hn0f2
DegVINApPGpnE/3B3K38QKKBu1X2BigWOiKqY0qACpu83ET54/LOJHQiBBDFcnFJ
zQ+w1+cH4CMFwvn50icIsr+ByfTzjK0ordew2gcCgYArbVbKS5+JoPZtfj0rPo/K
RoG9b9cou8TtCqraawLa+PSG11LJoAqt4MBdkGLjCGjiWKVGtoalVDzMGbi/mUQ3
2yUmdhy+fTRop98q2vcQGJhEl0cH+3hB6zIgqwoN0E9Bs84Sq3WkiClAxIQOWoJ3
PDfOClGrLMTO4iJwIw1kqg==
-----END PRIVATE KEY-----
"#;

    const CERT_2: &str = r#"-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIURZNjcbJlMXen1TOx446ZYH2uLn8wDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOdmFsdGljay10ZXN0LTIwHhcNMjYwMzE2MTQwNjM0WhcN
MjcwMzE2MTQwNjM0WjAZMRcwFQYDVQQDDA52YWx0aWNrLXRlc3QtMjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMyNl3uFQsJFhJquorKmScug0XTf0vLl
aBu8MmFe1k1X3RVPZSVVaK2v5oAtflN6l9mhVdf9bqTIDNvaHG5gwZU9qniMIKp4
fcdHJtCFa8RQl8F/P3TnOJG3DYrZqpHkhnxk5LOF5Md9EpNw258KFNJe329gRG5l
dQsQOZAN0I/Vyu3n4czAO05jCI3e3SdPLl8sIiQGJiV2vtmS9SKw7nbYe6uxmtg9
JvT7eCBr8DepC1/HklmH6DMNBtJ4fVfjkgdKvFS5PD9gjTtmUaCs3ULF1omXsLGn
qvl8Gbleq/B7E4Y7CZ4pmYEDpmQFm+297ckloGNG0ujsjC8khgcWg70CAwEAAaNT
MFEwHQYDVR0OBBYEFAHpRWmnK5naQplbwRNT5zzwCTPrMB8GA1UdIwQYMBaAFAHp
RWmnK5naQplbwRNT5zzwCTPrMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAHgPjDzDzP/OFiNwxStvLhu/s75b8Tqie/St3D20hB+A6PaSoetOEeIa
O63TuaHkzDStjpFAtJke1CS3l4Os8qqiG3PSjPiybExBpx1/9PW2CO9XudX3yXxy
reHWcH/cUrwHhwYQeASHJqW0SqFoxbMYciwe6U53rkaRwjIc+AZ2M0AvalRtNams
9ftBVw84tZ1GMw5A+O8YwQcTZ9kjAaJRaPctiijFLe3OkTlzdB23r3kb4gJf+8Af
DlO0uWXEwLJoUL8m6EU+CXd/7Uf6y+iRJKBouYhAvPL6qUmx5dHn4E3qq+VDJm8I
vMTyin6Cb0Timv91bsBe8dJpKyWSVtE=
-----END CERTIFICATE-----
"#;

    const KEY_2: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMjZd7hULCRYSa
rqKypknLoNF039Ly5WgbvDJhXtZNV90VT2UlVWitr+aALX5TepfZoVXX/W6kyAzb
2hxuYMGVPap4jCCqeH3HRybQhWvEUJfBfz905ziRtw2K2aqR5IZ8ZOSzheTHfRKT
cNufChTSXt9vYERuZXULEDmQDdCP1crt5+HMwDtOYwiN3t0nTy5fLCIkBiYldr7Z
kvUisO522HursZrYPSb0+3gga/A3qQtfx5JZh+gzDQbSeH1X45IHSrxUuTw/YI07
ZlGgrN1CxdaJl7Cxp6r5fBm5XqvwexOGOwmeKZmBA6ZkBZvtve3JJaBjRtLo7Iwv
JIYHFoO9AgMBAAECggEACV/d1uPbFOMxuhMR0sUrMaFbqBMP7GDWHhtIZcz+XkoO
EEl0tbrN0tPyaOJs3S+LoQYzVHRBa1zdtf+veOGHTasnUmH9p0JhZU4d+cV7lGIr
KkuGIXntTkRI4xmppwkFntLS5mVXAEt7m/U6o3XHUYLWk5iiWjrdG9YxBSiU69qH
+ApR31CPcXE09N2ddaLNFdFzspWP1taWrGg9AeU/WS6jYwbkVHq0uBmtbmIou/7n
rW12C+LC36HT8KFc/fu/7XT1vixZcjiSU++zpe18jK3F0PRwdmVUTG5tIwAryP2E
I/AwneespgKPdnJjTEL2rL/lG8zw0yxxKoD6jD4dYQKBgQDreZf4eVWQbRb20SYN
AiaqRksONvoTNh0jKYtms/pORuZFtfBfyy+BvoEW30C4S5De7QxulyfKdF0BDzjc
BCVNUTaVXtOkup7DlXtFuEvn3S+pt7F42IIRBaulWhqSdT7At2VeDe9SgkkaOAfy
iJMjxbASdWo+LUa3OGLyS+Fi8QKBgQDeYgE/fGCWgkqLMHak0y8Efeu7EQlPdaRm
X8oRQU3696Z5fmdSM/WilkotbVraqcVE1t54qlAyrctKjM0F1LlgAtdn8KWoAV4P
U36URVuBbAl0T8+Cp6+00kxWE+Sc+8kIkrdzNzf4sSXm5xeNTEGuCeNu2EAqhZY0
hATdZalVjQKBgQDKmVTS+XpQCDxA4hSODrK7wD0lntGtI9sP/Neu5t1O6huIEREf
Ko/WXtVsm2tw5btgwq32nOEkhNfcaH9wdbSugFipTexlCBg/iWaFxxqwBRPUP3NX
2ViXUryrSQohxvTWFTUHJpAp+mTxRRI5b57BoX5rc1CU7JmyXLZtaDIk0QKBgHSG
/Eps/RvA2BjJY1IJCxkadnyGd894QJYYWYTjKF56iHQfRTqw2WTBxcq6A6KS1Ti2
Mssdy3pS0TSWRRRqHFzwADmJwvQfC0+Sm8BL+5/8oZOeAolfHtXsYG22bNPJp9Tj
NFeeNqkNAmRU8WVr8PqmWdOKY00kxMlt6DKvA6U9AoGAAxWy63JWwGWGI2AblJwa
LgHNEY15eoHRuZn4u5wnt1XVx1abKmNl0x0o9erPlulzTG8x73uRJFNvAarg36Nm
8/+kfluVu+wjgdQ/AoSmiugNXhvDm/r+TEk2Igi4BMJYLeietYGemkOT/R2bCvFf
wfa0Ve8fq73AK1+visY4gUc=
-----END PRIVATE KEY-----
"#;

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

    #[test]
    fn workspace_crud_works() {
        let (_dir, store) = new_store();
        let default_workspace = store.get_workspace(DEFAULT_WORKSPACE_NAME).unwrap();
        let created = store.create_workspace("team-a").unwrap();

        let listed = store.list_workspaces().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], default_workspace);
        assert_eq!(listed[1], created);

        let fetched = store.get_workspace("team-a").unwrap();
        assert_eq!(fetched, created);

        store.delete_workspace("team-a").unwrap();
        let listed = store.list_workspaces().unwrap();
        assert_eq!(listed, vec![default_workspace]);
    }

    #[test]
    fn new_database_starts_with_default_workspace() {
        let (_dir, store) = new_store();

        let listed = store.list_workspaces().unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, DEFAULT_WORKSPACE_NAME);
    }

    #[test]
    fn new_database_records_schema_version() {
        let (_dir, store) = new_store();
        let version: i64 = store
            .conn
            .borrow()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();

        assert_eq!(version, 2);
    }

    #[test]
    fn add_certificate_rejects_invalid_pem() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();

        let err = store
            .add_certificate("team-a", "primary", "not-a-cert", None)
            .unwrap_err();

        assert!(matches!(err, VaultickError::InvalidCertificate(_)));
    }

    #[test]
    fn secret_roundtrip_with_single_certificate() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();

        store
            .set_secret("team-a", "api-key", "super-secret", false)
            .unwrap();
        let value = store.get_secret("team-a", "api-key", KEY_1).unwrap();

        assert_eq!(value, "super-secret");
    }

    #[test]
    fn secret_get_fails_with_wrong_private_key() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        store
            .set_secret("team-a", "api-key", "super-secret", false)
            .unwrap();

        let err = store.get_secret("team-a", "api-key", KEY_2).unwrap_err();

        assert!(matches!(err, VaultickError::IncompatiblePrivateKey));
    }

    #[test]
    fn multiple_certificates_can_read_same_secret() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        store
            .add_certificate("team-a", "secondary", CERT_2, None)
            .unwrap();

        store
            .set_secret("team-a", "api-key", "shared-secret", false)
            .unwrap();

        assert_eq!(
            store.get_secret("team-a", "api-key", KEY_1).unwrap(),
            "shared-secret"
        );
        assert_eq!(
            store.get_secret("team-a", "api-key", KEY_2).unwrap(),
            "shared-secret"
        );
    }

    #[test]
    fn adding_certificate_with_rewrap_grants_access_to_existing_secret() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        store
            .set_secret("team-a", "api-key", "legacy-secret", false)
            .unwrap();

        store
            .add_certificate("team-a", "secondary", CERT_2, Some(KEY_1))
            .unwrap();

        assert_eq!(
            store.get_secret("team-a", "api-key", KEY_2).unwrap(),
            "legacy-secret"
        );
    }

    #[test]
    fn set_secret_requires_at_least_one_certificate() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();

        let err = store
            .set_secret("team-a", "api-key", "secret", false)
            .unwrap_err();

        assert!(matches!(err, VaultickError::WorkspaceHasNoCertificates));
    }

    #[test]
    fn deleting_last_certificate_is_blocked_when_secrets_depend_on_it() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        let certificate = store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        store
            .set_secret("team-a", "api-key", "secret", false)
            .unwrap();

        let err = store
            .delete_certificate("team-a", &certificate.id)
            .unwrap_err();

        assert!(matches!(err, VaultickError::CertificateInUse));
    }

    #[test]
    fn overwriting_secret_keeps_single_record_and_updates_timestamp() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();

        let first = store
            .set_secret("team-a", "api-key", "secret-1", false)
            .unwrap();
        thread::sleep(Duration::from_millis(10));
        let second = store
            .set_secret("team-a", "api-key", "secret-2", true)
            .unwrap();
        let listed = store.list_secrets("team-a").unwrap();

        assert_eq!(first.id, second.id);
        assert_eq!(listed.len(), 1);
        assert_ne!(first.updated_at, second.updated_at);
        assert_eq!(
            store.get_secret("team-a", "api-key", KEY_1).unwrap(),
            "secret-2"
        );
    }

    #[test]
    fn set_secret_rejects_overwrite_without_flag() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        store
            .set_secret("team-a", "api-key", "secret-1", false)
            .unwrap();

        let err = store
            .set_secret("team-a", "api-key", "secret-2", false)
            .unwrap_err();

        assert!(
            matches!(err, VaultickError::Validation(message) if message.contains("--overwrite"))
        );
    }

    #[test]
    fn get_secret_metadata_returns_single_secret_metadata() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        let created = store
            .set_secret("team-a", "api-key", "secret-1", false)
            .unwrap();

        let fetched = store.get_secret_metadata("team-a", "Api-Key").unwrap();

        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.workspace_id, created.workspace_id);
        assert_eq!(fetched.key, "API-KEY");
        assert_eq!(fetched.created_at, created.created_at);
        assert_eq!(fetched.updated_at, created.updated_at);
    }

    #[test]
    fn list_secrets_paginated_applies_limit_and_offset() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();

        for index in 0..12 {
            store
                .set_secret(
                    "team-a",
                    &format!("SECRET_{index:02}"),
                    &format!("value-{index}"),
                    false,
                )
                .unwrap();
        }

        let first_page = store.list_secrets_paginated("team-a", 5, 0).unwrap();
        let second_page = store.list_secrets_paginated("team-a", 5, 5).unwrap();
        let tail_page = store.list_secrets_paginated("team-a", 5, 10).unwrap();

        assert_eq!(first_page.len(), 5);
        assert_eq!(first_page[0].key, "SECRET_00");
        assert_eq!(first_page[4].key, "SECRET_04");

        assert_eq!(second_page.len(), 5);
        assert_eq!(second_page[0].key, "SECRET_05");
        assert_eq!(second_page[4].key, "SECRET_09");

        assert_eq!(tail_page.len(), 2);
        assert_eq!(tail_page[0].key, "SECRET_10");
        assert_eq!(tail_page[1].key, "SECRET_11");
    }

    #[test]
    fn secret_keys_are_normalized_to_uppercase_and_are_case_insensitive() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();

        let metadata = store
            .set_secret("team-a", "google_token", "secret-1", false)
            .unwrap();
        let fetched = store.get_secret_metadata("team-a", "GoOgLe_ToKeN").unwrap();
        let decrypted = store.get_secret("team-a", "gOoGlE_tOkEn", KEY_1).unwrap();

        assert_eq!(metadata.key, "GOOGLE_TOKEN");
        assert_eq!(fetched.key, "GOOGLE_TOKEN");
        assert_eq!(decrypted, "secret-1");
    }

    #[test]
    fn binary_secret_roundtrip_works_with_bytes_api() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();

        let payload = vec![0x00, 0x9f, 0xff, 0x41, 0x42];
        store
            .set_secret_bytes("team-a", "binary_blob", &payload, false)
            .unwrap();

        let decrypted = store
            .get_secret_bytes("team-a", "BINARY_BLOB", KEY_1)
            .unwrap();
        let err = store
            .get_secret("team-a", "BINARY_BLOB", KEY_1)
            .unwrap_err();

        assert_eq!(decrypted, payload);
        assert!(
            matches!(err, VaultickError::Crypto(message) if message.contains("not valid UTF-8"))
        );
    }

    #[test]
    fn compressed_secret_bytes_roundtrip_to_original_bytes() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(32);
        let prepared =
            compression::prepare_secret_payload(&payload, compression::CompressionMode::Try {
                level: 10,
            })
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

    #[test]
    fn raw_secret_bytes_return_stored_payload_without_decompression() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        let payload = b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".repeat(64);
        let prepared =
            compression::prepare_secret_payload(&payload, compression::CompressionMode::Force {
                level: 10,
            })
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

        let raw = store
            .get_secret_raw_bytes("team-a", "archive", KEY_1)
            .unwrap();
        assert_eq!(raw.payload, prepared.payload);
        assert_eq!(raw.compression, compression::Compression::Zstd);
    }

    #[test]
    fn compression_level_rejects_out_of_range_values() {
        let err = compression::validate_level(23).unwrap_err();

        assert!(err.to_string().contains("expected 1..=22"));
    }

    #[test]
    fn renaming_secret_key_breaks_decryption_because_key_name_is_authenticated() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();
        store
            .add_certificate("team-a", "primary", CERT_1, None)
            .unwrap();
        let metadata = store
            .set_secret("team-a", "api-key", "secret-1", false)
            .unwrap();

        store
            .conn
            .borrow()
            .execute(
                "UPDATE secrets SET key = ?1 WHERE id = ?2",
                params!["RENAMED_KEY", metadata.id],
            )
            .unwrap();

        let err = store
            .get_secret("team-a", "RENAMED_KEY", KEY_1)
            .unwrap_err();

        assert!(
            matches!(err, VaultickError::Crypto(message) if message.contains("failed to decrypt secret"))
        );
    }

    #[test]
    fn openssh_private_key_and_pem_public_key_work_together() {
        let (_dir, store) = new_store();
        store.create_workspace("team-a").unwrap();

        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate("team-a", "ssh", public_key_pem.as_str(), None)
            .unwrap();
        store
            .set_secret("team-a", "api-key", "ssh-secret", false)
            .unwrap();

        assert_eq!(
            store
                .get_secret("team-a", "api-key", SSH_RSA_PRIVATE)
                .unwrap(),
            "ssh-secret"
        );
    }

    #[test]
    fn get_secret_auto_uses_label_named_private_key() {
        let (dir, store) = new_store();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("id_rsa"), SSH_RSA_PRIVATE).unwrap();

        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate("default", "id_rsa", public_key_pem.as_str(), None)
            .unwrap();
        store
            .set_secret("default", "API_KEY", "value", false)
            .unwrap();

        let value = store
            .get_secret_auto("default", "API_KEY", &ssh_dir)
            .unwrap();

        assert_eq!(value, "value");
    }

    #[test]
    fn get_secret_auto_falls_back_to_id_rsa() {
        let (dir, store) = new_store();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join(DEFAULT_SSH_PRIVATE_KEY_NAME), SSH_RSA_PRIVATE).unwrap();

        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate("default", "prod-primary", public_key_pem.as_str(), None)
            .unwrap();
        store
            .set_secret("default", "API_KEY", "value", false)
            .unwrap();

        let value = store
            .get_secret_auto("default", "API_KEY", &ssh_dir)
            .unwrap();

        assert_eq!(value, "value");
    }

    #[test]
    fn get_secret_auto_returns_guidance_when_no_candidate_exists() {
        let (dir, store) = new_store();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate("default", "prod-primary", public_key_pem.as_str(), None)
            .unwrap();
        store
            .set_secret("default", "API_KEY", "value", false)
            .unwrap();

        let err = store
            .get_secret_auto("default", "API_KEY", &ssh_dir)
            .unwrap_err();

        assert!(
            matches!(err, VaultickError::AutoPrivateKeyLookup(message) if message.contains("define --private-key"))
        );
    }

    fn new_store() -> (TempDir, Vaultick) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vaultick.db");
        let store = Vaultick::open(path).unwrap();
        (dir, store)
    }

    fn ssh_rsa_public_to_public_key(
        public_key: &ssh_key::public::RsaPublicKey,
    ) -> Result<RsaPublicKey> {
        RsaPublicKey::new(
            BigUint::try_from(&public_key.n)
                .map_err(|err| VaultickError::InvalidCertificate(err.to_string()))?,
            BigUint::try_from(&public_key.e)
                .map_err(|err| VaultickError::InvalidCertificate(err.to_string()))?,
        )
        .map_err(|err| VaultickError::InvalidCertificate(err.to_string()))
    }
}
