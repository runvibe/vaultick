use std::fmt;
use std::str::FromStr;

use crate::{Result, VaultickError};

pub const DEFAULT_COMPRESSION_LEVEL: i32 = 10;
pub const MIN_COMPRESSION_LEVEL: i32 = 1;
pub const MAX_COMPRESSION_LEVEL: i32 = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Zstd,
}

impl Compression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Compression {
    type Err = VaultickError;

    fn from_str(input: &str) -> Result<Self> {
        match input {
            "none" => Ok(Self::None),
            "zstd" => Ok(Self::Zstd),
            other => Err(VaultickError::Validation(format!(
                "unsupported secret compression: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMode {
    None,
    Try { level: i32 },
    Force { level: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSecretPayload {
    pub payload: Vec<u8>,
    pub compression: Compression,
    pub original_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSecretBytes {
    pub payload: Vec<u8>,
    pub compression: Compression,
    pub original_size: Option<u64>,
}

pub fn validate_level(level: i32) -> Result<i32> {
    if !(MIN_COMPRESSION_LEVEL..=MAX_COMPRESSION_LEVEL).contains(&level) {
        return Err(VaultickError::Validation(format!(
            "invalid compression level: expected {MIN_COMPRESSION_LEVEL}..={MAX_COMPRESSION_LEVEL}"
        )));
    }

    Ok(level)
}

pub fn prepare_secret_payload(input: &[u8], mode: CompressionMode) -> Result<PreparedSecretPayload> {
    match mode {
        CompressionMode::None => Ok(PreparedSecretPayload {
            payload: input.to_vec(),
            compression: Compression::None,
            original_size: None,
        }),
        CompressionMode::Try { level } => {
            let level = validate_level(level)?;
            let compressed = zstd::bulk::compress(input, level).map_err(|err| {
                VaultickError::Crypto(format!("failed to compress secret with zstd: {err}"))
            })?;
            if compressed.len() < input.len() {
                Ok(PreparedSecretPayload {
                    payload: compressed,
                    compression: Compression::Zstd,
                    original_size: Some(input.len() as u64),
                })
            } else {
                Ok(PreparedSecretPayload {
                    payload: input.to_vec(),
                    compression: Compression::None,
                    original_size: None,
                })
            }
        }
        CompressionMode::Force { level } => {
            let level = validate_level(level)?;
            let compressed = zstd::bulk::compress(input, level).map_err(|err| {
                VaultickError::Crypto(format!("failed to compress secret with zstd: {err}"))
            })?;
            Ok(PreparedSecretPayload {
                payload: compressed,
                compression: Compression::Zstd,
                original_size: Some(input.len() as u64),
            })
        }
    }
}

pub fn decompress_secret_payload(
    payload: &[u8],
    compression: Compression,
    original_size: Option<u64>,
) -> Result<Vec<u8>> {
    match compression {
        Compression::None => Ok(payload.to_vec()),
        Compression::Zstd => {
            let original_size = original_size.ok_or_else(|| {
                VaultickError::Validation(
                    "missing original_size for zstd-compressed secret".to_string(),
                )
            })?;
            let original_size = usize::try_from(original_size).map_err(|_| {
                VaultickError::Validation(
                    "original_size for zstd-compressed secret is too large".to_string(),
                )
            })?;
            zstd::bulk::decompress(payload, original_size).map_err(|err| {
                VaultickError::Crypto(format!("failed to decompress zstd secret: {err}"))
            })
        }
    }
}
