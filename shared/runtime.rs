use std::collections::HashMap;
use std::error::Error;
use std::io;

#[derive(Debug, Clone)]
pub struct SecretTemplateIndex {
    canonical_keys: HashMap<String, String>,
}

impl SecretTemplateIndex {
    pub fn new<I>(keys: I) -> Result<Self, Box<dyn Error>>
    where
        I: IntoIterator<Item = String>,
    {
        let mut canonical_keys = HashMap::new();

        for key in keys {
            let normalized = key.to_ascii_lowercase();
            if let Some(existing_key) = canonical_keys.insert(normalized, key.clone()) {
                return Err(io::Error::other(format!(
                    "cannot use placeholder resolution because secrets {existing_key} and {key} collide"
                ))
                .into());
            }
        }

        Ok(Self { canonical_keys })
    }

    pub fn canonical_key(&self, key: &str) -> Option<&str> {
        self.canonical_keys
            .get(&key.to_ascii_lowercase())
            .map(String::as_str)
    }

    #[allow(dead_code)]
    pub fn keys(&self) -> Vec<String> {
        let mut keys = self.canonical_keys.values().cloned().collect::<Vec<_>>();
        keys.sort();
        keys
    }
}

pub fn replace_secret_placeholders<F>(
    input: &str,
    mut resolve_secret: F,
) -> Result<String, Box<dyn Error>>
where
    F: FnMut(&str) -> Result<String, Box<dyn Error>>,
{
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(start_offset) = input[cursor..].find('$') {
        let start = cursor + start_offset;
        output.push_str(&input[cursor..start]);

        let Some(first_char) = input[start + 1..].chars().next() else {
            output.push('$');
            cursor = start + 1;
            break;
        };

        if !is_secret_placeholder_start(first_char) {
            output.push('$');
            cursor = start + 1;
            continue;
        }

        let mut end = start + 1 + first_char.len_utf8();
        for ch in input[end..].chars() {
            if is_secret_placeholder_continue(ch) {
                end += ch.len_utf8();
            } else {
                break;
            }
        }

        let secret_key = &input[start + 1..end];
        output.push_str(&resolve_secret(secret_key)?);
        cursor = end;
    }

    output.push_str(&input[cursor..]);
    Ok(output)
}

#[allow(dead_code)]
pub fn collect_secret_placeholders(input: &str) -> Vec<String> {
    let mut placeholders = Vec::new();
    let mut cursor = 0;

    while let Some(start_offset) = input[cursor..].find('$') {
        let start = cursor + start_offset;
        let Some(first_char) = input[start + 1..].chars().next() else {
            break;
        };

        if !is_secret_placeholder_start(first_char) {
            cursor = start + 1;
            continue;
        }

        let mut end = start + 1 + first_char.len_utf8();
        for ch in input[end..].chars() {
            if is_secret_placeholder_continue(ch) {
                end += ch.len_utf8();
            } else {
                break;
            }
        }

        placeholders.push(input[start + 1..end].to_string());
        cursor = end;
    }

    placeholders
}

#[derive(Debug, Clone)]
pub struct Redactor {
    patterns: Vec<Vec<u8>>,
    pending: Vec<u8>,
}

impl Redactor {
    pub fn new(redacted_values: &[String]) -> Self {
        let mut patterns = redacted_values
            .iter()
            .filter(|value| !value.is_empty())
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        patterns.dedup();

        Self {
            patterns,
            pending: Vec::new(),
        }
    }

    pub fn redact_chunk(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();

        for byte in bytes {
            self.pending.push(*byte);
            flush_redaction_pending(&mut output, &mut self.pending, &self.patterns, false);
        }

        output
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let mut output = Vec::new();
        flush_redaction_pending(&mut output, &mut self.pending, &self.patterns, true);
        output
    }
}

fn flush_redaction_pending(
    output: &mut Vec<u8>,
    pending: &mut Vec<u8>,
    patterns: &[Vec<u8>],
    eof: bool,
) {
    loop {
        if pending.is_empty() {
            return;
        }

        if let Some(pattern) = patterns
            .iter()
            .find(|pattern| pending.starts_with(pattern.as_slice()))
        {
            let waiting_for_longer_match = !eof
                && patterns.iter().any(|candidate| {
                    candidate.len() > pending.len() && candidate.starts_with(pending.as_slice())
                });

            if waiting_for_longer_match {
                return;
            }

            output.extend_from_slice(b"[REDACTED]");
            pending.drain(..pattern.len());
            continue;
        }

        let waiting_for_partial_match = !eof
            && patterns
                .iter()
                .any(|pattern| pattern.starts_with(pending.as_slice()));
        if waiting_for_partial_match {
            return;
        }

        output.push(pending[0]);
        pending.drain(..1);
    }
}

fn is_secret_placeholder_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_secret_placeholder_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::{
        Redactor, SecretTemplateIndex, collect_secret_placeholders, replace_secret_placeholders,
    };

    #[test]
    fn secret_template_index_detects_case_collisions() {
        let err = SecretTemplateIndex::new(vec!["TOKEN".to_string(), "token".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("collide"));
    }

    #[test]
    fn replace_secret_placeholders_resolves_multiple_values() {
        let rendered = replace_secret_placeholders("Bearer $token/$OTHER", |key| {
            Ok(match key {
                "token" => "abc".to_string(),
                "OTHER" => "xyz".to_string(),
                _ => unreachable!(),
            })
        })
        .unwrap();

        assert_eq!(rendered, "Bearer abc/xyz");
    }

    #[test]
    fn collect_secret_placeholders_ignores_invalid_dollar_sequences() {
        assert_eq!(
            collect_secret_placeholders("$TOKEN $5 $$ $other"),
            vec!["TOKEN".to_string(), "other".to_string()]
        );
    }

    #[test]
    fn redactor_masks_values_across_chunk_boundaries() {
        let mut redactor = Redactor::new(&["super-secret".to_string()]);
        let mut output = Vec::new();
        output.extend(redactor.redact_chunk(b"hello super-"));
        output.extend(redactor.redact_chunk(b"secret world"));
        output.extend(redactor.finish());

        assert_eq!(String::from_utf8(output).unwrap(), "hello [REDACTED] world");
    }
}
