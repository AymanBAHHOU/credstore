//! Output redaction (spec 6.5).
//!
//! Every form listed in the spec is replaced with `[REDACTED:NAME]`: the exact value, the
//! value without a trailing newline, URL-encoded (upper and lower hex, `+` or `%20` for
//! spaces), base64 in all three alignments (standard and URL-safe alphabets), hex (lower
//! and upper), JSON-escaped, and each line of a multi-line value. Values shorter than
//! [`MIN_REDACTABLE_LEN`] are skipped (they would mask too much ordinary output; `set`
//! warns about them).
//!
//! This catches accidental leaks. It does not stop a command that deliberately encodes
//! a value some other way (reversed, rot13, split up, compressed); see the threat model.

use zeroize::Zeroizing;

use credstore_proto::SecretText;

use crate::vault::MIN_REDACTABLE_LEN;

/// Shortest encoded form worth matching. Shorter fragments (from short base64 tails)
/// would hit ordinary output.
const MIN_PATTERN_LEN: usize = 6;

struct Pattern {
    bytes: Zeroizing<Vec<u8>>,
    /// Index into `names`.
    secret: usize,
}

/// Replaces every known encoding of a set of secret values.
pub struct Redactor {
    names: Vec<String>,
    /// Longest first, so a longer form wins over a shorter one at the same position.
    patterns: Vec<Pattern>,
    /// For each first byte, the patterns starting with it (indices into `patterns`).
    by_first: Vec<Vec<usize>>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("names", &self.names)
            .field("patterns", &self.patterns.len())
            .finish()
    }
}

impl Redactor {
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a SecretText)>) -> Self {
        let mut names = Vec::new();
        let mut patterns: Vec<Pattern> = Vec::new();
        for (name, value) in secrets {
            let idx = names.len();
            names.push(name.to_owned());
            let v = value.expose();
            if v.chars().count() < MIN_REDACTABLE_LEN {
                continue;
            }
            for form in forms(v.as_bytes()) {
                if form.len() >= MIN_PATTERN_LEN
                    && !patterns
                        .iter()
                        .any(|p| p.bytes.as_slice() == form.as_slice())
                {
                    patterns.push(Pattern {
                        bytes: form,
                        secret: idx,
                    });
                }
            }
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.bytes.len()));
        let mut by_first = vec![Vec::new(); 256];
        for (i, p) in patterns.iter().enumerate() {
            by_first[usize::from(p.bytes[0])].push(i);
        }
        Self {
            names,
            patterns,
            by_first,
        }
    }

    /// Replace every occurrence; returns the new text and the number of replacements.
    pub fn redact(&self, input: &[u8]) -> (Zeroizing<Vec<u8>>, u64) {
        let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
        let mut count = 0;
        let mut i = 0;
        while i < input.len() {
            match self.match_at(input, i) {
                Some(p) => {
                    out.extend_from_slice(self.marker(p.secret).as_bytes());
                    i += p.bytes.len();
                    count += 1;
                }
                None => {
                    out.push(input[i]);
                    i += 1;
                }
            }
        }
        (out, count)
    }

    /// For output that was cut off: also mask a trailing fragment that could be the start
    /// of a secret, since the rest of it was never captured.
    pub fn redact_truncated(&self, input: &[u8]) -> (Zeroizing<Vec<u8>>, u64) {
        let (mut out, mut count) = self.redact(input);
        let tail = self
            .patterns
            .iter()
            .filter_map(|p| {
                let max = (p.bytes.len() - 1).min(out.len());
                (1..=max)
                    .rev()
                    .find(|&k| out[out.len() - k..] == p.bytes[..k])
                    .map(|k| (k, p.secret))
            })
            .max_by_key(|(k, _)| *k);
        if let Some((k, secret)) = tail {
            let keep = out.len() - k;
            out.truncate(keep);
            out.extend_from_slice(self.marker(secret).as_bytes());
            count += 1;
        }
        (out, count)
    }

    /// Redact text (error messages); invalid UTF-8 from the replacement can't happen.
    pub fn redact_str(&self, s: &str) -> (String, u64) {
        let (b, n) = self.redact(s.as_bytes());
        (String::from_utf8_lossy(&b).into_owned(), n)
    }

    fn match_at(&self, input: &[u8], i: usize) -> Option<&Pattern> {
        self.by_first[usize::from(input[i])]
            .iter()
            .map(|&p| &self.patterns[p])
            .find(|p| input[i..].starts_with(&p.bytes))
    }

    fn marker(&self, secret: usize) -> String {
        format!("[REDACTED:{}]", self.names[secret])
    }
}

/// Every encoded form of `v` that is redacted.
fn forms(v: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut add = |f: Vec<u8>| out.push(Zeroizing::new(f));

    let trimmed = trim_newlines(v);
    for base in [v, trimmed] {
        add(base.to_vec());
        add(url_encode(base, false, false));
        add(url_encode(base, true, false));
        add(url_encode(base, false, true));
        add(hex(base, false));
        add(hex(base, true));
        add(json_escape(base));
        for align in 0..3 {
            add(base64_aligned(base, align, STD));
            add(base64_aligned(base, align, URL_SAFE));
        }
    }
    // Each line of a multi-line value.
    if trimmed.contains(&b'\n') {
        for line in trimmed.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.len() >= MIN_REDACTABLE_LEN {
                add(line.to_vec());
            }
        }
    }
    out
}

fn trim_newlines(v: &[u8]) -> &[u8] {
    let mut end = v.len();
    while end > 0 && matches!(v[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &v[..end]
}

fn url_encode(v: &[u8], lower: bool, plus_for_space: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if lower {
        b"0123456789abcdef"
    } else {
        b"0123456789ABCDEF"
    };
    let mut out = Vec::with_capacity(v.len() * 3);
    for &b in v {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b),
            b' ' if plus_for_space => out.push(b'+'),
            _ => {
                out.push(b'%');
                out.push(digits[usize::from(b >> 4)]);
                out.push(digits[usize::from(b & 15)]);
            }
        }
    }
    out
}

fn hex(v: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    v.iter()
        .flat_map(|&b| [digits[usize::from(b >> 4)], digits[usize::from(b & 15)]])
        .collect()
}

fn json_escape(v: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(v);
    let quoted = serde_json::to_string(&s).unwrap_or_default();
    quoted
        .strip_prefix('"')
        .and_then(|q| q.strip_suffix('"'))
        .unwrap_or("")
        .as_bytes()
        .to_vec()
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The base64 characters that depend only on `v` when `v` starts `align` bytes into a
/// 3-byte group: characters that mix in bytes before or after `v` are dropped.
fn base64_aligned(v: &[u8], align: usize, alphabet: &[u8; 64]) -> Vec<u8> {
    let mut data = vec![0u8; align];
    data.extend_from_slice(v);
    let mut chars = Vec::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for k in 0..4 {
            chars.push(alphabet[((n >> (18 - 6 * k)) & 63) as usize]);
        }
    }
    let total_bits = data.len() * 8;
    let start = (align * 8).div_ceil(6);
    let end = total_bits / 6; // characters fully determined by `data`
    let out = chars.get(start..end).unwrap_or_default().to_vec();
    zeroize::Zeroize::zeroize(&mut data);
    zeroize::Zeroize::zeroize(&mut chars);
    out
}

#[cfg(test)]
mod tests;
