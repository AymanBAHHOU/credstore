//! Hash-chained, append-only audit log (spec 5.3).
//!
//! One JSON object per line. Each record carries `prev` (the previous record's hash, or
//! 64 zeros for the first) and `hash = sha256(prev || canonical_json_without_hash)`,
//! hex-encoded. Canonical JSON sorts object keys recursively and has no whitespace, so
//! it does not depend on serde_json's map ordering features.
//!
//! Never put secret values or environment dumps in a record.

use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// `prev` of the first record.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Os(#[from] credstore_os::OsError),
}

/// Open handle for appending.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: File,
    prev: String,
}

impl AuditLog {
    /// Open (or create) the log and find the hash to chain from.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        if let Some(dir) = path.parent() {
            credstore_os::fs::create_private_dir(dir)?;
        }
        let mut file = credstore_os::fs::open_append_private(path)?;
        let (prev, ends_with_newline) = last_hash(&mut file)?;
        if !ends_with_newline {
            // A crash left a partial line. Start a fresh line; `verify` reports the
            // damaged one.
            file.write_all(b"\n")?;
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            prev,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and fsync it. `fields` must not contain `ts`, `event`, `prev`
    /// or `hash`; those are set here.
    pub fn append(
        &mut self,
        event: &str,
        id: Option<&str>,
        fields: Map<String, Value>,
    ) -> Result<(), AuditError> {
        let mut rec = fields;
        rec.insert(
            "ts".into(),
            Value::String(crate::util::now_rfc3339_millis()),
        );
        rec.insert("event".into(), Value::String(event.into()));
        if let Some(id) = id {
            rec.insert("id".into(), Value::String(id.into()));
        }
        rec.insert("prev".into(), Value::String(self.prev.clone()));
        rec.remove("hash");
        let hash = record_hash(&self.prev, &Value::Object(rec.clone()));
        rec.insert("hash".into(), Value::String(hash.clone()));

        let mut line = canonical_json(&Value::Object(rec));
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        self.prev = hash;
        Ok(())
    }
}

/// `sha256(prev || canonical_json(record))`, where `record` excludes `hash`.
pub fn record_hash(prev: &str, record_without_hash: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(canonical_json(record_without_hash).as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sorted keys, no whitespace, serde_json string escaping.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Hash of the last complete record, and whether the file ends with a newline.
fn last_hash(file: &mut File) -> std::io::Result<(String, bool)> {
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok((GENESIS.into(), true));
    }
    let start = len.saturating_sub(1024 * 1024);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    file.seek(SeekFrom::End(0))?;
    let ends_with_newline = tail.last() == Some(&b'\n');
    for line in tail.split(|b| *b == b'\n').rev() {
        if let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(line) {
            if let Some(Value::String(h)) = m.get("hash") {
                return Ok((h.clone(), ends_with_newline));
            }
        }
    }
    Ok((GENESIS.into(), ends_with_newline))
}

/// Result of walking the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: usize,
    pub first_break: Option<ChainBreak>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// 1-based line number.
    pub line: usize,
    pub reason: String,
}

/// Re-walk the chain from the first line and report the first break.
pub fn verify(reader: impl BufRead) -> std::io::Result<VerifyReport> {
    let mut prev = GENESIS.to_string();
    let mut entries = 0;
    for (i, line) in reader.split(b'\n').enumerate() {
        let line = line?;
        let n = i + 1;
        let brk = |reason: &str| {
            Ok(VerifyReport {
                entries,
                first_break: Some(ChainBreak {
                    line: n,
                    reason: reason.into(),
                }),
            })
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(Value::Object(mut rec)) = serde_json::from_slice::<Value>(&line) else {
            return brk("not a JSON object (damaged or partial line)");
        };
        let Some(Value::String(hash)) = rec.remove("hash") else {
            return brk("missing hash");
        };
        match rec.get("prev") {
            Some(Value::String(p)) if *p == prev => {}
            Some(Value::String(_)) => {
                return brk(
                    "prev does not match the previous record (a record was removed, \
                     inserted or reordered)",
                );
            }
            _ => return brk("missing prev"),
        }
        if record_hash(&prev, &Value::Object(rec)) != hash {
            return brk("hash mismatch (the record was modified)");
        }
        prev = hash;
        entries += 1;
    }
    Ok(VerifyReport {
        entries,
        first_break: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs::OpenOptions;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "credstore-audit-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .join("audit.jsonl")
    }

    fn fields(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn write_three(path: &Path) {
        let mut log = AuditLog::open(path).unwrap();
        log.append(
            "request",
            Some("req_1"),
            fields(json!({"secrets": ["STRIPE_KEY"], "argv": ["curl", "-s"], "peer": {"uid": 1000, "pid": 42}})),
        )
        .unwrap();
        log.append("approved", Some("req_1"), fields(json!({"scope": "once"})))
            .unwrap();
        log.append("unlock", None, Map::new()).unwrap();
    }

    fn verify_file(path: &Path) -> VerifyReport {
        verify(std::io::BufReader::new(File::open(path).unwrap())).unwrap()
    }

    #[test]
    fn chain_verifies_and_survives_reopen() {
        let p = tmp("ok");
        write_three(&p);
        // Reopen and continue the chain.
        AuditLog::open(&p)
            .unwrap()
            .append("lock", None, Map::new())
            .unwrap();
        let r = verify_file(&p);
        assert_eq!(r.first_break, None);
        assert_eq!(r.entries, 4);
        let first: Value =
            serde_json::from_str(std::fs::read_to_string(&p).unwrap().lines().next().unwrap())
                .unwrap();
        assert_eq!(first["prev"], GENESIS);
        assert_eq!(first["event"], "request");
        assert!(first["ts"].as_str().unwrap().ends_with('Z'));
    }

    fn rewrite(p: &Path, f: impl FnOnce(&mut Vec<String>)) {
        let mut lines: Vec<String> = std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        f(&mut lines);
        std::fs::write(p, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn modified_record_is_detected() {
        let p = tmp("mod");
        write_three(&p);
        rewrite(&p, |l| l[1] = l[1].replace("once", "session"));
        let b = verify_file(&p).first_break.unwrap();
        assert_eq!(b.line, 2);
        assert!(b.reason.contains("modified"), "{b:?}");
    }

    #[test]
    fn removed_record_is_detected() {
        let p = tmp("del");
        write_three(&p);
        rewrite(&p, |l| {
            l.remove(1);
        });
        let b = verify_file(&p).first_break.unwrap();
        assert_eq!(b.line, 2);
        assert!(b.reason.contains("prev"), "{b:?}");
    }

    #[test]
    fn reordered_and_garbage_lines_are_detected() {
        let p = tmp("swap");
        write_three(&p);
        rewrite(&p, |l| l.swap(0, 1));
        assert_eq!(verify_file(&p).first_break.unwrap().line, 1);

        let p = tmp("junk");
        write_three(&p);
        rewrite(&p, |l| l.insert(2, "not json".into()));
        assert_eq!(verify_file(&p).first_break.unwrap().line, 3);
    }

    #[test]
    fn recomputed_hash_with_wrong_prev_is_detected() {
        // An attacker edits a record and recomputes its own hash; the next record's
        // prev no longer matches.
        let p = tmp("forge");
        write_three(&p);
        rewrite(&p, |l| {
            let mut rec: Map<String, Value> = serde_json::from_str(&l[0]).unwrap();
            rec.insert("argv".into(), json!(["harmless"]));
            rec.remove("hash");
            let h = record_hash(GENESIS, &Value::Object(rec.clone()));
            rec.insert("hash".into(), Value::String(h));
            l[0] = canonical_json(&Value::Object(rec));
        });
        let b = verify_file(&p).first_break.unwrap();
        assert_eq!(b.line, 2, "{b:?}");
    }

    #[test]
    fn partial_last_line_is_reported_and_log_continues() {
        let p = tmp("partial");
        write_three(&p);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(br#"{"event":"run_sta"#).unwrap();
        drop(f);
        AuditLog::open(&p)
            .unwrap()
            .append("lock", None, Map::new())
            .unwrap();
        let b = verify_file(&p).first_break.unwrap();
        assert_eq!(b.line, 4);
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = json!({"b": 1, "a": {"d": [1, {"z": 1, "y": 2}], "c": "x\"y"}});
        assert_eq!(
            canonical_json(&v),
            r#"{"a":{"c":"x\"y","d":[1,{"y":2,"z":1}]},"b":1}"#
        );
    }
}
