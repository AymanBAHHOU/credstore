//! The app's activity history, built from audit records (spec 5.3).
//!
//! Records of one request share its `id`: `request`, then `policy_denied`, `approved` or
//! `denied`, then `run_finished` or `http_finished`. Audit records never hold secret
//! values, so neither does an entry. Strings that came from an agent (commands, URLs,
//! folders) are passed on as they are: the app shows them as plain text.

use std::collections::HashMap;

use credstore_proto::{ActivityEntry, ActivityKind, ActivityOutcome};
use serde_json::Value;

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `host` or `host:port` of an `https://` URL (port only when it is not 443).
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?.to_ascii_lowercase();
    let host = authority.strip_suffix(":443").unwrap_or(&authority);
    (!host.is_empty()).then(|| host.to_owned())
}

fn seconds(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
    }
}

/// Entries for the last `limit` requests and changes, most recent first. Lines that are
/// not JSON are skipped (the log may have been cut at the start of a read).
pub fn from_audit<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Vec<ActivityEntry> {
    let mut entries: Vec<ActivityEntry> = Vec::new();
    let mut by_id: HashMap<String, usize> = HashMap::new();
    for line in lines {
        let Ok(rec) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let event = text(&rec, "event").unwrap_or_default();
        let ts = text(&rec, "ts").unwrap_or_default();
        let id = text(&rec, "id");
        match (event.as_str(), id) {
            ("request", Some(id)) => {
                let http = rec.get("kind").and_then(Value::as_str) == Some("http");
                let (kind, summary, host) = if http {
                    let url = text(&rec, "url").unwrap_or_default();
                    let method = text(&rec, "method").unwrap_or_default();
                    (
                        ActivityKind::Http,
                        format!("{method} {url}"),
                        url_host(&url),
                    )
                } else {
                    let summary =
                        text(&rec, "shell").unwrap_or_else(|| strings(&rec, "argv").join(" "));
                    (ActivityKind::Run, summary, None)
                };
                by_id.insert(id.clone(), entries.len());
                entries.push(ActivityEntry {
                    id,
                    ts,
                    kind,
                    outcome: ActivityOutcome::Waiting,
                    summary,
                    secrets: strings(&rec, "secrets"),
                    detail: None,
                    host,
                    cwd: text(&rec, "cwd").filter(|c| !c.is_empty()),
                    via: None,
                });
            }
            (_, Some(id)) => {
                let Some(e) = by_id.get(&id).and_then(|&i| entries.get_mut(i)) else {
                    continue;
                };
                match event.as_str() {
                    "policy_denied" => {
                        e.outcome = ActivityOutcome::Refused;
                        e.detail = text(&rec, "denial");
                    }
                    "approved" => {
                        e.outcome = ActivityOutcome::Running;
                        e.via = text(&rec, "via");
                    }
                    "denied" => {
                        e.outcome = ActivityOutcome::Denied;
                        e.detail = Some(match text(&rec, "via").as_deref() {
                            Some("human") => "denied by you".into(),
                            Some("timeout") => "no answer in time".into(),
                            Some("shutdown") => "the service stopped".into(),
                            Some("disconnect") => "the agent hung up".into(),
                            Some(other) => other.to_owned(),
                            None => "denied".into(),
                        });
                    }
                    "run_finished" | "http_finished" => {
                        let ok = rec.get("ok").and_then(Value::as_bool) == Some(true);
                        let took = rec.get("duration_ms").and_then(Value::as_u64).map(seconds);
                        if !ok {
                            e.outcome = ActivityOutcome::Failed;
                            e.detail = text(&rec, "error");
                        } else if event == "http_finished" {
                            let status = rec.get("status").and_then(Value::as_u64).unwrap_or(0);
                            e.outcome = if (200..400).contains(&status) {
                                ActivityOutcome::Ok
                            } else {
                                ActivityOutcome::Failed
                            };
                            e.detail = Some(match took {
                                Some(t) => format!("HTTP {status} in {t}"),
                                None => format!("HTTP {status}"),
                            });
                        } else {
                            let code = rec.get("exit_code").and_then(Value::as_i64);
                            let timed_out =
                                rec.get("timed_out").and_then(Value::as_bool) == Some(true);
                            e.outcome = if code == Some(0) {
                                ActivityOutcome::Ok
                            } else {
                                ActivityOutcome::Failed
                            };
                            let how = match code {
                                _ if timed_out => "timed out".to_owned(),
                                Some(c) => format!("exit {c}"),
                                None => "killed".to_owned(),
                            };
                            e.detail = Some(match took {
                                Some(t) => format!("{how} after {t}"),
                                None => how,
                            });
                        }
                    }
                    _ => {}
                }
            }
            ("vault_changed", None) => {
                let secret = text(&rec, "secret").unwrap_or_default();
                let summary = match text(&rec, "action").as_deref() {
                    Some("init") => "Created the vault".to_owned(),
                    Some("set") => format!("Saved {secret}"),
                    Some("rm") => format!("Removed {secret}"),
                    Some("approval_key_added") => "Turned on Windows Hello approval".to_owned(),
                    Some("approval_key_removed") => "Turned off Windows Hello approval".to_owned(),
                    Some(other) => format!("Vault change: {other}"),
                    None => "Vault change".to_owned(),
                };
                entries.push(ActivityEntry {
                    id: String::new(),
                    ts,
                    kind: ActivityKind::Vault,
                    outcome: ActivityOutcome::Changed,
                    summary,
                    secrets: Vec::new(),
                    detail: None,
                    host: None,
                    cwd: None,
                    via: None,
                });
            }
            ("policy_changed", None) => {
                let summary = match text(&rec, "secret") {
                    Some(s) => format!("Changed the rules for {s}"),
                    None => "Changed the security settings".to_owned(),
                };
                entries.push(ActivityEntry {
                    id: String::new(),
                    ts,
                    kind: ActivityKind::Policy,
                    outcome: ActivityOutcome::Changed,
                    summary,
                    secrets: Vec::new(),
                    detail: text(&rec, "detail"),
                    host: None,
                    cwd: None,
                    via: None,
                });
            }
            ("auth_failed", None) => entries.push(ActivityEntry {
                id: String::new(),
                ts,
                kind: ActivityKind::Auth,
                outcome: ActivityOutcome::Failed,
                summary: "Wrong passphrase or approval key".to_owned(),
                secrets: Vec::new(),
                detail: None,
                host: None,
                cwd: None,
                via: None,
            }),
            _ => {}
        }
    }
    entries.reverse();
    entries.truncate(limit);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lines(recs: &[Value]) -> Vec<String> {
        recs.iter().map(Value::to_string).collect()
    }

    #[test]
    fn groups_records_by_request() {
        let recs = lines(&[
            json!({"ts":"t1","event":"request","id":"r1","argv":["curl","-s","x"],"secrets":["K"],"cwd":"/p"}),
            json!({"ts":"t2","event":"approved","id":"r1","via":"human"}),
            json!({"ts":"t3","event":"run_finished","id":"r1","ok":true,"exit_code":0,"duration_ms":1500}),
            json!({"ts":"t4","event":"request","id":"r2","kind":"http","method":"POST","url":"https://API.example.com:443/v1?q=1","secrets":["K"]}),
            json!({"ts":"t5","event":"policy_denied","id":"r2","denial":"K may not be sent to api.example.com:443"}),
            json!({"ts":"t6","event":"vault_changed","action":"set","secret":"K"}),
            "not json".into(),
            json!({"ts":"t7","event":"request","id":"r3","shell":"make deploy","secrets":["K"]}),
            json!({"ts":"t8","event":"denied","id":"r3","via":"timeout"}),
        ]);
        let a = from_audit(recs.iter().map(String::as_str), 10);
        assert_eq!(a.len(), 4);
        assert_eq!(a[0].summary, "make deploy");
        assert_eq!(a[0].outcome, ActivityOutcome::Denied);
        assert_eq!(a[0].detail.as_deref(), Some("no answer in time"));
        assert_eq!(a[1].summary, "Saved K");
        assert_eq!(a[2].outcome, ActivityOutcome::Refused);
        assert_eq!(a[2].host.as_deref(), Some("api.example.com"));
        assert_eq!(a[3].summary, "curl -s x");
        assert_eq!(a[3].outcome, ActivityOutcome::Ok);
        assert_eq!(a[3].detail.as_deref(), Some("exit 0 after 1.5 s"));
        assert_eq!(a[3].via.as_deref(), Some("human"));
        assert_eq!(a[3].cwd.as_deref(), Some("/p"));
        assert_eq!(from_audit(recs.iter().map(String::as_str), 2).len(), 2);
    }

    #[test]
    fn records_without_their_request_are_skipped() {
        let recs = lines(&[json!({"event":"approved","id":"gone"})]);
        assert!(from_audit(recs.iter().map(String::as_str), 10).is_empty());
    }

    #[test]
    fn hosts() {
        assert_eq!(url_host("https://a.b/c").as_deref(), Some("a.b"));
        assert_eq!(url_host("https://u@a.b:8443").as_deref(), Some("a.b:8443"));
        assert_eq!(url_host("nope"), None);
    }
}
