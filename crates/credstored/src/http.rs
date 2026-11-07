//! `http_request` (spec 6.6, M11): the daemon makes an HTTPS request itself, with one
//! secret in one header, and returns the redacted response. The secret never enters a
//! process the agent controls, so even an approved request cannot leak it anywhere but
//! the hosts in the secret's `allow_hosts`.
//!
//! The request goes out exactly as approved: HTTPS only, no redirects followed (a 3xx
//! comes back as is), no proxy from the environment, the URL's host checked against
//! policy and again against the HTTP library's own parse of the URL.

use std::io::Read;
use std::time::{Duration, Instant};

use credstore_core::http::{self as httpcheck, CheckedHttp};
use credstore_core::policy::Effective;
use credstore_core::redact::Redactor;
use credstore_core::util::new_id;
use credstore_core::vault::VaultError;
use credstore_proto::{
    ErrorCode, HttpHeader, HttpRequest, HttpResult, PeerInfo, PendingHttp, Response, SecretInfo,
    SecretText,
};
use serde_json::json;

use crate::approvals::Values;
use crate::state::{error, peer_json, State};

/// Longest body preview shown to the human.
const BODY_PREVIEW_CHARS: usize = 400;

/// An HTTP request that passed validation and policy, ready for approval.
#[derive(Debug, Clone)]
pub(crate) struct PreparedHttp {
    pub id: String,
    pub req: HttpRequest,
    pub checked: CheckedHttp,
    /// `[req.secret]`, for code shared with runs.
    pub secret_names: Vec<String>,
    pub secret: SecretInfo,
    pub effective: Effective,
}

impl PreparedHttp {
    pub fn pending(&self) -> PendingHttp {
        let body = self.req.body.as_deref();
        PendingHttp {
            method: self.checked.method.clone(),
            url: self.req.url.clone(),
            header_template: self.req.header_template.clone(),
            headers: self.req.headers.clone(),
            body_bytes: body.map(|b| b.len() as u64),
            body_preview: body.map(|b| {
                let mut p: String = b.chars().take(BODY_PREVIEW_CHARS).collect();
                if b.chars().count() > BODY_PREVIEW_CHARS {
                    p.push('…');
                }
                p
            }),
        }
    }
}

impl State {
    /// Validate an HTTP request and check it against policy. Denials are audited and
    /// returned as `Response::Denied`; malformed requests as `Response::Error`.
    pub async fn prepare_http(
        &self,
        req: HttpRequest,
        peer: &PeerInfo,
    ) -> Result<PreparedHttp, Response> {
        let checked =
            httpcheck::check(&req).map_err(|e| error(ErrorCode::BadRequest, e.to_string()))?;
        let known = match self.vault.list() {
            Ok(k) => k,
            Err(VaultError::Missing(_)) => {
                return Err(error(
                    ErrorCode::BadRequest,
                    "no vault yet; the human must run `credstore init`",
                ))
            }
            Err(e) => return Err(error(ErrorCode::Internal, e.to_string())),
        };
        let Some(secret) = known.into_iter().find(|s| s.name == req.secret) else {
            return Err(error(
                ErrorCode::BadRequest,
                format!("unknown secret {} (see list_secrets)", req.secret),
            ));
        };

        let id = new_id("req");
        let _ = self.audit(
            "request",
            Some(&id),
            json!({
                "kind": "http",
                "peer": peer_json(peer),
                "secrets": [req.secret],
                "method": checked.method,
                "url": req.url,
                "header": checked.header_name,
                // Names only: values may hold something the agent pasted by mistake.
                "headers": req.headers.iter().map(|h| &h.name).collect::<Vec<_>>(),
                "body_bytes": req.body.as_ref().map(String::len),
                "reason": req.reason,
                "injection": "header",
            }),
        );
        let deny = |why: String| {
            let _ = self.audit(
                "policy_denied",
                Some(&id),
                json!({"peer": peer_json(peer), "denial": why}),
            );
            Response::Denied {
                reason: format!("denied by policy: {why}"),
            }
        };
        let pol = self
            .policy()
            .map_err(|e| deny(format!("no valid policy is loaded ({e})")))?;
        let effective = pol
            .evaluate_http(&req.secret, &checked.host, checked.port, req.timeout_secs)
            .map_err(|d| deny(d.0))?;

        Ok(PreparedHttp {
            id,
            secret_names: vec![req.secret.clone()],
            req,
            checked,
            secret,
            effective,
        })
    }

    /// Send an approved HTTP request and return the redacted response.
    pub async fn execute_http(&self, p: PreparedHttp, values: Values) -> Response {
        let id = p.id.clone();
        let Some((_, value)) = values.into_iter().next() else {
            return error(ErrorCode::Internal, "no value for the approved secret");
        };
        let redactor = Redactor::new([(p.req.secret.as_str(), &value)]);

        if let Err(e) = self.audit(
            "http_sent",
            Some(&id),
            json!({
                "method": p.checked.method,
                "host": p.checked.authority(),
                "timeout_secs": p.effective.timeout_secs,
            }),
        ) {
            return error(
                ErrorCode::Internal,
                format!("the audit log cannot be written, so the request was not sent: {e}"),
            );
        }
        tracing::info!(id, host = %p.checked.authority(), "http request sent");

        let started = Instant::now();
        let max = usize::try_from(p.effective.max_output_bytes).unwrap_or(usize::MAX);
        let req = p.req.clone();
        let checked = p.checked.clone();
        let timeout = Duration::from_secs(p.effective.timeout_secs);
        let outcome =
            tokio::task::spawn_blocking(move || send(&req, &checked, value, timeout, max)).await;
        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => Err(format!("the request task failed: {e}")),
        };

        let resp = match outcome {
            Ok(raw) => {
                let (body, n_body) = if raw.truncated {
                    redactor.redact_truncated(&raw.body)
                } else {
                    redactor.redact(&raw.body)
                };
                let mut redactions = n_body;
                let headers = raw
                    .headers
                    .into_iter()
                    .map(|(name, v)| {
                        let (value, n) = redactor.redact_str(&v);
                        redactions += n;
                        HttpHeader { name, value }
                    })
                    .collect();
                let _ = self.audit(
                    "http_finished",
                    Some(&id),
                    json!({
                        "ok": true,
                        "status": raw.status,
                        "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        "body_bytes": raw.body.len(),
                        "truncated": raw.truncated,
                        "redactions": redactions,
                    }),
                );
                Response::HttpResult(HttpResult {
                    status: raw.status,
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                    truncated: raw.truncated,
                    redactions,
                })
            }
            Err(why) => {
                let (why, _) = redactor.redact_str(&why);
                let _ = self.audit(
                    "http_finished",
                    Some(&id),
                    json!({"ok": false, "error": why}),
                );
                error(ErrorCode::Internal, format!("the request failed: {why}"))
            }
        };
        let idle = *self.idle_ttl.lock().unwrap_or_else(|p| p.into_inner());
        if idle.is_zero() {
            self.relock("after-run");
        }
        resp
    }
}

struct Raw {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    truncated: bool,
}

/// Blocking: build the request, check the library parses the same host, send, read up
/// to `max` bytes of body.
fn send(
    req: &HttpRequest,
    checked: &CheckedHttp,
    value: SecretText,
    timeout: Duration,
    max: usize,
) -> Result<Raw, String> {
    use ureq::http::{header::HeaderName, HeaderValue, Method, Request, Uri};

    let uri: Uri = req.url.parse().map_err(|_| "the URL could not be parsed")?;
    let host = uri.host().map(|h| {
        h.trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase()
    });
    if uri.scheme_str() != Some("https")
        || host.as_deref() != Some(checked.host.as_str())
        || uri.port_u16().unwrap_or(443) != checked.port
    {
        return Err("the URL parses differently than it was checked; not sent".into());
    }

    let method = Method::from_bytes(checked.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut builder = Request::builder().method(method).uri(uri);
    for h in &req.headers {
        builder = builder.header(h.name.as_str(), h.value.as_str());
    }
    let name = HeaderName::from_bytes(checked.header_name.as_bytes()).map_err(|e| e.to_string())?;
    let line = SecretText::new(format!(
        "{}{}{}",
        checked.prefix,
        value.expose(),
        checked.suffix
    ));
    drop(value);
    // The header value is a plain buffer inside the HTTP library; it lives only until
    // the request is written.
    let mut secret_header = HeaderValue::from_str(line.expose())
        .map_err(|_| "the secret cannot go in an HTTP header (it has control characters)")?;
    drop(line);
    secret_header.set_sensitive(true);
    builder = builder.header(name, secret_header);

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .proxy(None)
        .timeout_global(Some(timeout))
        .user_agent("credstore")
        .build()
        .into();
    let response = match &req.body {
        None => agent.run(builder.body(()).map_err(|e| e.to_string())?),
        Some(b) => agent.run(builder.body(b.as_bytes()).map_err(|e| e.to_string())?),
    }
    .map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let mut body = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(max as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("reading the response: {e}"))?;
    let truncated = body.len() > max;
    body.truncate(max);
    Ok(Raw {
        status,
        headers,
        body,
        truncated,
    })
}
