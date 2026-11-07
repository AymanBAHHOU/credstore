//! Input checks for HTTP requests (spec 6.6), before policy is consulted.
//!
//! The URL is parsed strictly here, and only URLs whose authority is unambiguous are
//! accepted (no user info, no backslashes, no whitespace, no percent-encoding in the
//! host), so the host that policy checks is the host the request goes to. The daemon
//! checks again with the HTTP library's own parser before sending anything.
//!
//! Errors describe what is wrong without echoing header values or the body: they may
//! contain something the agent pasted by mistake.

use credstore_proto::{HttpHeader, HttpRequest};

use crate::names;
use crate::request::{check_reason, RequestError};

pub const MAX_URL_BYTES: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 32;
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// Placeholder for the secret in `header_template`.
pub const PLACEHOLDER: &str = "{value}";

/// Headers the agent may not set: they belong to the connection or the transport.
const RESERVED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

fn bad(m: impl Into<String>) -> RequestError {
    RequestError(m.into())
}

/// A checked HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedHttp {
    pub method: String,
    /// Lowercase host name, or an IPv6 literal without brackets.
    pub host: String,
    /// Explicit port, or 443.
    pub port: u16,
    /// Name of the header that carries the secret.
    pub header_name: String,
    /// Header value before and after `{value}`.
    pub prefix: String,
    pub suffix: String,
}

impl CheckedHttp {
    /// `host` or `host:port` (port only when not 443), as `allow_hosts` lists it.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Check shape and sizes of an HTTP request.
pub fn check(req: &HttpRequest) -> Result<CheckedHttp, RequestError> {
    let method = req.method.trim().to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(bad(format!("method must be one of {}", METHODS.join(", "))));
    }
    if matches!(method.as_str(), "GET" | "HEAD") && req.body.is_some() {
        return Err(bad(format!("a {method} request cannot have a body")));
    }
    names::validate_name(&req.secret).map_err(|e| bad(format!("secret: {e}")))?;
    check_reason(&req.reason)?;
    let (host, port) = parse_url(&req.url)?;
    let (header_name, prefix, suffix) = parse_template(&req.header_template)?;

    if req.headers.len() > MAX_HEADERS {
        return Err(bad(format!("at most {MAX_HEADERS} extra headers")));
    }
    for (i, h) in req.headers.iter().enumerate() {
        check_header(h).map_err(|e| bad(format!("headers[{i}]: {}", e.0)))?;
        let name = h.name.to_ascii_lowercase();
        if RESERVED.contains(&name.as_str()) {
            return Err(bad(format!("headers[{i}]: {} cannot be set", h.name)));
        }
        if name == header_name.to_ascii_lowercase() {
            return Err(bad(format!(
                "headers[{i}]: {} is the header that carries the secret",
                h.name
            )));
        }
    }
    if let Some(body) = &req.body {
        if body.len() > MAX_BODY_BYTES {
            return Err(bad(format!("body is longer than {MAX_BODY_BYTES} bytes")));
        }
    }
    if req.timeout_secs == Some(0) {
        return Err(bad("timeout_secs must be at least 1"));
    }
    Ok(CheckedHttp {
        method,
        host,
        port,
        header_name,
        prefix,
        suffix,
    })
}

/// `https://host[:port][/path][?query]`, with a plain host name or IP literal.
fn parse_url(url: &str) -> Result<(String, u16), RequestError> {
    if url.len() > MAX_URL_BYTES {
        return Err(bad(format!("url is longer than {MAX_URL_BYTES} bytes")));
    }
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || !c.is_ascii())
    {
        return Err(bad(
            "url must be ASCII without spaces, control characters or backslashes \
             (percent-encode the path and query)",
        ));
    }
    let Some(rest) = url
        .get(..8)
        .filter(|s| s.eq_ignore_ascii_case("https://"))
        .map(|_| &url[8..])
    else {
        return Err(bad("url must start with https://"));
    };
    if url.contains('#') {
        return Err(bad("url must not have a #fragment"));
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return Err(bad("url must not contain user info (user@host)"));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let close = v6
            .find(']')
            .ok_or_else(|| bad("url has an unclosed [ in the host"))?;
        let host = &v6[..close];
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Err(bad("url host is not a valid IPv6 address"));
        }
        let port = match &v6[close + 1..] {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or_else(|| bad("url has junk after the host"))?,
            ),
        };
        (host.to_ascii_lowercase(), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let valid = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        if !valid {
            return Err(bad("url host must be a plain host name"));
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => 443,
        // Digits only, no leading zero, so the library cannot read it differently.
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|n| *n != 0 && n.to_string() == p)
            .ok_or_else(|| bad("url port is not a number from 1 to 65535"))?,
    };
    Ok((host, port))
}

/// `Name: before{value}after` -> (name, before, after).
fn parse_template(t: &str) -> Result<(String, String, String), RequestError> {
    let (name, value) = t
        .split_once(':')
        .ok_or_else(|| bad("header_template must look like \"Authorization: Bearer {value}\""))?;
    let name = name.trim();
    let value = value.trim();
    check_header_name(name).map_err(|e| bad(format!("header_template: {}", e.0)))?;
    if RESERVED.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(bad(format!(
            "header_template: {name} cannot carry a secret"
        )));
    }
    if value.matches(PLACEHOLDER).count() != 1 {
        return Err(bad("header_template must contain {value} exactly once"));
    }
    check_header_value(value).map_err(|e| bad(format!("header_template: {}", e.0)))?;
    let (prefix, suffix) = value.split_once(PLACEHOLDER).unwrap_or((value, ""));
    Ok((name.to_owned(), prefix.to_owned(), suffix.to_owned()))
}

fn check_header(h: &HttpHeader) -> Result<(), RequestError> {
    check_header_name(&h.name)?;
    check_header_value(&h.value)?;
    if h.name.len() + h.value.len() > MAX_HEADER_BYTES {
        return Err(bad(format!("longer than {MAX_HEADER_BYTES} bytes")));
    }
    Ok(())
}

fn check_header_name(n: &str) -> Result<(), RequestError> {
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if n.is_empty() || n.len() > 256 || !n.chars().all(token) {
        return Err(bad("header name is not a valid HTTP token"));
    }
    Ok(())
}

fn check_header_value(v: &str) -> Result<(), RequestError> {
    if v.len() > MAX_HEADER_BYTES || v.chars().any(|c| c.is_control() && c != '\t') {
        return Err(bad("header value has control characters or is too long"));
    }
    Ok(())
}

/// Whether `allow_hosts` lets a request reach `host:port`. An entry is `host`,
/// `host:port` or `*.domain` (any subdomain, not the domain itself); without a port it
/// means 443. Case-insensitive.
pub fn host_allowed(allow_hosts: &[String], host: &str, port: u16) -> bool {
    allow_hosts.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        let (h, p) = match entry.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_owned(), p.parse::<u16>().ok()),
            _ => (entry.clone(), Some(443)),
        };
        if p != Some(port) {
            return false;
        }
        match h.strip_prefix("*.") {
            Some(domain) => host.len() > domain.len() + 1 && host.ends_with(&format!(".{domain}")),
            None => host == h,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE: &str = "FAKE-SECRET-VALUE-12345";

    fn ok() -> HttpRequest {
        HttpRequest {
            method: "get".into(),
            url: "https://API.example.com/v1/prices?code=BRENT".into(),
            secret: "OIL_KEY".into(),
            header_template: "Authorization: Token {value}".into(),
            reason: "Fetch the latest oil price".into(),
            headers: vec![HttpHeader {
                name: "Accept".into(),
                value: "application/json".into(),
            }],
            body: None,
            timeout_secs: None,
        }
    }

    #[test]
    fn accepts_a_normal_request() {
        let c = check(&ok()).unwrap();
        assert_eq!(c.method, "GET");
        assert_eq!(c.host, "api.example.com");
        assert_eq!(c.port, 443);
        assert_eq!(c.header_name, "Authorization");
        assert_eq!((c.prefix.as_str(), c.suffix.as_str()), ("Token ", ""));
        assert_eq!(c.authority(), "api.example.com");
    }

    #[test]
    fn parses_ports_and_ipv6() {
        let mut r = ok();
        r.url = "https://api.example.com:8443".into();
        assert_eq!(check(&r).unwrap().authority(), "api.example.com:8443");
        r.url = "https://[::1]:9000/x".into();
        let c = check(&r).unwrap();
        assert_eq!((c.host.as_str(), c.port), ("::1", 9000));
        assert_eq!(c.authority(), "[::1]:9000");
    }

    #[test]
    fn rejects_bad_requests_without_echoing_them() {
        type Edit = Box<dyn Fn(&mut HttpRequest)>;
        let cases: Vec<(&str, Edit, &str)> = vec![
            (
                "plain http",
                Box::new(|r| r.url = "http://api.example.com/".into()),
                "https://",
            ),
            (
                "user info",
                Box::new(|r| r.url = format!("https://{FAKE}@evil.example/")),
                "user info",
            ),
            (
                "backslash host trick",
                Box::new(|r| r.url = "https://api.example.com\\@evil.example/".into()),
                "backslashes",
            ),
            (
                "space",
                Box::new(|r| r.url = "https://api.example.com/a b".into()),
                "spaces",
            ),
            (
                "percent host",
                Box::new(|r| r.url = "https://api%2eexample.com/".into()),
                "plain host",
            ),
            (
                "fragment",
                Box::new(|r| r.url = "https://api.example.com/#x".into()),
                "fragment",
            ),
            (
                "empty host",
                Box::new(|r| r.url = "https:///x".into()),
                "plain host",
            ),
            (
                "bad port",
                Box::new(|r| r.url = "https://api.example.com:0/".into()),
                "port",
            ),
            (
                "port junk",
                Box::new(|r| r.url = "https://api.example.com:443x/".into()),
                "port",
            ),
            (
                "leading zero port",
                Box::new(|r| r.url = "https://api.example.com:0443/".into()),
                "port",
            ),
            (
                "method",
                Box::new(|r| r.method = "CONNECT".into()),
                "method",
            ),
            (
                "GET with body",
                Box::new(|r| r.body = Some("x".into())),
                "cannot have a body",
            ),
            (
                "no placeholder",
                Box::new(|r| r.header_template = format!("Authorization: {FAKE}")),
                "exactly once",
            ),
            (
                "two placeholders",
                Box::new(|r| r.header_template = "X: {value}{value}".into()),
                "exactly once",
            ),
            (
                "no colon",
                Box::new(|r| r.header_template = "Bearer {value}".into()),
                "header_template",
            ),
            (
                "reserved secret header",
                Box::new(|r| r.header_template = "Host: {value}".into()),
                "cannot carry",
            ),
            (
                "newline in template",
                Box::new(|r| r.header_template = "X: a\r\nY: {value}".into()),
                "control",
            ),
            (
                "override the secret header",
                Box::new(|r| {
                    r.headers.push(HttpHeader {
                        name: "authorization".into(),
                        value: FAKE.into(),
                    })
                }),
                "carries the secret",
            ),
            (
                "reserved header",
                Box::new(|r| {
                    r.headers.push(HttpHeader {
                        name: "Host".into(),
                        value: "evil.example".into(),
                    })
                }),
                "cannot be set",
            ),
            (
                "header injection",
                Box::new(|r| {
                    r.headers.push(HttpHeader {
                        name: "X".into(),
                        value: format!("{FAKE}\r\nHost: evil"),
                    })
                }),
                "control",
            ),
            (
                "bad secret name",
                Box::new(|r| r.secret = "lower".into()),
                "secret",
            ),
            (
                "short reason",
                Box::new(|r| r.reason = "x".into()),
                "reason",
            ),
            (
                "zero timeout",
                Box::new(|r| r.timeout_secs = Some(0)),
                "timeout",
            ),
        ];
        for (name, edit, want) in cases {
            let mut r = ok();
            edit(&mut r);
            let err = check(&r).expect_err(name).to_string();
            assert!(
                err.contains(want),
                "{name}: {err:?} should mention {want:?}"
            );
            assert!(!err.contains(FAKE), "{name}: the error echoes input");
        }
    }

    #[test]
    fn matches_allow_hosts() {
        let hosts: Vec<String> = ["api.example.com", "*.stripe.com", "localhost:8443"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(host_allowed(&hosts, "api.example.com", 443));
        assert!(!host_allowed(&hosts, "api.example.com", 8443));
        assert!(!host_allowed(&hosts, "evil-api.example.com", 443));
        assert!(!host_allowed(&hosts, "api.example.com.evil.example", 443));
        assert!(host_allowed(&hosts, "api.stripe.com", 443));
        assert!(!host_allowed(&hosts, "stripe.com", 443));
        assert!(!host_allowed(&hosts, "evilstripe.com", 443));
        assert!(host_allowed(&hosts, "localhost", 8443));
        assert!(!host_allowed(&hosts, "localhost", 443));
    }
}
