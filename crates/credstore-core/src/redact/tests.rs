use super::*;

const FAKE: &str = "FAKE-SECRET-VALUE-12345";
/// A second fake value whose URL and JSON forms differ from the raw value.
const ODD: &str = "fake value/with+odd \"chars\"&=";

fn r() -> Redactor {
    let a = SecretText::new(FAKE.into());
    let b = SecretText::new(ODD.into());
    Redactor::new([("API_KEY", &a), ("ODD_KEY", &b)])
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn std_b64(v: &[u8]) -> String {
    let mut out = String::new();
    for chunk in v.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for k in 0..4 {
            if k <= chunk.len() {
                out.push(STD[((n >> (18 - 6 * k)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn exact_value_and_count() {
    let (out, n) = r().redact(format!("a {FAKE} b {FAKE}\n").as_bytes());
    assert_eq!(text(&out), "a [REDACTED:API_KEY] b [REDACTED:API_KEY]\n");
    assert_eq!(n, 2);
}

#[test]
fn base64_in_every_alignment_and_with_any_surroundings() {
    for prefix in ["", "x", "xy", "xyz"] {
        for suffix in ["", "!", "!!", "\n"] {
            let encoded = std_b64(format!("{prefix}{FAKE}{suffix}").as_bytes());
            let (out, n) = r().redact(encoded.as_bytes());
            assert!(n >= 1, "prefix {prefix:?} suffix {suffix:?}: {encoded}");
            assert!(text(&out).contains("[REDACTED:API_KEY]"));
        }
    }
    // URL-safe alphabet.
    let urlsafe = std_b64(ODD.as_bytes()).replace('+', "-").replace('/', "_");
    assert!(r().redact(urlsafe.as_bytes()).1 >= 1, "{urlsafe}");
}

#[test]
fn hex_url_and_json_forms() {
    let lower: String = FAKE.bytes().map(|b| format!("{b:02x}")).collect();
    let upper = lower.to_uppercase();
    let url_upper = "fake%20value%2Fwith%2Bodd%20%22chars%22%26%3D";
    let url_lower = "fake%20value%2fwith%2bodd%20%22chars%22%26%3d";
    let url_plus = "fake+value%2Fwith%2Bodd+%22chars%22%26%3D";
    let json = serde_json::to_string(ODD).unwrap();
    for form in [
        lower.as_str(),
        upper.as_str(),
        url_upper,
        url_lower,
        url_plus,
        &json,
    ] {
        let (out, n) = r().redact(form.as_bytes());
        assert!(n >= 1, "{form} not redacted: {}", text(&out));
        assert!(!text(&out).contains("odd") && !text(&out).contains("4b45"));
    }
}

#[test]
fn multiline_values_redact_each_line() {
    let v = SecretText::new("-----BEGIN KEY-----\nAAAABBBBCCCC\nshort\n-----END KEY-----\n".into());
    let red = Redactor::new([("PEM", &v)]);
    let (out, n) = red.redact(b"line two is AAAABBBBCCCC here; short stays");
    assert_eq!(text(&out), "line two is [REDACTED:PEM] here; short stays");
    assert_eq!(n, 1);
    // Value without its trailing newline.
    let (out, _) = red.redact(b"-----BEGIN KEY-----\nAAAABBBBCCCC\nshort\n-----END KEY-----");
    assert_eq!(text(&out), "[REDACTED:PEM]");
}

#[test]
fn short_values_are_not_redacted() {
    let v = SecretText::new("abc12".into());
    let (out, n) = Redactor::new([("TINY", &v)]).redact(b"abc12");
    assert_eq!((text(&out).as_str(), n), ("abc12", 0));
}

#[test]
fn truncated_output_masks_a_trailing_partial_secret() {
    let cut = format!("ok {}", &FAKE[..9]);
    let (out, n) = r().redact_truncated(cut.as_bytes());
    assert_eq!(text(&out), "ok [REDACTED:API_KEY]");
    assert_eq!(n, 1);
    // Partial base64 at the cut, too.
    let b64 = std_b64(FAKE.as_bytes());
    let (out, _) = r().redact_truncated(&b64.as_bytes()[..12]);
    assert!(!text(&out).contains(&b64[..8]), "{}", text(&out));
    // Without truncation the tail is ordinary output.
    let (out, n) = r().redact(cut.as_bytes());
    assert_eq!((text(&out), n), (cut, 0));
}

#[test]
fn longest_form_wins_and_no_overlap_leaks() {
    // The value plus a newline is one match, not "value" then a stray newline.
    let v = SecretText::new(format!("{FAKE}\n"));
    let red = Redactor::new([("NL", &v)]);
    let (out, n) = red.redact(format!("{FAKE}\n{FAKE}").as_bytes());
    assert_eq!(text(&out), "[REDACTED:NL][REDACTED:NL]");
    assert_eq!(n, 2);
    assert!(!format!("{red:?}").contains(FAKE));
}

#[test]
fn reversed_value_is_a_known_bypass() {
    // Documented: redaction is for accidents, not deliberate encoding.
    let rev: String = FAKE.chars().rev().collect();
    assert_eq!(r().redact(rev.as_bytes()).1, 0);
}
