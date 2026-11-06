//! `credstore-adversary`: a hostile command for the adversarial suite (spec section 10).
//!
//! It does what a malicious or careless command would do with an injected secret: dump
//! the environment, print encodings of a value, read credstore's files and the daemon's
//! memory, flood output, leave processes behind, and open network connections. Secret
//! values reach it only through its environment, files or stdin, never through argv (argv
//! is written to the audit log).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use credstore_tests::enc;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    let mut out = std::io::stdout().lock();
    match arg(0).as_str() {
        "env" => {
            for (k, v) in std::env::vars_os() {
                let _ = writeln!(out, "{}={}", k.to_string_lossy(), v.to_string_lossy());
            }
        }
        // Every encoding the redactor knows, of the value of env var `arg(1)`.
        "encode" => {
            let v = std::env::var(arg(1)).unwrap_or_default();
            for form in enc::known_forms(v.as_bytes()) {
                let _ = writeln!(out, "{form}");
            }
        }
        // A known bypass (documented in the threat model).
        "reverse" => {
            let v = std::env::var(arg(1)).unwrap_or_default();
            let _ = writeln!(out, "{}", v.chars().rev().collect::<String>());
        }
        "read" => {
            for p in &args[1..] {
                match std::fs::read(p) {
                    Ok(b) => {
                        let _ = writeln!(out, "READ {p}: {} bytes", b.len());
                        let _ = out.write_all(&b);
                        let _ = writeln!(out);
                    }
                    Err(e) => {
                        let _ = writeln!(out, "error {p}: {e}");
                    }
                }
            }
        }
        "write" => {
            let p = arg(1);
            match std::fs::write(&p, b"adversary was here") {
                Ok(()) => {
                    let _ = writeln!(out, "WROTE {p}");
                }
                Err(e) => {
                    let _ = writeln!(out, "error {p}: {e}");
                }
            }
        }
        // Look for the value of env var `arg(2)` in the memory of process `arg(1)`.
        "readmem" => {
            let needle = std::env::var(arg(2)).unwrap_or_default();
            let _ = writeln!(out, "{}", read_memory(&arg(1), needle.as_bytes()));
        }
        "flood" => {
            let total: u64 = arg(1).parse().unwrap_or(1 << 30);
            let chunk = vec![b'A'; 64 * 1024];
            let mut sent = 0u64;
            while sent < total {
                if out.write_all(&chunk).is_err() {
                    break;
                }
                sent += chunk.len() as u64;
            }
        }
        // Start a detached helper that writes `arg(1)` after `arg(2)` seconds, then hang.
        "spawn-sleeper" => {
            let me = std::env::current_exe().expect("own path");
            let child = std::process::Command::new(me)
                .args(["sleep-write", &arg(1), &arg(2)])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            match child {
                Ok(c) => {
                    let _ = writeln!(out, "spawned {}", c.id());
                }
                Err(e) => {
                    let _ = writeln!(out, "spawn failed: {e}");
                }
            }
            let _ = out.flush();
            std::thread::sleep(Duration::from_secs(3600));
        }
        "sleep-write" => {
            let secs: u64 = arg(2).parse().unwrap_or(5);
            std::thread::sleep(Duration::from_secs(secs));
            let _ = std::fs::write(arg(1), b"survived");
        }
        "connect" => {
            let addr: SocketAddr = arg(1).parse().expect("socket address");
            match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(_) => {
                    let _ = writeln!(out, "CONNECTED {addr}");
                }
                Err(e) => {
                    let _ = writeln!(out, "connect failed: {e}");
                }
            }
        }
        // Print the path in env var `arg(1)` and the file's content.
        "cat-env-file" => {
            let p = std::env::var(arg(1)).unwrap_or_default();
            let _ = writeln!(out, "path={p}");
            match std::fs::read(&p) {
                Ok(b) => {
                    let _ = out.write_all(&b);
                    let _ = writeln!(out);
                }
                Err(e) => {
                    let _ = writeln!(out, "error: {e}");
                }
            }
        }
        "stdin" => {
            let mut b = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut b);
            let _ = out.write_all(&b);
            let _ = writeln!(out);
        }
        "echo" => {
            let _ = writeln!(out, "{}", args[1..].join(" "));
        }
        other => {
            eprintln!("unknown command {other:?}");
            std::process::exit(2);
        }
    }
}

/// Linux: try `/proc/<pid>/mem`, scanning every readable mapping for `needle`.
fn read_memory(pid: &str, needle: &[u8]) -> String {
    if !cfg!(target_os = "linux") {
        return "unsupported on this OS".into();
    }
    let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(m) => m,
        Err(e) => return format!("denied: maps: {e}"),
    };
    let mut mem = match std::fs::File::open(format!("/proc/{pid}/mem")) {
        Ok(f) => f,
        Err(e) => return format!("denied: mem: {e}"),
    };
    use std::io::{Seek, SeekFrom};
    let mut readable = 0u64;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !perms.starts_with('r') {
            continue;
        }
        let Some((a, b)) = range.split_once('-') else {
            continue;
        };
        let (Ok(a), Ok(b)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else {
            continue;
        };
        let len = (b - a).min(256 << 20) as usize;
        let mut buf = vec![0u8; len];
        if mem.seek(SeekFrom::Start(a)).is_err() {
            continue;
        }
        if let Ok(n) = mem.read(&mut buf) {
            readable += n as u64;
            if credstore_tests::contains(&buf[..n], needle) {
                return "FOUND the value in daemon memory".into();
            }
        }
    }
    if readable == 0 {
        "denied: no memory could be read".into()
    } else {
        format!("READABLE: {readable} bytes, value not found")
    }
}
