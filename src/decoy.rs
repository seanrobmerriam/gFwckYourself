use chrono::{DateTime, Utc};
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyProfile {
    NginxWelcome,
    ApacheNotFound,
    CloudflareDenied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMessage {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: String) {
        if let Some(slot) = self.headers.iter_mut().find(|(key, _)| key.eq_ignore_ascii_case(name)) {
            slot.1 = value;
        } else {
            self.headers.push((name.to_string(), value));
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, self.reason);
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str(&format!("Content-Length: {}\r\n\r\n", self.body.len()));
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

pub struct DecoyGenerator<R> {
    profile: DecoyProfile,
    rng: R,
}

impl<R: Rng> DecoyGenerator<R> {
    pub fn new(profile: DecoyProfile, rng: R) -> Self {
        Self { profile, rng }
    }

    pub fn generate(&mut self, now: SystemTime) -> HttpMessage {
        let date = rfc7231(now);
        match self.profile {
            DecoyProfile::NginxWelcome => {
                let session: String = (0..16)
                    .map(|_| self.rng.sample(Alphanumeric) as char)
                    .collect();
                let spacer = self.rng.gen_range(12..48);
                let body = format!(
                    "<!DOCTYPE html>\n<html>\n<head><title>Welcome to nginx!</title></head>\n<body>\n<center><h1>Welcome to nginx!</h1></center>\n{}</body>\n</html>\n",
                    " ".repeat(spacer)
                );
                HttpMessage {
                    status: 200,
                    reason: "OK".to_string(),
                    headers: vec![
                        ("Server".to_string(), "nginx/1.24.0 (Ubuntu)".to_string()),
                        ("Date".to_string(), date),
                        ("Content-Type".to_string(), "text/html; charset=utf-8".to_string()),
                        ("Connection".to_string(), "close".to_string()),
                        ("Set-Cookie".to_string(), format!("SESSIONID={session}; Path=/; HttpOnly")),
                        ("Accept-Ranges".to_string(), "bytes".to_string()),
                    ],
                    body: body.into_bytes(),
                }
            }
            DecoyProfile::ApacheNotFound => {
                let debug = hex_nybbles(&mut self.rng, 8);
                let body = format!(
                    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n<!-- Debug ID: {debug} -->\n</body></html>\n"
                );
                HttpMessage {
                    status: 404,
                    reason: "Not Found".to_string(),
                    headers: vec![
                        ("Server".to_string(), "Apache/2.4.52 (Unix) OpenSSL/1.1.1t".to_string()),
                        ("Date".to_string(), date),
                        ("Content-Type".to_string(), "text/html; charset=iso-8859-1".to_string()),
                        ("Connection".to_string(), "close".to_string()),
                    ],
                    body: body.into_bytes(),
                }
            }
            DecoyProfile::CloudflareDenied => {
                let ray = hex_nybbles(&mut self.rng, 16);
                let body = format!(
                    "<!DOCTYPE html><html><head><title>Access Denied</title></head>\n<body><h1>Error 1020</h1><p>Access Denied by security rules.</p>\n<p>CF Ray ID: {ray}</p></body></html>\n"
                );
                HttpMessage {
                    status: 403,
                    reason: "Forbidden".to_string(),
                    headers: vec![
                        ("Date".to_string(), date),
                        ("Content-Type".to_string(), "text/html; charset=UTF-8".to_string()),
                        ("Connection".to_string(), "close".to_string()),
                        ("CF-RAY".to_string(), format!("{ray}-SJC")),
                        (
                            "Cache-Control".to_string(),
                            "private, max-age=0, no-store, no-cache, must-revalidate".to_string(),
                        ),
                    ],
                    body: body.into_bytes(),
                }
            }
        }
    }
}

fn hex_nybbles<R: Rng>(rng: &mut R, nybbles: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    (0..nybbles)
        .map(|_| HEX[rng.gen_range(0..16)] as char)
        .collect()
}

fn rfc7231(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let stamp = DateTime::<Utc>::from_timestamp(secs, 0).unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    stamp.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn body_of(bytes: &[u8]) -> &[u8] {
        let marker = b"\r\n\r\n";
        let pos = bytes.windows(4).position(|w| w == marker).unwrap();
        &bytes[pos + 4..]
    }

    #[test]
    fn nginx_date_and_content_length_follow_the_clock_and_body() {
        let mut gen = DecoyGenerator::new(DecoyProfile::NginxWelcome, StdRng::seed_from_u64(1));
        let message = gen.generate(now());
        assert_eq!(message.status, 200);
        assert_eq!(message.header("Date"), Some("Tue, 14 Nov 2023 22:13:20 GMT"));
        assert!(message.header("Server").unwrap().contains("nginx/1.24.0"));
        let raw = message.to_bytes();
        let body = body_of(&raw);
        assert!(std::str::from_utf8(body).unwrap().contains("Welcome to nginx!"));
        let text = String::from_utf8(raw.clone()).unwrap();
        let line = text.lines().find(|l| l.to_ascii_lowercase().starts_with("content-length:")).unwrap();
        let len: usize = line.split(':').nth(1).unwrap().trim().parse().unwrap();
        assert_eq!(len, body.len());
        assert!(text.contains("SESSIONID="));
        assert!(text.contains("Connection: close"));
    }

    #[test]
    fn profiles_differ_and_seeds_change_entropy() {
        let apache = DecoyGenerator::new(DecoyProfile::ApacheNotFound, StdRng::seed_from_u64(1)).generate(now());
        assert_eq!(apache.status, 404);
        assert!(apache.header("Server").unwrap().contains("Apache/2.4.52"));
        assert!(String::from_utf8_lossy(&apache.body).contains("404 Not Found"));
        let cf = DecoyGenerator::new(DecoyProfile::CloudflareDenied, StdRng::seed_from_u64(1)).generate(now());
        assert_eq!(cf.status, 403);
        assert!(cf.header("CF-RAY").unwrap().ends_with("-SJC"));
        assert!(String::from_utf8_lossy(&cf.body).contains("CF Ray ID:"));
        let a = DecoyGenerator::new(DecoyProfile::NginxWelcome, StdRng::seed_from_u64(1)).generate(now());
        let b = DecoyGenerator::new(DecoyProfile::NginxWelcome, StdRng::seed_from_u64(2)).generate(now());
        assert_ne!(a.header("Set-Cookie"), b.header("Set-Cookie"));
    }

    #[test]
    fn set_header_keeps_content_length_equal_to_the_body() {
        let mut message = DecoyGenerator::new(DecoyProfile::ApacheNotFound, StdRng::seed_from_u64(3)).generate(now());
        message.set_header("X-Request-Id", "1;abcd".to_string());
        let raw = message.to_bytes();
        let body = body_of(&raw);
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.contains("X-Request-Id: 1;abcd"));
        let line = text.lines().find(|l| l.starts_with("Content-Length:")).unwrap();
        let len: usize = line.split(':').nth(1).unwrap().trim().parse().unwrap();
        assert_eq!(len, body.len());
    }
}
