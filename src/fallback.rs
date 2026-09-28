use crate::HttpMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackDirective {
    pub backup_port: u16,
    pub token: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderCarrier {
    pub header_name: String,
}

impl Default for HeaderCarrier {
    fn default() -> Self {
        Self { header_name: "X-Request-Id".to_string() }
    }
}

impl HeaderCarrier {
    pub fn new(header_name: String) -> Self {
        Self { header_name }
    }

    pub fn embed(&self, message: &mut HttpMessage, directive: &FallbackDirective) {
        let value = format!("{};{}", directive.backup_port, hex_encode(&directive.token));
        message.set_header(&self.header_name, value);
    }

    pub fn extract(&self, raw: &str) -> Option<FallbackDirective> {
        let head = raw.split("\r\n\r\n").next().unwrap_or(raw);
        for line in head.split("\r\n") {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case(&self.header_name) {
                return parse_directive(value.trim());
            }
        }
        None
    }
}

fn parse_directive(value: &str) -> Option<FallbackDirective> {
    let (port, hex_token) = value.split_once(';')?;
    let backup_port = port.parse().ok()?;
    if hex_token.len() != 32 {
        return None;
    }
    let mut token = [0u8; 16];
    for index in 0..16 {
        let start = index * 2;
        token[index] = u8::from_str_radix(&hex_token[start..start + 2], 16).ok()?;
    }
    Some(FallbackDirective { backup_port, token })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(*byte >> 4) as usize] as char);
        out.push(HEX[(*byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecoyGenerator, DecoyProfile, HttpMessage};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn directive_round_trips_through_a_decoy() {
        let mut message = DecoyGenerator::new(
            DecoyProfile::NginxWelcome,
            StdRng::seed_from_u64(1),
        )
        .generate(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let directive = FallbackDirective {
            backup_port: 8443,
            token: [0xab; 16],
        };
        let carrier = HeaderCarrier::default();
        assert_eq!(carrier.header_name, "X-Request-Id");
        carrier.embed(&mut message, &directive);
        let found = carrier.extract(&String::from_utf8(message.to_bytes()).unwrap());
        assert_eq!(found, Some(directive));
    }

    #[test]
    fn bad_values_return_none() {
        let carrier = HeaderCarrier::new("X-Request-Id".to_string());
        assert_eq!(carrier.extract("HTTP/1.1 200 OK\r\n\r\n"), None);
        assert_eq!(carrier.extract("HTTP/1.1 200 OK\r\nX-Request-Id: no\r\n\r\n"), None);
        let mut message = HttpMessage {
            status: 200,
            reason: "OK".to_string(),
            headers: vec![("Server".to_string(), "nginx".to_string())],
            body: Vec::new(),
        };
        message.set_header("X-Request-Id", "8443;abcd".to_string());
        assert_eq!(carrier.extract(&String::from_utf8(message.to_bytes()).unwrap()), None);
    }
}
