use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
        }
    }

    pub fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.fin {
            byte |= 0x01;
        }
        if self.syn {
            byte |= 0x02;
        }
        if self.rst {
            byte |= 0x04;
        }
        if self.psh {
            byte |= 0x08;
        }
        if self.ack {
            byte |= 0x10;
        }
        byte
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4TcpPacket {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub identification: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: Ipv4Addr,
    pub src_port: u16,
    pub dst: Ipv4Addr,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn from_packet(packet: &Ipv4TcpPacket) -> Self {
        Self {
            src: packet.src,
            src_port: packet.src_port,
            dst: packet.dst,
            dst_port: packet.dst_port,
        }
    }
}

pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn ipv4_payload_from_ethernet(frame: &[u8]) -> Result<&[u8], ParseError> {
    if frame.len() < 14 {
        return Err(ParseError {
            reason: "ethernet frame is shorter than 14 bytes",
        });
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Err(ParseError {
            reason: "ethernet type is not IPv4",
        });
    }
    Ok(&frame[14..])
}

pub fn parse_ipv4_tcp(bytes: &[u8]) -> Result<Ipv4TcpPacket, ParseError> {
    if bytes.len() < 20 {
        return Err(ParseError {
            reason: "ipv4 header is truncated",
        });
    }
    let version = bytes[0] >> 4;
    if version != 4 {
        return Err(ParseError {
            reason: "ip version is not 4",
        });
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if ihl < 20 || bytes.len() < ihl {
        return Err(ParseError {
            reason: "ipv4 header length is invalid",
        });
    }
    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < ihl || bytes.len() < total_len {
        return Err(ParseError {
            reason: "ipv4 total length is invalid",
        });
    }
    let frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    if frag & 0x1fff != 0 || frag & 0x2000 != 0 {
        return Err(ParseError {
            reason: "ipv4 fragment is not supported",
        });
    }
    if bytes[9] != 6 {
        return Err(ParseError {
            reason: "ip protocol is not tcp",
        });
    }
    let tcp = &bytes[ihl..total_len];
    if tcp.len() < 20 {
        return Err(ParseError {
            reason: "tcp header is truncated",
        });
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return Err(ParseError {
            reason: "tcp data offset is invalid",
        });
    }
    Ok(Ipv4TcpPacket {
        src: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        ttl: bytes[8],
        identification: u16::from_be_bytes([bytes[4], bytes[5]]),
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: TcpFlags::from_byte(tcp[13]),
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        payload: tcp[data_offset..].to_vec(),
    })
}

pub fn write_ipv4_tcp(packet: &Ipv4TcpPacket) -> Result<Vec<u8>, ParseError> {
    let total_len = 40usize.saturating_add(packet.payload.len());
    if total_len > u16::MAX as usize {
        return Err(ParseError {
            reason: "ipv4 total length exceeds 65535",
        });
    }
    let mut out = vec![0u8; total_len];
    out[0] = 0x45;
    let len_bytes = (total_len as u16).to_be_bytes();
    out[2] = len_bytes[0];
    out[3] = len_bytes[1];
    out[4..6].copy_from_slice(&packet.identification.to_be_bytes());
    out[8] = packet.ttl;
    out[9] = 6;
    out[12..16].copy_from_slice(&packet.src.octets());
    out[16..20].copy_from_slice(&packet.dst.octets());
    out[20..22].copy_from_slice(&packet.src_port.to_be_bytes());
    out[22..24].copy_from_slice(&packet.dst_port.to_be_bytes());
    out[24..28].copy_from_slice(&packet.seq.to_be_bytes());
    out[28..32].copy_from_slice(&packet.ack.to_be_bytes());
    out[32] = 5 << 4;
    out[33] = packet.flags.to_byte();
    out[34..36].copy_from_slice(&packet.window.to_be_bytes());
    out[40..].copy_from_slice(&packet.payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Ipv4TcpPacket {
        Ipv4TcpPacket {
            src: Ipv4Addr::new(203, 0, 113, 10),
            dst: Ipv4Addr::new(198, 51, 100, 8),
            ttl: 52,
            identification: 0x1234,
            src_port: 40000,
            dst_port: 443,
            seq: 1000,
            ack: 2000,
            flags: TcpFlags {
                fin: false,
                syn: true,
                rst: false,
                psh: false,
                ack: false,
            },
            window: 64240,
            payload: b"hello".to_vec(),
        }
    }

    #[test]
    fn write_then_parse_round_trips() {
        let packet = sample();
        let bytes = write_ipv4_tcp(&packet).unwrap();
        let parsed = parse_ipv4_tcp(&bytes).unwrap();
        assert_eq!(parsed, packet);
        assert_eq!(FlowKey::from_packet(&parsed).src_port, 40000);
    }

    #[test]
    fn ethernet_strips_ipv4_ethertype() {
        let ip = write_ipv4_tcp(&sample()).unwrap();
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame.extend_from_slice(&ip);
        let parsed = parse_ipv4_tcp(ipv4_payload_from_ethernet(&frame).unwrap()).unwrap();
        assert_eq!(parsed.ttl, 52);
        assert!(ipv4_payload_from_ethernet(&[0u8; 14]).is_err());
    }

    #[test]
    fn rejects_fragments_non_tcp_and_short_buffers() {
        assert!(parse_ipv4_tcp(&[0x45]).is_err());
        let mut bytes = write_ipv4_tcp(&sample()).unwrap();
        bytes[9] = 17;
        assert!(parse_ipv4_tcp(&bytes).is_err());
        bytes = write_ipv4_tcp(&sample()).unwrap();
        bytes[6] = 0x20;
        assert!(parse_ipv4_tcp(&bytes).is_err());
    }

    #[test]
    fn honors_ihl_and_ignores_ethernet_padding() {
        let mut packet = sample();
        packet.payload = b"abc".to_vec();
        let mut bytes = write_ipv4_tcp(&packet).unwrap();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let parsed = parse_ipv4_tcp(&bytes).unwrap();
        assert_eq!(parsed.payload, b"abc");

        // Insert 4 bytes of IP options and bump IHL from 5 to 6.
        let ihl5 = bytes;
        let mut with_opts = Vec::new();
        with_opts.extend_from_slice(&ihl5[..20]);
        with_opts.extend_from_slice(&[1, 2, 3, 4]);
        with_opts.extend_from_slice(&ihl5[20..ihl5.len() - 4]);
        with_opts[0] = 0x46;
        let total = (with_opts.len() as u16).to_be_bytes();
        with_opts[2] = total[0];
        with_opts[3] = total[1];
        let parsed = parse_ipv4_tcp(&with_opts).unwrap();
        assert_eq!(parsed.payload, b"abc");
        assert_eq!(parsed.src_port, 40000);
    }

    #[test]
    fn fnv_is_stable_and_payload_sensitive() {
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        assert_ne!(fnv1a64(b"a"), fnv1a64(b"b"));
    }

    #[test]
    fn oversized_payload_is_an_error() {
        let mut packet = sample();
        packet.payload = vec![0; 70_000];
        assert!(write_ipv4_tcp(&packet).is_err());
    }
}
