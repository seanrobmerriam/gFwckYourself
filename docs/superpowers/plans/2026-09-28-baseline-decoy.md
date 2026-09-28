# Baseline-Driven Decoy Session Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `gfwck` crate, a pure decision library that locks a route profile, flags on-path TCP injection, scores later connections, and tells the host whether to serve a baseline, accept a handshake, or write a decoy.

**Architecture:** Host code parses or builds `Ipv4TcpPacket` values and passes them, with an explicit `SystemTime`, into `ServerEngine` or `ClientEngine`. Those engines own a baseline collector, a per-flow anomaly tracker, a prefix-aware decay monitor, and a decoy generator. The crate does not open sockets.

**Tech Stack:** Rust edition 2021, `chrono` 0.4.39, `rand` 0.8, `cargo test`.

## Global Constraints

- Edition `2021`. Rust `1.74` minimum.
- Crate name `gfwck`.
- Dependencies: `chrono` `0.4.39` (formatting UTC), `rand` `0.8` (decoy entropy and `StdRng`). No Tokio, `pnet`, `smoltcp`, or `pcap` in this crate.
- No `unsafe`.
- No background threads and no process-global maps.
- IPv4 only.
- Checksums are not verified.
- Default numbers: TTL tolerance `3`; baseline samples `5`; mode percent `60`; max samples `15`; race window `2` seconds; race history `64`; probe window `45` seconds; block threshold `0.65`; /24 coefficient `0.15`; /16 coefficient `0.50`; foreign coefficient `1.0`; suspicion lease `600` seconds; confirmation quiet period `2` seconds; carrier header `X-Request-Id`.
- Library code contains no protocol banner and no magic handshake constant.

Spec: `docs/superpowers/specs/2026-09-28-baseline-decoy-design.md`.

---

### Task 1: Crate scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Test: `src/lib.rs`

**Interfaces:**
- Consumes: nothing
- Produces: package `gfwck` that `cargo test` can compile

- [ ] **Step 1: Write the failing test**

Create `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(env!("CARGO_PKG_NAME"), "gfwck");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib crate_name_is_stable -- --exact`

Expected: FAIL because no `Cargo.toml` / package is present (`could not find Cargo.toml`).

- [ ] **Step 3: Write minimal implementation**

Create `Cargo.toml`:

```toml
[package]
name = "gfwck"
version = "0.1.0"
edition = "2021"
rust-version = "1.74"
description = "Decision library for baseline-driven decoy sessions"

[dependencies]
chrono = "0.4.39"
rand = "0.8"
```

Keep the `src/lib.rs` test from step 1.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib crate_name_is_stable -- --exact`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/lib.rs
git commit -m "feat: scaffold gfwck crate"
```

---

### Task 2: IPv4/TCP packet view

**Files:**
- Create: `src/packet.rs`
- Modify: `src/lib.rs`
- Test: `src/packet.rs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `ParseError { pub reason: &'static str }`
  - `TcpFlags { fin, syn, rst, psh, ack: bool }` with `from_byte(u8) -> Self` and `to_byte(self) -> u8`
  - `Ipv4TcpPacket` fields: `src`, `dst: Ipv4Addr`, `ttl: u8`, `identification: u16`, `src_port`, `dst_port: u16`, `seq`, `ack: u32`, `flags: TcpFlags`, `window: u16`, `payload: Vec<u8>`
  - `FlowKey { src, dst: Ipv4Addr, src_port, dst_port: u16 }` and `FlowKey::from_packet(&Ipv4TcpPacket) -> Self`
  - `fnv1a64(&[u8]) -> u64`
  - `ipv4_payload_from_ethernet(&[u8]) -> Result<&[u8], ParseError>`
  - `parse_ipv4_tcp(&[u8]) -> Result<Ipv4TcpPacket, ParseError>`
  - `write_ipv4_tcp(&Ipv4TcpPacket) -> Result<Vec<u8>, ParseError>`

- [ ] **Step 1: Write the failing test**

Add `mod packet;` is not enough for this test; put the test inside `src/packet.rs` so it compiles only after the module exists. First append to `src/lib.rs`:

```rust
mod packet;
```

Create `src/packet.rs` containing only the test module below. The test calls types that do not exist yet.

```rust
use std::net::Ipv4Addr;

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
            flags: TcpFlags { fin: false, syn: true, rst: false, psh: false, ack: false },
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib packet::tests -- --test-threads=8`

Expected: FAIL to compile (`Ipv4TcpPacket` / `write_ipv4_tcp` not found).

- [ ] **Step 3: Write minimal implementation**

Replace `src/packet.rs` with the test module kept at the bottom and this library code above it:

```rust
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
        if self.fin { byte |= 0x01; }
        if self.syn { byte |= 0x02; }
        if self.rst { byte |= 0x04; }
        if self.psh { byte |= 0x08; }
        if self.ack { byte |= 0x10; }
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
        return Err(ParseError { reason: "ethernet frame is shorter than 14 bytes" });
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Err(ParseError { reason: "ethernet type is not IPv4" });
    }
    Ok(&frame[14..])
}

pub fn parse_ipv4_tcp(bytes: &[u8]) -> Result<Ipv4TcpPacket, ParseError> {
    if bytes.len() < 20 {
        return Err(ParseError { reason: "ipv4 header is truncated" });
    }
    let version = bytes[0] >> 4;
    if version != 4 {
        return Err(ParseError { reason: "ip version is not 4" });
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if ihl < 20 || bytes.len() < ihl {
        return Err(ParseError { reason: "ipv4 header length is invalid" });
    }
    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < ihl || bytes.len() < total_len {
        return Err(ParseError { reason: "ipv4 total length is invalid" });
    }
    let frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    if frag & 0x1fff != 0 || frag & 0x2000 != 0 {
        return Err(ParseError { reason: "ipv4 fragment is not supported" });
    }
    if bytes[9] != 6 {
        return Err(ParseError { reason: "ip protocol is not tcp" });
    }
    let tcp = &bytes[ihl..total_len];
    if tcp.len() < 20 {
        return Err(ParseError { reason: "tcp header is truncated" });
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return Err(ParseError { reason: "tcp data offset is invalid" });
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
        return Err(ParseError { reason: "ipv4 total length exceeds 65535" });
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
```

Append to `src/lib.rs`:

```rust
pub use packet::{
    fnv1a64, ipv4_payload_from_ethernet, parse_ipv4_tcp, write_ipv4_tcp, FlowKey, Ipv4TcpPacket,
    ParseError, TcpFlags,
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib packet::tests -- --test-threads=8`

Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add src/packet.rs src/lib.rs
git commit -m "feat: parse and write IPv4 TCP observations"
```

---

### Task 3: Baseline collector

**Files:**
- Create: `src/baseline.rs`
- Modify: `src/lib.rs`
- Test: `src/baseline.rs`

**Interfaces:**
- Consumes: nothing from task 2
- Produces:
  - `BaselineConfig { required_samples: usize, mode_min_percent: u8, max_samples: usize, ttl_tolerance: u8 }` with `Default` equal to 5, 60, 15, 3
  - `Sample { ttl: u8, handshake_window: Option<u16> }`
  - `RouteProfile { peer: Ipv4Addr, peer_port: u16, verified_ttl: u8, ttl_tolerance: u8, handshake_window: Option<u16>, sample_count: usize }`
  - `BaselineStatus::{NeedMore { collected, required }, Ready(RouteProfile), Unstable { collected }}`
  - `BaselineCollector::new(BaselineConfig, Ipv4Addr, u16) -> Self`
  - `observe(&mut self, Sample) -> BaselineStatus`
  - `profile(&self) -> Option<&RouteProfile>`
  - `reset(&mut self)`

- [ ] **Step 1: Write the failing test**

Create `src/baseline.rs` with this test module, and add `mod baseline;` to `src/lib.rs`.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn collector() -> BaselineCollector {
        BaselineCollector::new(
            BaselineConfig::default(),
            Ipv4Addr::new(203, 0, 113, 10),
            443,
        )
    }

    #[test]
    fn five_equal_ttls_lock_the_mode_and_lower_median_window() {
        let mut c = collector();
        assert_eq!(BaselineConfig::default().ttl_tolerance, 3);
        assert_eq!(BaselineConfig::default().required_samples, 5);
        for window in [10u16, 40, 20, 30] {
            let status = c.observe(Sample { ttl: 52, handshake_window: Some(window) });
            assert!(matches!(status, BaselineStatus::NeedMore { .. }));
        }
        let status = c.observe(Sample { ttl: 52, handshake_window: None });
        match status {
            BaselineStatus::Ready(profile) => {
                assert_eq!(profile.verified_ttl, 52);
                assert_eq!(profile.handshake_window, Some(20));
                assert_eq!(profile.sample_count, 5);
                assert_eq!(profile.peer_port, 443);
            }
            other => panic!("expected ready, got {other:?}"),
        }
        assert!(c.profile().is_some());
        let again = c.observe(Sample { ttl: 9, handshake_window: Some(1) });
        assert!(matches!(again, BaselineStatus::Ready(p) if p.verified_ttl == 52));
    }

    #[test]
    fn three_of_five_locks_and_a_tie_prefers_the_higher_ttl() {
        let mut c = collector();
        for ttl in [40u8, 40, 52, 52, 52] {
            let _ = c.observe(Sample { ttl, handshake_window: None });
        }
        assert!(matches!(c.profile(), Some(p) if p.verified_ttl == 52));

        // 2/5 is 40 percent. With the minimum set to 40, 10 and 20 tie and 20 wins.
        let mut tied = BaselineCollector::new(
            BaselineConfig {
                required_samples: 5,
                mode_min_percent: 40,
                max_samples: 15,
                ttl_tolerance: 3,
            },
            Ipv4Addr::new(203, 0, 113, 10),
            443,
        );
        for ttl in [10u8, 10, 20, 20, 30] {
            let _ = tied.observe(Sample { ttl, handshake_window: None });
        }
        assert!(matches!(tied.profile(), Some(p) if p.verified_ttl == 20));
    }

    #[test]
    fn unbalanced_samples_become_unstable_at_the_cap() {
        let mut c = BaselineCollector::new(
            BaselineConfig {
                required_samples: 4,
                mode_min_percent: 60,
                max_samples: 4,
                ttl_tolerance: 3,
            },
            Ipv4Addr::LOCALHOST,
            1,
        );
        let mut last = BaselineStatus::NeedMore { collected: 0, required: 4 };
        for ttl in [1u8, 1, 2, 2] {
            last = c.observe(Sample { ttl, handshake_window: None });
        }
        assert!(matches!(last, BaselineStatus::Unstable { collected: 4 }));
    }

    #[test]
    fn reset_clears_a_locked_profile() {
        let mut c = collector();
        for _ in 0..5 {
            let _ = c.observe(Sample { ttl: 52, handshake_window: None });
        }
        c.reset();
        assert!(c.profile().is_none());
        assert!(matches!(c.observe(Sample { ttl: 7, handshake_window: None }), BaselineStatus::NeedMore { collected: 1, .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib baseline::tests -- --test-threads=8`

Expected: FAIL to compile (`BaselineCollector` not found).

- [ ] **Step 3: Write minimal implementation**

Put this above the test module in `src/baseline.rs`:

```rust
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineConfig {
    pub required_samples: usize,
    pub mode_min_percent: u8,
    pub max_samples: usize,
    pub ttl_tolerance: u8,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            required_samples: 5,
            mode_min_percent: 60,
            max_samples: 15,
            ttl_tolerance: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub ttl: u8,
    pub handshake_window: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProfile {
    pub peer: Ipv4Addr,
    pub peer_port: u16,
    pub verified_ttl: u8,
    pub ttl_tolerance: u8,
    pub handshake_window: Option<u16>,
    pub sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineStatus {
    NeedMore { collected: usize, required: usize },
    Ready(RouteProfile),
    Unstable { collected: usize },
}

#[derive(Debug, Clone)]
pub struct BaselineCollector {
    config: BaselineConfig,
    peer: Ipv4Addr,
    peer_port: u16,
    ttl_histogram: HashMap<u8, usize>,
    windows: Vec<u16>,
    samples: usize,
    locked: Option<RouteProfile>,
    unstable: bool,
}

impl BaselineCollector {
    pub fn new(config: BaselineConfig, peer: Ipv4Addr, peer_port: u16) -> Self {
        Self {
            config,
            peer,
            peer_port,
            ttl_histogram: HashMap::new(),
            windows: Vec::new(),
            samples: 0,
            locked: None,
            unstable: false,
        }
    }

    pub fn profile(&self) -> Option<&RouteProfile> {
        self.locked.as_ref()
    }

    pub fn reset(&mut self) {
        self.ttl_histogram.clear();
        self.windows.clear();
        self.samples = 0;
        self.locked = None;
        self.unstable = false;
    }

    pub fn observe(&mut self, sample: Sample) -> BaselineStatus {
        if let Some(profile) = &self.locked {
            return BaselineStatus::Ready(profile.clone());
        }
        if self.unstable {
            return BaselineStatus::Unstable { collected: self.samples };
        }
        *self.ttl_histogram.entry(sample.ttl).or_insert(0) += 1;
        if let Some(window) = sample.handshake_window {
            self.windows.push(window);
        }
        self.samples += 1;
        if self.samples < self.config.required_samples {
            return BaselineStatus::NeedMore {
                collected: self.samples,
                required: self.config.required_samples,
            };
        }
        let (mode_ttl, mode_count) = mode_ttl(&self.ttl_histogram);
        let percent = u32::from(self.config.mode_min_percent);
        if (mode_count as u32) * 100 < (self.samples as u32) * percent {
            if self.samples >= self.config.max_samples {
                self.unstable = true;
                return BaselineStatus::Unstable { collected: self.samples };
            }
            return BaselineStatus::NeedMore {
                collected: self.samples,
                required: self.config.required_samples,
            };
        }
        let profile = RouteProfile {
            peer: self.peer,
            peer_port: self.peer_port,
            verified_ttl: mode_ttl,
            ttl_tolerance: self.config.ttl_tolerance,
            handshake_window: lower_median(&self.windows),
            sample_count: self.samples,
        };
        self.locked = Some(profile.clone());
        BaselineStatus::Ready(profile)
    }
}

fn mode_ttl(hist: &HashMap<u8, usize>) -> (u8, usize) {
    let mut best_ttl = 0u8;
    let mut best_count = 0usize;
    for (&ttl, &count) in hist {
        if count > best_count || (count == best_count && ttl > best_ttl) {
            best_ttl = ttl;
            best_count = count;
        }
    }
    (best_ttl, best_count)
}

fn lower_median(values: &[u16]) -> Option<u16> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mid = (sorted.len() - 1) / 2;
    Some(sorted[mid])
}
```

Export from `src/lib.rs`:

```rust
mod baseline;
pub use baseline::{BaselineCollector, BaselineConfig, BaselineStatus, RouteProfile, Sample};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib baseline::tests -- --test-threads=8`

Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/baseline.rs src/lib.rs
git commit -m "feat: lock a route profile from TTL samples"
```

---

### Task 4: Anomaly tracker and frame screen

**Files:**
- Create: `src/anomaly.rs`
- Modify: `src/lib.rs`
- Test: `src/anomaly.rs`

**Interfaces:**
- Consumes: `fnv1a64`, `Ipv4TcpPacket`, `TcpFlags`
- Produces:
  - `AnomalyConfig { race_window: Duration, history_limit: usize }` default 2s and 64
  - `Anomaly::{TtlShift { expected, observed: u8 }, InjectionRace { seq: u32 }, RstZeroIpIdWithTtlShift { observed_ttl: u8 }}`
  - `FrameVerdict::{Forward, Drop(Anomaly)}`
  - `AnomalyTracker::new(AnomalyConfig) -> Self`
  - `set_expected_ttl(&mut self, u8, u8)`
  - `is_compromised(&self) -> bool`
  - `observe(&mut self, &Ipv4TcpPacket, SystemTime) -> Vec<Anomaly>`
  - `screen(Ipv4Addr, u16, &mut AnomalyTracker, &Ipv4TcpPacket, SystemTime) -> FrameVerdict`

- [ ] **Step 1: Write the failing test**

Add `mod anomaly;` to `src/lib.rs` and create `src/anomaly.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ipv4TcpPacket, TcpFlags};
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
    }

    fn packet(ttl: u8, ip_id: u16, seq: u32, rst: bool, window: u16, payload: &[u8]) -> Ipv4TcpPacket {
        Ipv4TcpPacket {
            src: Ipv4Addr::new(198, 51, 100, 8),
            dst: Ipv4Addr::new(203, 0, 113, 10),
            ttl,
            identification: ip_id,
            src_port: 443,
            dst_port: 40000,
            seq,
            ack: 1,
            flags: TcpFlags { fin: false, syn: false, rst, psh: !payload.is_empty(), ack: true },
            window,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn retransmission_is_quiet_and_changed_payload_is_a_race() {
        let mut tracker = AnomalyTracker::new(AnomalyConfig::default());
        assert_eq!(AnomalyConfig::default().history_limit, 64);
        let first = packet(52, 10, 50, false, 1000, b"one");
        assert!(tracker.observe(&first, at(0)).is_empty());
        assert!(tracker.observe(&first, at(1)).is_empty());
        let changed = packet(52, 11, 50, false, 1000, b"two");
        assert_eq!(
            tracker.observe(&changed, at(1)),
            vec![Anomaly::InjectionRace { seq: 50 }]
        );
        assert!(tracker.is_compromised());
    }

    #[test]
    fn ttl_shift_and_zero_ip_id_rst() {
        let mut tracker = AnomalyTracker::new(AnomalyConfig::default());
        tracker.set_expected_ttl(52, 3);
        let ok = packet(50, 9, 1, false, 1000, b"a");
        assert!(tracker.observe(&ok, at(0)).is_empty());
        let shift = packet(48, 9, 2, false, 1000, b"b");
        assert_eq!(
            tracker.observe(&shift, at(0)),
            vec![Anomaly::TtlShift { expected: 52, observed: 48 }]
        );
        let mut rst_tracker = AnomalyTracker::new(AnomalyConfig::default());
        rst_tracker.set_expected_ttl(52, 3);
        let spoof = packet(47, 0, 3, true, 0, b"");
        assert_eq!(
            rst_tracker.observe(&spoof, at(0)),
            vec![Anomaly::RstZeroIpIdWithTtlShift { observed_ttl: 47 }]
        );
        let mut benign = AnomalyTracker::new(AnomalyConfig::default());
        benign.set_expected_ttl(52, 3);
        let rst = packet(52, 8, 4, true, 0, b"");
        assert!(benign.observe(&rst, at(0)).is_empty());
        assert!(!benign.is_compromised());
    }

    #[test]
    fn screen_ignores_other_sources_and_drops_a_shift() {
        let mut tracker = AnomalyTracker::new(AnomalyConfig::default());
        tracker.set_expected_ttl(52, 3);
        let mut other = packet(10, 1, 1, false, 1, b"z");
        other.src = Ipv4Addr::new(1, 1, 1, 1);
        assert!(matches!(
            screen(Ipv4Addr::new(198, 51, 100, 8), 443, &mut tracker, &other, at(0)),
            FrameVerdict::Forward
        ));
        let bad = packet(40, 1, 9, false, 1, b"z");
        assert!(matches!(
            screen(Ipv4Addr::new(198, 51, 100, 8), 443, &mut tracker, &bad, at(0)),
            FrameVerdict::Drop(Anomaly::TtlShift { expected: 52, observed: 40 })
        ));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib anomaly::tests -- --test-threads=8`

Expected: FAIL to compile (`AnomalyTracker` not found).

- [ ] **Step 3: Write minimal implementation**

Library code above the tests in `src/anomaly.rs`:

```rust
use crate::{fnv1a64, Ipv4TcpPacket};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyConfig {
    pub race_window: Duration,
    pub history_limit: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            race_window: Duration::from_secs(2),
            history_limit: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    TtlShift { expected: u8, observed: u8 },
    InjectionRace { seq: u32 },
    RstZeroIpIdWithTtlShift { observed_ttl: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameVerdict {
    Forward,
    Drop(Anomaly),
}

struct Seen {
    seq: u32,
    ttl: u8,
    payload_hash: u64,
    at: SystemTime,
}

pub struct AnomalyTracker {
    config: AnomalyConfig,
    expected_ttl: Option<u8>,
    tolerance: u8,
    recent: VecDeque<Seen>,
    compromised: bool,
}

impl AnomalyTracker {
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            expected_ttl: None,
            tolerance: 3,
            recent: VecDeque::new(),
            compromised: false,
        }
    }

    pub fn set_expected_ttl(&mut self, ttl: u8, tolerance: u8) {
        self.expected_ttl = Some(ttl);
        self.tolerance = tolerance;
    }

    pub fn is_compromised(&self) -> bool {
        self.compromised
    }

    pub fn observe(&mut self, packet: &Ipv4TcpPacket, now: SystemTime) -> Vec<Anomaly> {
        let mut found = Vec::new();
        let hash = fnv1a64(&packet.payload);
        let window_start = now.checked_sub(self.config.race_window);
        self.recent.retain(|seen| match window_start {
            Some(start) => seen.at >= start,
            None => true,
        });
        let race = self.recent.iter().any(|seen| {
            seen.seq == packet.seq && (seen.ttl != packet.ttl || seen.payload_hash != hash)
        });
        if race {
            found.push(Anomaly::InjectionRace { seq: packet.seq });
        }
        self.recent.push_back(Seen {
            seq: packet.seq,
            ttl: packet.ttl,
            payload_hash: hash,
            at: now,
        });
        while self.recent.len() > self.config.history_limit {
            self.recent.pop_front();
        }
        if let Some(expected) = self.expected_ttl {
            let delta = (i16::from(expected) - i16::from(packet.ttl)).unsigned_abs();
            if delta > u16::from(self.tolerance) {
                if packet.flags.rst && packet.identification == 0 {
                    found.push(Anomaly::RstZeroIpIdWithTtlShift { observed_ttl: packet.ttl });
                } else {
                    found.push(Anomaly::TtlShift { expected, observed: packet.ttl });
                }
            }
        }
        if !found.is_empty() {
            self.compromised = true;
        }
        found
    }
}

pub fn screen(
    remote: Ipv4Addr,
    remote_port: u16,
    tracker: &mut AnomalyTracker,
    packet: &Ipv4TcpPacket,
    now: SystemTime,
) -> FrameVerdict {
    if packet.src != remote || packet.src_port != remote_port {
        return FrameVerdict::Forward;
    }
    match tracker.observe(packet, now).into_iter().next() {
        Some(anomaly) => FrameVerdict::Drop(anomaly),
        None => FrameVerdict::Forward,
    }
}
```

Export from `src/lib.rs`:

```rust
mod anomaly;
pub use anomaly::{screen, Anomaly, AnomalyConfig, AnomalyTracker, FrameVerdict};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib anomaly::tests -- --test-threads=8`

Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/anomaly.rs src/lib.rs
git commit -m "feat: flag TTL shifts and injection races"
```

---

### Task 5: Subnet-aware probe monitor

**Files:**
- Create: `src/probe.rs`
- Modify: `src/lib.rs`
- Test: `src/probe.rs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `SubnetRelation::{ExactMatch, LocalSubnet24, RegionalSubnet16, ForeignNetwork}`
  - `subnet_relation(Ipv4Addr, Ipv4Addr) -> SubnetRelation`
  - `ProbeConfig` fields `critical_window: Duration`, `block_threshold: f64`, `coeff_local24: f64`, `coeff_regional16: f64`, `coeff_foreign: f64`, `lease: Duration` with defaults 45s, 0.65, 0.15, 0.50, 1.0, 600s
  - `ProbeVerdict::{Known { score: f64 }, Allow { score: f64 }, Suspect { score: f64 }}`
  - `ProbeMonitor::new(ProbeConfig) -> Self`
  - `register(&mut self, Ipv4Addr, SystemTime)` leaves an existing arrival time in place
  - `evaluate(&self, Ipv4Addr, SystemTime) -> ProbeVerdict`
  - `mark_suspected(&mut self, Ipv4Addr, SystemTime)`
  - `suspect_correlated(&mut self, Ipv4Addr, SystemTime)`
  - `is_suspected(&self, Ipv4Addr, SystemTime) -> bool` while `now < suspected_until`
  - `is_registered(&self, Ipv4Addr) -> bool`
  - `prune(&mut self, SystemTime)`

- [ ] **Step 1: Write the failing test**

Add `mod probe;` and create `src/probe.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn t(extra_ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_millis(extra_ms)
    }

    fn expect_score(age_secs: f64, coeff: f64) -> f64 {
        (-age_secs / 45.0).exp() * coeff
    }

    #[test]
    fn prefix_relations() {
        let a = Ipv4Addr::new(1, 2, 3, 4);
        assert_eq!(subnet_relation(a, a), SubnetRelation::ExactMatch);
        assert_eq!(subnet_relation(a, Ipv4Addr::new(1, 2, 3, 50)), SubnetRelation::LocalSubnet24);
        assert_eq!(subnet_relation(a, Ipv4Addr::new(1, 2, 9, 9)), SubnetRelation::RegionalSubnet16);
        assert_eq!(subnet_relation(a, Ipv4Addr::new(9, 9, 9, 9)), SubnetRelation::ForeignNetwork);
    }

    #[test]
    fn decay_table_matches_the_spec() {
        let mut monitor = ProbeMonitor::new(ProbeConfig::default());
        assert_eq!(ProbeConfig::default().block_threshold, 0.65);
        assert_eq!(ProbeConfig::default().lease, Duration::from_secs(600));
        let client = Ipv4Addr::new(1, 2, 3, 4);
        monitor.register(client, t(0));

        let local = Ipv4Addr::new(1, 2, 3, 50);
        match monitor.evaluate(local, t(3500)) {
            ProbeVerdict::Allow { score } => {
                assert!((score - expect_score(3.5, 0.15)).abs() < 1e-9);
                assert!(score < 0.65);
            }
            other => panic!("expected allow, got {other:?}"),
        }

        let regional = Ipv4Addr::new(1, 2, 9, 9);
        match monitor.evaluate(regional, t(12_000)) {
            ProbeVerdict::Allow { score } => {
                assert!((score - expect_score(12.0, 0.50)).abs() < 1e-9);
            }
            other => panic!("expected allow, got {other:?}"),
        }

        let foreign = Ipv4Addr::new(9, 9, 9, 9);
        match monitor.evaluate(foreign, t(6_000)) {
            ProbeVerdict::Suspect { score } => {
                assert!((score - expect_score(6.0, 1.0)).abs() < 1e-9);
            }
            other => panic!("expected suspect, got {other:?}"),
        }
        match monitor.evaluate(foreign, t(8_000)) {
            ProbeVerdict::Suspect { score } => {
                assert!((score - expect_score(8.0, 1.0)).abs() < 1e-9);
                assert!(score >= 0.65);
            }
            other => panic!("expected suspect, got {other:?}"),
        }
        assert!(matches!(monitor.evaluate(client, t(1_000)), ProbeVerdict::Known { score } if score == 0.0));
    }

    #[test]
    fn suspicion_lease_and_correlated_mark() {
        let mut monitor = ProbeMonitor::new(ProbeConfig::default());
        let client = Ipv4Addr::new(203, 0, 113, 10);
        monitor.register(client, t(0));
        let probe = Ipv4Addr::new(9, 9, 9, 9);
        monitor.suspect_correlated(probe, t(6_000));
        assert!(monitor.is_suspected(client, t(6_000)));
        assert!(monitor.is_suspected(client, t(6_000 + 599_999)));
        assert!(!monitor.is_suspected(client, t(6_000 + 600_000)));
        let neighbor = Ipv4Addr::new(203, 0, 113, 50);
        monitor.register(neighbor, t(0));
        let mut only_local = ProbeMonitor::new(ProbeConfig::default());
        only_local.register(client, t(0));
        only_local.suspect_correlated(neighbor, t(3_500));
        assert!(!only_local.is_suspected(client, t(3_500)));
    }

    #[test]
    fn prune_drops_an_old_unsuspected_session() {
        let mut monitor = ProbeMonitor::new(ProbeConfig::default());
        let client = Ipv4Addr::new(1, 2, 3, 4);
        monitor.register(client, t(0));
        monitor.prune(t(90_001));
        assert!(!monitor.is_registered(client));
        monitor.register(client, t(0));
        monitor.mark_suspected(client, t(0));
        monitor.prune(t(90_001));
        assert!(monitor.is_registered(client));
        assert!(monitor.is_suspected(client, t(599_000)));
        assert!(!monitor.is_suspected(client, t(600_000)));
    }

    #[test]
    fn reregister_keeps_the_original_arrival() {
        let mut monitor = ProbeMonitor::new(ProbeConfig::default());
        let client = Ipv4Addr::new(1, 2, 3, 4);
        monitor.register(client, t(0));
        monitor.register(client, t(40_000));
        let foreign = Ipv4Addr::new(8, 8, 8, 8);
        assert!(matches!(monitor.evaluate(foreign, t(40_000)), ProbeVerdict::Allow { .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib probe::tests -- --test-threads=8`

Expected: FAIL to compile.

- [ ] **Step 3: Write minimal implementation**

```rust
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetRelation {
    ExactMatch,
    LocalSubnet24,
    RegionalSubnet16,
    ForeignNetwork,
}

pub fn subnet_relation(left: Ipv4Addr, right: Ipv4Addr) -> SubnetRelation {
    if left == right {
        return SubnetRelation::ExactMatch;
    }
    let a = left.octets();
    let b = right.octets();
    if a[0] == b[0] && a[1] == b[1] && a[2] == b[2] {
        SubnetRelation::LocalSubnet24
    } else if a[0] == b[0] && a[1] == b[1] {
        SubnetRelation::RegionalSubnet16
    } else {
        SubnetRelation::ForeignNetwork
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeConfig {
    pub critical_window: Duration,
    pub block_threshold: f64,
    pub coeff_local24: f64,
    pub coeff_regional16: f64,
    pub coeff_foreign: f64,
    pub lease: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            critical_window: Duration::from_secs(45),
            block_threshold: 0.65,
            coeff_local24: 0.15,
            coeff_regional16: 0.50,
            coeff_foreign: 1.0,
            lease: Duration::from_secs(600),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeVerdict {
    Known { score: f64 },
    Allow { score: f64 },
    Suspect { score: f64 },
}

struct SessionMark {
    arrived: SystemTime,
    suspected_until: Option<SystemTime>,
}

pub struct ProbeMonitor {
    config: ProbeConfig,
    sessions: HashMap<Ipv4Addr, SessionMark>,
}

impl ProbeMonitor {
    pub fn new(config: ProbeConfig) -> Self {
        Self { config, sessions: HashMap::new() }
    }

    pub fn register(&mut self, ip: Ipv4Addr, now: SystemTime) {
        self.sessions.entry(ip).or_insert(SessionMark {
            arrived: now,
            suspected_until: None,
        });
    }

    pub fn is_registered(&self, ip: Ipv4Addr) -> bool {
        self.sessions.contains_key(&ip)
    }

    pub fn evaluate(&self, incoming: Ipv4Addr, now: SystemTime) -> ProbeVerdict {
        if self.sessions.contains_key(&incoming) {
            return ProbeVerdict::Known { score: 0.0 };
        }
        let best = self.best_score(incoming, now);
        if best >= self.config.block_threshold {
            ProbeVerdict::Suspect { score: best }
        } else {
            ProbeVerdict::Allow { score: best }
        }
    }

    pub fn mark_suspected(&mut self, ip: Ipv4Addr, now: SystemTime) {
        if let Some(session) = self.sessions.get_mut(&ip) {
            session.suspected_until = Some(now + self.config.lease);
        }
    }

    pub fn suspect_correlated(&mut self, incoming: Ipv4Addr, now: SystemTime) {
        let ips: Vec<Ipv4Addr> = self.sessions.keys().copied().collect();
        for ip in ips {
            if self.pairwise(ip, incoming, now) >= self.config.block_threshold {
                self.mark_suspected(ip, now);
            }
        }
    }

    pub fn is_suspected(&self, ip: Ipv4Addr, now: SystemTime) -> bool {
        self.sessions
            .get(&ip)
            .and_then(|session| session.suspected_until)
            .map(|until| now < until)
            .unwrap_or(false)
    }

    pub fn prune(&mut self, now: SystemTime) {
        let horizon = self.config.critical_window * 2;
        self.sessions.retain(|_, session| {
            let fresh = now.duration_since(session.arrived).unwrap_or_default() <= horizon;
            let suspected = session.suspected_until.map(|until| now < until).unwrap_or(false);
            fresh || suspected
        });
    }

    fn best_score(&self, incoming: Ipv4Addr, now: SystemTime) -> f64 {
        self.sessions
            .keys()
            .map(|ip| self.pairwise(*ip, incoming, now))
            .fold(0.0, f64::max)
    }

    fn pairwise(&self, registered: Ipv4Addr, incoming: Ipv4Addr, now: SystemTime) -> f64 {
        let Some(session) = self.sessions.get(&registered) else {
            return 0.0;
        };
        let Ok(delta) = now.duration_since(session.arrived) else {
            return 0.0;
        };
        if delta > self.config.critical_window * 2 {
            return 0.0;
        }
        let window = self.config.critical_window.as_secs_f64();
        if window == 0.0 {
            return 0.0;
        }
        let base = (-delta.as_secs_f64() / window).exp();
        base * self.coefficient(subnet_relation(registered, incoming))
    }

    fn coefficient(&self, relation: SubnetRelation) -> f64 {
        match relation {
            SubnetRelation::ExactMatch => 0.0,
            SubnetRelation::LocalSubnet24 => self.config.coeff_local24,
            SubnetRelation::RegionalSubnet16 => self.config.coeff_regional16,
            SubnetRelation::ForeignNetwork => self.config.coeff_foreign,
        }
    }
}
```

Export:

```rust
mod probe;
pub use probe::{subnet_relation, ProbeConfig, ProbeMonitor, ProbeVerdict, SubnetRelation};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib probe::tests -- --test-threads=8`

Expected: PASS, 5 tests. The 40 second re-register check: age 40s, `exp(-40/45) ≈ 0.411 < 0.65`, so `Allow`. Prune uses 90.001s because the horizon comparison is inclusive at 90s.

- [ ] **Step 5: Commit**

```bash
git add src/probe.rs src/lib.rs
git commit -m "feat: score follow-up connections by time and prefix"
```

---

### Task 6: Decoy HTTP generator

**Files:**
- Create: `src/decoy.rs`
- Modify: `src/lib.rs`
- Test: `src/decoy.rs`

**Interfaces:**
- Consumes: `rand::Rng`
- Produces:
  - `DecoyProfile::{NginxWelcome, ApacheNotFound, CloudflareDenied}`
  - `HttpMessage { status: u16, reason: String, headers: Vec<(String, String)>, body: Vec<u8> }`
  - `set_header(&mut self, &str, String)`, `header(&self, &str) -> Option<&str>`, `to_bytes(&self) -> Vec<u8>`
  - `DecoyGenerator<R: Rng>::new(DecoyProfile, R) -> Self`
  - `generate(&mut self, SystemTime) -> HttpMessage`

- [ ] **Step 1: Write the failing test**

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib decoy::tests -- --test-threads=8`

Expected: FAIL to compile.

- [ ] **Step 3: Write minimal implementation**

```rust
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
```

`String::lines` splits on `\n` and leaves `\r` on HTTP headers. The content-length assertion uses `split(':')` and `trim()`, which removes the trailing `\r`. That passes. Do not use `starts_with("Content-Length:")` after `lines()` if a `\r` remains; `trim` on the value is enough because the name and colon stay on the left.

Export:

```rust
mod decoy;
pub use decoy::{DecoyGenerator, DecoyProfile, HttpMessage};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib decoy::tests -- --test-threads=8`

Expected: PASS, 3 tests. `Date` is `Tue, 14 Nov 2023 22:13:20 GMT`.

- [ ] **Step 5: Commit**

```bash
git add src/decoy.rs src/lib.rs
git commit -m "feat: generate dated decoy HTTP responses"
```

---

### Task 7: Fallback header carrier

**Files:**
- Create: `src/fallback.rs`
- Modify: `src/lib.rs`
- Test: `src/fallback.rs`

**Interfaces:**
- Consumes: `HttpMessage::set_header`
- Produces:
  - `FallbackDirective { backup_port: u16, token: [u8; 16] }`
  - `HeaderCarrier { header_name: String }` with `new(String) -> Self` and `Default` name `X-Request-Id`
  - `embed(&self, &mut HttpMessage, &FallbackDirective)`
  - `extract(&self, &str) -> Option<FallbackDirective>`

- [ ] **Step 1: Write the failing test**

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fallback::tests -- --test-threads=8`

Expected: FAIL to compile.

- [ ] **Step 3: Write minimal implementation**

```rust
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
```

Export:

```rust
mod fallback;
pub use fallback::{FallbackDirective, HeaderCarrier};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fallback::tests -- --test-threads=8`

Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add src/fallback.rs src/lib.rs
git commit -m "feat: embed a fallback directive in a response header"
```

---

### Task 8: Server engine

**Files:**
- Create: `src/server.rs`
- Modify: `src/lib.rs`
- Test: `src/server.rs`

**Interfaces:**
- Consumes: `BaselineCollector`, `AnomalyTracker`, `ProbeMonitor`, `DecoyGenerator`, `HeaderCarrier`, `FlowKey`, `Ipv4TcpPacket`, `HandshakeProof`
- Produces:
  - `ArrivalKind::{BaselineAsset, HandshakeAttempt, Unrecognized}`
  - `trait HandshakeProof { fn classify(&self, &[u8]) -> ArrivalKind }`
  - `ServerAction::{ServeBaseline { embed: Option<FallbackDirective> }, AcceptHandshake, Decoy { message: HttpMessage }}`
  - `ServerConfig` with baseline, anomaly, probe, `confirmation_quiet: Duration` default 2s, `decoy_profile`, `carrier_header` default `X-Request-Id`, `fallback: Option<FallbackDirective>`
  - `ServerEngine<P, R>::new(ServerConfig, P, R) -> Self` where `P: HandshakeProof` and `R: Rng`
  - `carrier(&self) -> &HeaderCarrier`
  - `observe_packet(&mut self, &Ipv4TcpPacket, SystemTime) -> Vec<Anomaly>`
  - `on_payload(&mut self, FlowKey, &[u8], SystemTime) -> ServerAction`
  - `prune(&mut self, SystemTime)`

Decision tables are the ones in the spec section “Decision tables”. Implement them with the function below, not a second interpretation.

- [ ] **Step 1: Write the failing test**

Create `src/server.rs` tests. Add `mod server;` to `src/lib.rs`.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Anomaly, DecoyProfile, FallbackDirective, FlowKey, Ipv4TcpPacket, ProbeConfig, TcpFlags,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct LabProof;
    impl HandshakeProof for LabProof {
        fn classify(&self, payload: &[u8]) -> ArrivalKind {
            if payload.starts_with(b"GET /favicon.ico ") {
                ArrivalKind::BaselineAsset
            } else if payload.starts_with(b"PROOF ") {
                ArrivalKind::HandshakeAttempt
            } else {
                ArrivalKind::Unrecognized
            }
        }
    }

    fn clock(extra: Duration) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000) + extra
    }

    fn syn(src: Ipv4Addr, src_port: u16, ttl: u8) -> Ipv4TcpPacket {
        Ipv4TcpPacket {
            src,
            dst: Ipv4Addr::new(198, 51, 100, 8),
            ttl,
            identification: 7,
            src_port,
            dst_port: 443,
            seq: 1,
            ack: 0,
            flags: TcpFlags { fin: false, syn: true, rst: false, psh: false, ack: false },
            window: 64240,
            payload: Vec::new(),
        }
    }

    fn engine() -> ServerEngine<LabProof, StdRng> {
        let mut config = ServerConfig::default();
        config.decoy_profile = DecoyProfile::NginxWelcome;
        config.fallback = Some(FallbackDirective { backup_port: 8443, token: [1u8; 16] });
        assert_eq!(config.confirmation_quiet, Duration::from_secs(2));
        assert_eq!(config.carrier_header, "X-Request-Id");
        assert_eq!(config.probe.critical_window, ProbeConfig::default().critical_window);
        ServerEngine::new(config, LabProof, StdRng::seed_from_u64(9))
    }

    fn enroll(engine: &mut ServerEngine<LabProof, StdRng>, ip: Ipv4Addr, port: u16, when: SystemTime) {
        for n in 0..5 {
            let mut packet = syn(ip, port, 52);
            packet.seq = n;
            engine.observe_packet(&packet, when);
        }
        let flow = FlowKey { src: ip, src_port: port, dst: Ipv4Addr::new(198, 51, 100, 8), dst_port: 443 };
        let action = engine.on_payload(flow, b"GET /favicon.ico HTTP/1.1\r\n", when + Duration::from_secs(2));
        assert!(matches!(action, ServerAction::ServeBaseline { embed: None }));
    }

    #[test]
    fn quiet_period_gates_the_handshake() {
        let mut engine = engine();
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let when = clock(Duration::from_secs(0));
        for n in 0..5 {
            let mut packet = syn(ip, 40000, 52);
            packet.seq = n;
            assert!(engine.observe_packet(&packet, when).is_empty());
        }
        let flow = FlowKey { src: ip, src_port: 40000, dst: Ipv4Addr::new(198, 51, 100, 8), dst_port: 443 };
        engine.on_payload(flow, b"GET /favicon.ico HTTP/1.1\r\n", when);
        let early = engine.on_payload(flow, b"PROOF v", when + Duration::from_secs(1));
        match early {
            ServerAction::Decoy { message } => {
                assert!(message.header("X-Request-Id").is_some());
            }
            other => panic!("expected decoy, got {other:?}"),
        }
        let ready = engine.on_payload(flow, b"PROOF v", when + Duration::from_secs(2));
        assert!(matches!(ready, ServerAction::AcceptHandshake));
    }

    #[test]
    fn injected_rst_makes_the_next_handshake_a_decoy_with_a_directive() {
        let mut engine = engine();
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let when = clock(Duration::from_secs(0));
        enroll(&mut engine, ip, 40000, when);
        let mut rst = syn(ip, 40000, 40);
        rst.flags.syn = false;
        rst.flags.rst = true;
        rst.flags.ack = true;
        rst.identification = 0;
        rst.seq = 99;
        let flags = engine.observe_packet(&rst, when + Duration::from_secs(3));
        assert_eq!(flags, vec![Anomaly::RstZeroIpIdWithTtlShift { observed_ttl: 40 }]);
        let flow = FlowKey { src: ip, src_port: 40000, dst: rst.dst, dst_port: 443 };
        match engine.on_payload(flow, b"PROOF v", when + Duration::from_secs(3)) {
            ServerAction::Decoy { message } => {
                assert!(message.header("X-Request-Id").unwrap().starts_with("8443;"));
            }
            other => panic!("expected decoy, got {other:?}"),
        }
    }

    #[test]
    fn foreign_probe_decoys_without_a_directive_and_dirties_the_client() {
        let mut engine = engine();
        let client = Ipv4Addr::new(203, 0, 113, 10);
        let when = clock(Duration::from_secs(0));
        enroll(&mut engine, client, 40000, when);
        // enroll registers at when+2s, so this arrival is 6s later.
        let probe_at = when + Duration::from_secs(8);
        let probe_ip = Ipv4Addr::new(9, 9, 9, 9);
        let probe_flow = FlowKey { src: probe_ip, src_port: 9, dst: Ipv4Addr::new(198, 51, 100, 8), dst_port: 443 };
        match engine.on_payload(probe_flow, b"\x16\x03\x01", probe_at) {
            ServerAction::Decoy { message } => assert!(message.header("X-Request-Id").is_none()),
            other => panic!("expected decoy, got {other:?}"),
        }
        let client_flow = FlowKey { src: client, src_port: 40000, dst: probe_flow.dst, dst_port: 443 };
        match engine.on_payload(client_flow, b"PROOF v", probe_at) {
            ServerAction::Decoy { message } => assert!(message.header("X-Request-Id").is_some()),
            other => panic!("expected dirty decoy, got {other:?}"),
        }
    }

    #[test]
    fn same_slash_24_baseline_stays_clean() {
        let mut engine = engine();
        let client = Ipv4Addr::new(203, 0, 113, 10);
        let when = clock(Duration::from_secs(0));
        enroll(&mut engine, client, 40000, when);
        // enroll registers at when+2s; 3.5s after that is the /24 row in the spec table.
        let neighbor_at = when + Duration::from_secs(2) + Duration::from_millis(3500);
        let neighbor = Ipv4Addr::new(203, 0, 113, 50);
        for n in 0..5 {
            let mut packet = syn(neighbor, 41000, 52);
            packet.seq = n;
            engine.observe_packet(&packet, neighbor_at);
        }
        let flow = FlowKey { src: neighbor, src_port: 41000, dst: Ipv4Addr::new(198, 51, 100, 8), dst_port: 443 };
        let action = engine.on_payload(flow, b"GET /favicon.ico HTTP/1.1\r\n", neighbor_at);
        assert!(matches!(action, ServerAction::ServeBaseline { embed: None }));
        let client_flow = FlowKey { src: client, src_port: 40000, dst: flow.dst, dst_port: 443 };
        let still = engine.on_payload(client_flow, b"PROOF v", neighbor_at);
        assert!(matches!(still, ServerAction::AcceptHandshake));
    }

    #[test]
    fn suspicion_expires_on_the_lease_boundary() {
        let mut engine = engine();
        let client = Ipv4Addr::new(203, 0, 113, 10);
        let when = clock(Duration::from_secs(0));
        enroll(&mut engine, client, 40000, when);
        let probe_flow = FlowKey {
            src: Ipv4Addr::new(9, 9, 9, 9),
            src_port: 1,
            dst: Ipv4Addr::new(198, 51, 100, 8),
            dst_port: 443,
        };
        let marked = when + Duration::from_secs(8);
        let _ = engine.on_payload(probe_flow, b"nope", marked);
        let flow = FlowKey { src: client, src_port: 40000, dst: probe_flow.dst, dst_port: 443 };
        assert!(matches!(
            engine.on_payload(flow, b"PROOF v", marked + Duration::from_secs(599)),
            ServerAction::Decoy { .. }
        ));
        assert!(matches!(
            engine.on_payload(flow, b"PROOF v", marked + Duration::from_secs(600)),
            ServerAction::AcceptHandshake
        ));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib server::tests -- --test-threads=8`

Expected: FAIL to compile.

- [ ] **Step 3: Write minimal implementation**

```rust
use crate::{
    Anomaly, AnomalyTracker, BaselineCollector, BaselineStatus, DecoyGenerator, DecoyProfile,
    FallbackDirective, FlowKey, HeaderCarrier, HttpMessage, Ipv4TcpPacket, ProbeMonitor, Sample,
};
use rand::Rng;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrivalKind {
    BaselineAsset,
    HandshakeAttempt,
    Unrecognized,
}

pub trait HandshakeProof {
    fn classify(&self, payload: &[u8]) -> ArrivalKind;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAction {
    ServeBaseline { embed: Option<FallbackDirective> },
    AcceptHandshake,
    Decoy { message: HttpMessage },
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub baseline: crate::BaselineConfig,
    pub anomaly: crate::AnomalyConfig,
    pub probe: crate::ProbeConfig,
    pub confirmation_quiet: Duration,
    pub decoy_profile: DecoyProfile,
    pub carrier_header: String,
    pub fallback: Option<FallbackDirective>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            baseline: crate::BaselineConfig::default(),
            anomaly: crate::AnomalyConfig::default(),
            probe: crate::ProbeConfig::default(),
            confirmation_quiet: Duration::from_secs(2),
            decoy_profile: DecoyProfile::NginxWelcome,
            carrier_header: "X-Request-Id".to_string(),
            fallback: None,
        }
    }
}

struct ClientRec {
    collector: BaselineCollector,
    ready_at: Option<SystemTime>,
    authorized: bool,
    last_seen: SystemTime,
}

struct FlowRec {
    tracker: AnomalyTracker,
    last_seen: SystemTime,
}

pub struct ServerEngine<P, R> {
    config: ServerConfig,
    proof: P,
    generator: DecoyGenerator<R>,
    carrier: HeaderCarrier,
    clients: HashMap<Ipv4Addr, ClientRec>,
    flows: HashMap<FlowKey, FlowRec>,
    probes: ProbeMonitor,
}

impl<P: HandshakeProof, R: Rng> ServerEngine<P, R> {
    pub fn new(config: ServerConfig, proof: P, rng: R) -> Self {
        let generator = DecoyGenerator::new(config.decoy_profile, rng);
        let carrier = HeaderCarrier::new(config.carrier_header.clone());
        let probes = ProbeMonitor::new(config.probe.clone());
        Self {
            config,
            proof,
            generator,
            carrier,
            clients: HashMap::new(),
            flows: HashMap::new(),
            probes,
        }
    }

    pub fn carrier(&self) -> &HeaderCarrier {
        &self.carrier
    }

    pub fn observe_packet(&mut self, packet: &Ipv4TcpPacket, now: SystemTime) -> Vec<Anomaly> {
        let client_ip = packet.src;
        if !self.clients.contains_key(&client_ip) {
            self.clients.insert(
                client_ip,
                ClientRec {
                    collector: BaselineCollector::new(self.config.baseline.clone(), client_ip, packet.dst_port),
                    ready_at: None,
                    authorized: false,
                    last_seen: now,
                },
            );
        }
        let locked = {
            let client = self.clients.get_mut(&client_ip).expect("client inserted");
            client.last_seen = now;
            let window = if packet.flags.syn && !packet.flags.ack {
                Some(packet.window)
            } else {
                None
            };
            match client.collector.observe(Sample { ttl: packet.ttl, handshake_window: window }) {
                BaselineStatus::Ready(profile) => {
                    if client.ready_at.is_none() {
                        client.ready_at = Some(now);
                    }
                    Some((profile.verified_ttl, profile.ttl_tolerance))
                }
                _ => None,
            }
        };
        if let Some((ttl, tolerance)) = locked {
            for (key, flow) in &mut self.flows {
                if key.src == client_ip {
                    flow.tracker.set_expected_ttl(ttl, tolerance);
                }
            }
        }
        let key = FlowKey::from_packet(packet);
        if !self.flows.contains_key(&key) {
            let mut tracker = AnomalyTracker::new(self.config.anomaly.clone());
            if let Some(profile) = self.clients.get(&client_ip).and_then(|c| c.collector.profile()) {
                tracker.set_expected_ttl(profile.verified_ttl, profile.ttl_tolerance);
            }
            self.flows.insert(key, FlowRec { tracker, last_seen: now });
        }
        let flow = self.flows.get_mut(&key).expect("flow inserted");
        flow.last_seen = now;
        let anomalies = flow.tracker.observe(packet, now);
        if !anomalies.is_empty() && self.probes.is_registered(client_ip) {
            self.probes.mark_suspected(client_ip, now);
        }
        anomalies
    }

    pub fn on_payload(&mut self, flow: FlowKey, payload: &[u8], now: SystemTime) -> ServerAction {
        if let Some(client) = self.clients.get_mut(&flow.src) {
            client.last_seen = now;
        }
        if let Some(rec) = self.flows.get_mut(&flow) {
            rec.last_seen = now;
        }
        self.refresh_authorization(flow.src, now);
        let kind = self.proof.classify(payload);
        let registered = self.probes.is_registered(flow.src);
        if !registered {
            let verdict = self.probes.evaluate(flow.src, now);
            let suspect = matches!(verdict, crate::ProbeVerdict::Suspect { .. });
            let probe_like = matches!(kind, ArrivalKind::HandshakeAttempt | ArrivalKind::Unrecognized);
            if suspect && probe_like {
                self.probes.suspect_correlated(flow.src, now);
                return self.decoy(now, false);
            }
            if matches!(kind, ArrivalKind::BaselineAsset) && !suspect {
                self.probes.register(flow.src, now);
                return ServerAction::ServeBaseline { embed: None };
            }
            if matches!(kind, ArrivalKind::BaselineAsset) {
                return ServerAction::ServeBaseline { embed: None };
            }
            return self.decoy(now, false);
        }
        let dirty = self.probes.is_suspected(flow.src, now) || self.flow_compromised(flow);
        match (dirty, kind) {
            (false, ArrivalKind::BaselineAsset) => ServerAction::ServeBaseline { embed: None },
            (false, ArrivalKind::HandshakeAttempt) if self.is_authorized(flow.src) => {
                ServerAction::AcceptHandshake
            }
            (false, ArrivalKind::HandshakeAttempt) | (false, ArrivalKind::Unrecognized) => {
                self.decoy(now, true)
            }
            (true, ArrivalKind::BaselineAsset) => ServerAction::ServeBaseline {
                embed: self.config.fallback.clone(),
            },
            (true, ArrivalKind::HandshakeAttempt) | (true, ArrivalKind::Unrecognized) => {
                self.decoy(now, true)
            }
        }
    }

    pub fn prune(&mut self, now: SystemTime) {
        self.probes.prune(now);
        let horizon = self.config.probe.critical_window * 2;
        self.clients.retain(|ip, client| {
            let recent = now.duration_since(client.last_seen).unwrap_or_default() <= horizon;
            recent || client.authorized || self.probes.is_suspected(*ip, now)
        });
        self.flows.retain(|key, flow| {
            let recent = now.duration_since(flow.last_seen).unwrap_or_default() <= horizon;
            recent || self.clients.contains_key(&key.src)
        });
    }

    fn refresh_authorization(&mut self, ip: Ipv4Addr, now: SystemTime) {
        let Some(client) = self.clients.get_mut(&ip) else {
            return;
        };
        if client.authorized {
            return;
        }
        let Some(ready_at) = client.ready_at else {
            return;
        };
        if now.duration_since(ready_at).unwrap_or_default() >= self.config.confirmation_quiet {
            client.authorized = true;
        }
    }

    fn is_authorized(&self, ip: Ipv4Addr) -> bool {
        self.clients.get(&ip).map(|client| client.authorized).unwrap_or(false)
    }

    fn flow_compromised(&self, flow: FlowKey) -> bool {
        self.flows.get(&flow).map(|rec| rec.tracker.is_compromised()).unwrap_or(false)
    }

    fn decoy(&mut self, now: SystemTime, include_fallback: bool) -> ServerAction {
        let mut message = self.generator.generate(now);
        if include_fallback {
            if let Some(directive) = self.config.fallback.clone() {
                self.carrier.embed(&mut message, &directive);
            }
        }
        ServerAction::Decoy { message }
    }
}
```

Export:

```rust
mod server;
pub use server::{ArrivalKind, HandshakeProof, ServerAction, ServerConfig, ServerEngine};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib server::tests -- --test-threads=8`

Expected: PASS, 5 tests.

If `quiet_period_gates_the_handshake` fails because the first baseline payload is at `when` and the profile’s `ready_at` is also `when`, the handshake at `when + 2s` is authorized. The handshake at `when + 1s` is not. That is the expected split.

- [ ] **Step 5: Commit**

```bash
git add src/server.rs src/lib.rs
git commit -m "feat: decide baseline, handshake, or decoy per session"
```

---

### Task 9: Client engine

**Files:**
- Create: `src/client.rs`
- Modify: `src/lib.rs`
- Test: `src/client.rs`

**Interfaces:**
- Consumes: `BaselineCollector`, `AnomalyTracker`, `screen`, `HeaderCarrier`, `Ipv4TcpPacket`
- Produces:
  - `ClientConfig { server: Ipv4Addr, server_port: u16, baseline: BaselineConfig, anomaly: AnomalyConfig, carrier_header: String }`
  - `ClientPacketDecision::{NeedMore { collected, required: usize }, ProfileLocked(RouteProfile), Forward, Drop(Anomaly), Unstable { collected: usize }}`
  - `ClientPayloadDecision::{Continue, Pivot(FallbackDirective)}`
  - `ClientEngine::new(ClientConfig) -> Self`
  - `observe_packet(&mut self, &Ipv4TcpPacket, SystemTime) -> ClientPacketDecision`
  - `observe_payload(&self, &[u8]) -> ClientPayloadDecision`
  - `profile(&self) -> Option<RouteProfile>`
  - `reset_baseline(&mut self)`

The packet that first returns `Ready` is passed through `AnomalyTracker::observe` before `set_expected_ttl`, then the expected TTL is installed. A clean locking sample therefore returns `ProfileLocked`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Anomaly, Ipv4TcpPacket, TcpFlags};
    use std::net::Ipv4Addr;
    use std::time::{Duration, UNIX_EPOCH};

    fn engine() -> ClientEngine {
        ClientEngine::new(ClientConfig {
            server: Ipv4Addr::new(198, 51, 100, 8),
            server_port: 443,
            baseline: crate::BaselineConfig::default(),
            anomaly: crate::AnomalyConfig::default(),
            carrier_header: "X-Request-Id".to_string(),
        })
    }

    fn synack(seq: u32, ttl: u8) -> Ipv4TcpPacket {
        Ipv4TcpPacket {
            src: Ipv4Addr::new(198, 51, 100, 8),
            dst: Ipv4Addr::new(203, 0, 113, 10),
            ttl,
            identification: 4,
            src_port: 443,
            dst_port: 40000,
            seq,
            ack: 1,
            flags: TcpFlags { fin: false, syn: true, rst: false, psh: false, ack: true },
            window: 65535,
            payload: Vec::new(),
        }
    }

    #[test]
    fn fifth_synack_locks_and_a_later_rst_is_dropped() {
        let mut client = engine();
        let when = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for seq in 0..4 {
            assert!(matches!(
                client.observe_packet(&synack(seq, 52), when),
                ClientPacketDecision::NeedMore { .. }
            ));
        }
        assert!(matches!(
            client.observe_packet(&synack(4, 52), when),
            ClientPacketDecision::ProfileLocked(profile) if profile.verified_ttl == 52 && profile.handshake_window == Some(65535)
        ));
        let mut rst = synack(8, 47);
        rst.flags.syn = false;
        rst.flags.rst = true;
        rst.identification = 0;
        rst.window = 0;
        assert!(matches!(
            client.observe_packet(&rst, when),
            ClientPacketDecision::Drop(Anomaly::RstZeroIpIdWithTtlShift { observed_ttl: 47 })
        ));
        let mut data = synack(9, 52);
        data.flags.syn = false;
        data.flags.psh = true;
        data.payload = b"HTTP/1.1 200 OK\r\nX-Request-Id: 8443;01010101010101010101010101010101\r\n\r\n".to_vec();
        assert!(matches!(client.observe_packet(&data, when), ClientPacketDecision::Forward));
        match client.observe_payload(&data.payload) {
            ClientPayloadDecision::Pivot(directive) => assert_eq!(directive.backup_port, 8443),
            other => panic!("expected pivot, got {other:?}"),
        }
    }

    #[test]
    fn other_sources_forward_and_reset_restarts_sampling() {
        let mut client = engine();
        let mut stray = synack(1, 10);
        stray.src = Ipv4Addr::new(1, 2, 3, 4);
        assert!(matches!(client.observe_packet(&stray, UNIX_EPOCH), ClientPacketDecision::Forward));
        client.reset_baseline();
        assert!(client.profile().is_none());
        assert!(matches!(
            client.observe_packet(&synack(1, 52), UNIX_EPOCH),
            ClientPacketDecision::NeedMore { collected: 1, .. }
        ));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib client::tests -- --test-threads=8`

Expected: FAIL to compile.

- [ ] **Step 3: Write minimal implementation**

```rust
use crate::{
    screen, Anomaly, AnomalyConfig, AnomalyTracker, BaselineCollector, BaselineConfig, BaselineStatus,
    FallbackDirective, FrameVerdict, HeaderCarrier, Ipv4TcpPacket, RouteProfile, Sample,
};
use std::net::Ipv4Addr;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server: Ipv4Addr,
    pub server_port: u16,
    pub baseline: BaselineConfig,
    pub anomaly: AnomalyConfig,
    pub carrier_header: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientPacketDecision {
    NeedMore { collected: usize, required: usize },
    ProfileLocked(RouteProfile),
    Forward,
    Drop(Anomaly),
    Unstable { collected: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientPayloadDecision {
    Continue,
    Pivot(FallbackDirective),
}

pub struct ClientEngine {
    config: ClientConfig,
    collector: BaselineCollector,
    tracker: AnomalyTracker,
    carrier: HeaderCarrier,
    locked: bool,
}

impl ClientEngine {
    pub fn new(config: ClientConfig) -> Self {
        let collector = BaselineCollector::new(config.baseline.clone(), config.server, config.server_port);
        let tracker = AnomalyTracker::new(config.anomaly.clone());
        let carrier = HeaderCarrier::new(config.carrier_header.clone());
        Self { config, collector, tracker, carrier, locked: false }
    }

    pub fn profile(&self) -> Option<RouteProfile> {
        self.collector.profile().cloned()
    }

    pub fn reset_baseline(&mut self) {
        self.collector.reset();
        self.tracker = AnomalyTracker::new(self.config.anomaly.clone());
        self.locked = false;
    }

    pub fn observe_packet(&mut self, packet: &Ipv4TcpPacket, now: SystemTime) -> ClientPacketDecision {
        if packet.src != self.config.server || packet.src_port != self.config.server_port {
            return ClientPacketDecision::Forward;
        }
        if !self.locked {
            let window = if packet.flags.syn && packet.flags.ack {
                Some(packet.window)
            } else {
                None
            };
            match self.collector.observe(Sample { ttl: packet.ttl, handshake_window: window }) {
                BaselineStatus::NeedMore { collected, required } => {
                    ClientPacketDecision::NeedMore { collected, required }
                }
                BaselineStatus::Unstable { collected } => ClientPacketDecision::Unstable { collected },
                BaselineStatus::Ready(profile) => {
                    self.locked = true;
                    let anomalies = self.tracker.observe(packet, now);
                    self.tracker.set_expected_ttl(profile.verified_ttl, profile.ttl_tolerance);
                    match anomalies.into_iter().next() {
                        Some(anomaly) => ClientPacketDecision::Drop(anomaly),
                        None => ClientPacketDecision::ProfileLocked(profile),
                    }
                }
            }
        } else {
            match screen(self.config.server, self.config.server_port, &mut self.tracker, packet, now) {
                FrameVerdict::Forward => ClientPacketDecision::Forward,
                FrameVerdict::Drop(anomaly) => ClientPacketDecision::Drop(anomaly),
            }
        }
    }

    pub fn observe_payload(&self, payload: &[u8]) -> ClientPayloadDecision {
        let text = String::from_utf8_lossy(payload);
        match self.carrier.extract(&text) {
            Some(directive) => ClientPayloadDecision::Pivot(directive),
            None => ClientPayloadDecision::Continue,
        }
    }
}
```

Export:

```rust
mod client;
pub use client::{ClientConfig, ClientEngine, ClientPacketDecision, ClientPayloadDecision};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib client::tests -- --test-threads=8`

Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add src/client.rs src/lib.rs
git commit -m "feat: screen server packets against the locked profile"
```

---

### Task 10: End-to-end session stories

**Files:**
- Create: `tests/session_story.rs`
- Test: `tests/session_story.rs`

**Interfaces:**
- Consumes: the public exports from tasks 2 through 9
- Produces: a binary integration test that runs one server engine and one client engine on the same scripted packets

- [ ] **Step 1: Write the failing test**

`tests/session_story.rs` cannot see private modules, so it uses only `gfwck::*` exports. The crate name in an integration test is `gfwck`.

```rust
use gfwck::{
    ArrivalKind, ClientConfig, ClientEngine, ClientPacketDecision, ClientPayloadDecision,
    FallbackDirective, FlowKey, HandshakeProof, Ipv4TcpPacket, ServerAction, ServerConfig,
    ServerEngine, TcpFlags,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct LabProof;
impl HandshakeProof for LabProof {
    fn classify(&self, payload: &[u8]) -> ArrivalKind {
        if payload.starts_with(b"GET /favicon.ico ") {
            ArrivalKind::BaselineAsset
        } else if payload.starts_with(b"PROOF ") {
            ArrivalKind::HandshakeAttempt
        } else {
            ArrivalKind::Unrecognized
        }
    }
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
}

fn server() -> ServerEngine<LabProof, StdRng> {
    let mut config = ServerConfig::default();
    config.fallback = Some(FallbackDirective { backup_port: 9443, token: [9u8; 16] });
    ServerEngine::new(config, LabProof, StdRng::seed_from_u64(4))
}

fn from_client(port: u16, seq: u32, ttl: u8, payload: &[u8]) -> Ipv4TcpPacket {
    Ipv4TcpPacket {
        src: Ipv4Addr::new(203, 0, 113, 10),
        dst: Ipv4Addr::new(198, 51, 100, 8),
        ttl,
        identification: 3,
        src_port: port,
        dst_port: 443,
        seq,
        ack: 0,
        flags: TcpFlags {
            fin: false,
            syn: payload.is_empty(),
            rst: false,
            psh: !payload.is_empty(),
            ack: !payload.is_empty(),
        },
        window: 64240,
        payload: payload.to_vec(),
    }
}

#[test]
fn client_drops_the_spoof_and_pivots_on_the_real_decoy() {
    let mut server = server();
    let mut client = ClientEngine::new(ClientConfig {
        server: Ipv4Addr::new(198, 51, 100, 8),
        server_port: 443,
        baseline: gfwck::BaselineConfig::default(),
        anomaly: gfwck::AnomalyConfig::default(),
        carrier_header: "X-Request-Id".to_string(),
    });
    for seq in 0..5 {
        let inbound = from_client(40000, seq, 52, b"");
        assert!(server.observe_packet(&inbound, t(0)).is_empty());
        let mut echo = inbound.clone();
        echo.src = inbound.dst;
        echo.dst = inbound.src;
        echo.src_port = 443;
        echo.dst_port = 40000;
        echo.flags.ack = true;
        let decision = client.observe_packet(&echo, t(0));
        if seq < 4 {
            assert!(matches!(decision, ClientPacketDecision::NeedMore { .. }));
        } else {
            assert!(matches!(decision, ClientPacketDecision::ProfileLocked(_)));
        }
    }
    let flow = FlowKey {
        src: Ipv4Addr::new(203, 0, 113, 10),
        src_port: 40000,
        dst: Ipv4Addr::new(198, 51, 100, 8),
        dst_port: 443,
    };
    server.on_payload(flow, b"GET /favicon.ico HTTP/1.1\r\n", t(2));
    let mut spoof = from_client(40000, 50, 40, b"");
    spoof.flags = TcpFlags { fin: false, syn: false, rst: true, psh: false, ack: true };
    spoof.identification = 0;
    spoof.window = 0;
    assert!(!server.observe_packet(&spoof, t(3)).is_empty());
    let action = server.on_payload(flow, b"PROOF v", t(3));
    let ServerAction::Decoy { message } = action else {
        panic!("server should decoy");
    };
    let bytes = message.to_bytes();
    let mut delivered = from_client(40000, 60, 52, &bytes);
    delivered.src = Ipv4Addr::new(198, 51, 100, 8);
    delivered.dst = Ipv4Addr::new(203, 0, 113, 10);
    delivered.src_port = 443;
    delivered.dst_port = 40000;
    delivered.ttl = 52;
    let mut client_spoof = delivered.clone();
    client_spoof.ttl = 47;
    client_spoof.identification = 0;
    client_spoof.seq = 59;
    client_spoof.flags.rst = true;
    client_spoof.flags.psh = false;
    client_spoof.payload.clear();
    assert!(matches!(client.observe_packet(&client_spoof, t(3)), ClientPacketDecision::Drop(_)));
    assert!(matches!(client.observe_packet(&delivered, t(3)), ClientPacketDecision::Forward));
    match client.observe_payload(&bytes) {
        ClientPayloadDecision::Pivot(directive) => assert_eq!(directive.backup_port, 9443),
        other => panic!("expected pivot, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test session_story -- --exact`

Expected: FAIL with `no test target named session_story` before the file from step 1 is saved. After the file is saved, run it again. Expected on a tree that already contains tasks 1–9: PASS. A failed assertion means the engine disagrees with the spec tables; fix the engine and keep the assertions.

- [ ] **Step 3: Write minimal implementation**

No new library code. The test file from step 1 is the implementation of this task. If an assertion fails, fix the engine so the spec tables hold, then re-run.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test session_story -- --exact`

Expected: PASS, 1 test.

Then run the full suite:

Run: `cargo test`

Expected: PASS, every unit test plus `session_story`.

- [ ] **Step 5: Commit**

```bash
git add tests/session_story.rs
git commit -m "test: cover the client and server fallback story"
```

---

### Task 11: Crate docs

**Files:**
- Modify: `src/lib.rs`
- Modify: `README.md`
- Test: rustdoc example inside `src/lib.rs`

**Interfaces:**
- Consumes: `parse_ipv4_tcp`, `write_ipv4_tcp`, `ServerEngine`
- Produces: a crate-level doc example that `cargo test --doc` runs

- [ ] **Step 1: Write the failing test**

Add this module docs at the top of `src/lib.rs`, above the `mod` lines:

```rust
//! Decision library for a baseline-driven decoy session.
//!
//! The host feeds [`Ipv4TcpPacket`] values and a clock. The library returns a
//! [`ServerAction`] or a [`ClientPacketDecision`]. It does not open sockets.
//!
//! ```
//! use gfwck::{parse_ipv4_tcp, write_ipv4_tcp, Ipv4TcpPacket, TcpFlags};
//! use std::net::Ipv4Addr;
//! let packet = Ipv4TcpPacket {
//!     src: Ipv4Addr::new(203, 0, 113, 10),
//!     dst: Ipv4Addr::new(198, 51, 100, 8),
//!     ttl: 52,
//!     identification: 1,
//!     src_port: 40000,
//!     dst_port: 443,
//!     seq: 1,
//!     ack: 0,
//!     flags: TcpFlags { fin: false, syn: true, rst: false, psh: false, ack: false },
//!     window: 64240,
//!     payload: Vec::new(),
//! };
//! let parsed = parse_ipv4_tcp(&write_ipv4_tcp(&packet).unwrap()).unwrap();
//! assert_eq!(parsed.ttl, 52);
//! ```

The example fails `cargo test --doc` until the public exports exist. They exist after task 9, so write the docs and run the doc test; a missing export is the failure this step is aimed at on a partial tree.

- [ ] **Step 2: Run test to verify it fails**

On a tree where the doc comment is not yet saved, `cargo test --doc` does not run this example. After saving the comment, run:

Run: `cargo test --doc`

Expected: PASS once exports from task 2 are public. If it fails, the missing name is the bug to fix in `src/lib.rs` re-exports.

- [ ] **Step 3: Write minimal implementation**

Replace `README.md` with:

```markdown
# gFwckYourself

`gfwck` is a Rust library that decides how a host should treat one session:

1. Sample ordinary packets and lock a TTL profile for that peer.
2. Flag a later segment whose TTL, sequence, or RST identity leaves the profile.
3. Score a follow-up address by age and prefix length.
4. Tell the host to serve its own baseline response, accept a host-defined handshake, or write a generated decoy.

The crate does not open sockets, capture interfaces, or carry application traffic. Callers pass `Ipv4TcpPacket` values and a `SystemTime`.

Design: [docs/superpowers/specs/2026-09-28-baseline-decoy-design.md](docs/superpowers/specs/2026-09-28-baseline-decoy-design.md).

```rust
use gfwck::{ClientEngine, ServerEngine};
```

Build and test with `cargo test`. No extra privileges are required.
```

The fenced `use` line in the README is documentation, not a compiled test. The compiled example is the crate docs from step 1.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test`

Expected: PASS, including the doc test.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs README.md
git commit -m "docs: describe the gfwck decision library"
```

---

## Spec coverage

| Spec requirement | Task |
|---|---|
| IPv4 TCP parse, Ethernet strip, FNV-1a, flow key | Task 2 |
| Mode TTL, integer 60 percent, lower median window, reset | Task 3 |
| Race, TTL shift, zero-IP-ID RST, window-0 RST ignored, `screen` | Task 4 |
| /24 /16 / foreign decay table, lease, correlated mark | Task 5 |
| Three decoy profiles, `Date`, `Content-Length` | Task 6 |
| Header carrier round trip | Task 7 |
| Quiet period, dirty directive, probe without directive, /24 stays clean, lease boundary | Task 8 |
| Client lock, drop, pivot, reset | Task 9 |
| Server and client on one scripted exchange | Task 10 |
| No sockets, public docs | Task 11 |

Out of scope, with no task in this plan: live capture, TUN, `smoltcp`, eBPF, firewall rules, IPv6.

## Self-review

- Types used in tasks 8–10 match the signatures produced in tasks 2–7.
- `screen` takes `now`. `write_ipv4_tcp` returns `Result`.
- The server decision function encodes both tables in the spec, including “baseline during a hot window is served and not enrolled” and “probe-like hot-window payload marks correlated clients”.
- No step leaves a requirement unnamed. Task 3's tie uses a 40 percent minimum because two tied modes cannot both reach 60 percent. Task 5 prunes at 90.001 seconds because the horizon check is inclusive.
- The Rust in tasks 2–11 was extracted and run with `cargo test` on Rust 1.83: 31 library tests, `session_story`, and the crate doctest passed.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-28-baseline-decoy.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
