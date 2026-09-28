# Baseline-Driven Decoy Session Library

Date: 2026-09-28

Repository: `gFwckYourself`

Crate name: `gfwck`

## Purpose

`gfwck` is a Rust library that helps an application run a session which looks like ordinary web traffic, watches the path for on-path packet injection, and chooses among three outcomes: keep serving the real baseline response, accept an application-defined handshake, or answer with a generated web decoy.

The operator runs both ends. The library decides what those ends should do. It does not open sockets, capture interfaces, or move user traffic.

## Why a decision library

The reference outline combines three I/O styles that cannot share one code path:

- A normal Tokio TCP listener, where the kernel has already accepted the segment.
- A passive capture that can read TTL and IP ID and cannot stop the kernel from acting on a segment.
- A user-space TCP stack, which can ignore a segment the kernel never sees.

Those styles stay outside the crate. The host feeds already-parsed observations in, and the crate returns a decision. A passive server and a user-space client call the same rules. Tests run the rules with synthetic packets and a clock the test controls.

## Scope of this version

In scope:

- IPv4 TCP header observations (TTL, IP ID, sequence, flags, window, payload).
- A route profile built from repeated samples on one remote IPv4 address and port.
- Per-flow anomaly flags: TTL outside the profile, a sequence observed twice with a different TTL or payload hash, and a RST whose IP ID is 0 and whose TTL is outside the profile.
- A time-decay score for a later connection, scaled by /32, /24, /16, or neither.
- Sticky suspicion for a registered client, held for a lease and then cleared.
- A confirmation quiet period between “profile ready” and “handshake allowed”.
- Three generated HTTP decoy profiles with a real `Date` and a `Content-Length` that matches the body.
- A header carrier that embeds and extracts a fallback directive.
- Server and client engines that apply the rules above.
- A frame screen a host can call before it hands bytes to any TCP stack, including a later `smoltcp` binding.

Out of scope for this version:

- Opening sockets, TUN devices, raw sockets, or packet-capture handles.
- `smoltcp`, eBPF/XDP, iptables, and nftables.
- IPv6, IP fragments, and VLAN tags.
- Encrypting or proxying application bytes.
- ASN or GeoIP databases.
- A wire handshake. The host classifies payload bytes. The crate never defines a magic string.

A later plan can bind `screen` to a capture device or a user-space stack. That binding is a consumer of this crate, and this version’s tests do not need root or a network interface.

## Outcomes the host can rely on

1. After enough agreeing samples, the engine locks one TTL and an optional handshake window for that peer.
2. A handshake payload is accepted only after the profile is locked, the quiet period has elapsed, the client is registered, the client is not inside a suspicion lease, and the flow is not compromised.
3. A compromised or suspected registered client receives either its real baseline response or a decoy, with a fallback directive attached when the host configured one.
4. An unregistered address whose decay score is at least the block threshold does not get a directive. A baseline-shaped request still gets a public baseline response and is not enrolled. Any other payload gets a decoy, and registered clients that correlate with that arrival are marked suspected.
5. The client engine drops a packet from the profiled server when the anomaly rules fire, and it surfaces a fallback directive when one is present in a payload it did not drop.
6. `cargo test` covers these outcomes with synthetic packets. No test opens a socket.

## Approaches considered

**Passive capture inside the library.** One background thread parses Ethernet frames and a Tokio listener serves HTTP. This matches the first sample in the outline, and it cannot discard a RST before the kernel does. The crate would also require privileges in every test.

**User-space TCP inside the library.** The crate owns a TUN device and `smoltcp`. The client can ignore injected RSTs. The server still needs a normal TCP socket so an on-path observer sees a finished HTTP exchange. One stack cannot play both roles, and the TUN path is not runnable in CI.

**Decision library with injected packets and an injected clock.** Chosen. Detection, scoring, decoys, and session phase live in pure functions. The host supplies packets and the current time. Server code keeps using the kernel TCP stack so a decoy is a normal socket write. Client code that must survive an injected RST calls `screen` and then delivers only the forwarded bytes to whatever stack it owns.

## Architecture

```text
host capture or test fixture
        │  Ipv4TcpPacket + SystemTime + payload bytes
        ▼
┌───────────────────────────────────────────┐
│ gfwck                                     │
│  packet   parse and write IPv4/TCP        │
│  baseline lock a route profile            │
│  anomaly  per-flow injection flags        │
│  probe    decay × prefix distance         │
│  decoy    HTTP response bytes             │
│  fallback embed and extract a directive   │
│  server   ServerAction                    │
│  client   ClientPacketDecision            │
└───────────────────────────────────────────┘
        │
        ▼
host serves a file, writes a decoy, accepts a handshake,
or passes the surviving bytes to its own TCP stack
```

Engines take `&mut self` and no lock. A host that shares an engine across tasks wraps it. The library does not log; every result is a return value.

Packet direction is the host’s job:

- The server engine is fed client-to-server packets. `src` is the client.
- The client engine is fed server-to-client packets. `src` is the server named in the client config. Other sources return `Forward`.

## Components

### Packet view (`packet`)

`parse_ipv4_tcp` reads an IPv4 datagram that starts at the version nibble. `ipv4_payload_from_ethernet` strips a standard 14-byte Ethernet header when the EtherType is `0x0800`.

Accepted datagrams use protocol 6 and are not fragmented (fragment offset 0 and MF clear). The parser honors IHL and the TCP data offset, ignores bytes past the IPv4 total length, and does not check checksums.

`write_ipv4_tcp` returns `Result<Vec<u8>, ParseError>`. It builds a header without options and with checksum fields set to 0. A payload that would push the IPv4 total length past 65535 yields `ParseError`.

```rust
pub struct TcpFlags { pub fin: bool, pub syn: bool, pub rst: bool, pub psh: bool, pub ack: bool }

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

pub struct FlowKey {
    pub src: Ipv4Addr,
    pub src_port: u16,
    pub dst: Ipv4Addr,
    pub dst_port: u16,
}
```

`FlowKey::from_packet` copies the four-tuple. Session flags that describe one TCP connection use this key. Route TTL is stored per client address, because the path hop count is a property of the route rather than of one source port.

Payload identity for race checks is FNV-1a 64-bit over the payload bytes (`fnv1a64`). The tracker stores the hash, the sequence, the TTL, and the time. It does not store the payload.

### Baseline (`baseline`)

`BaselineCollector` records samples for one `(peer, peer_port)`.

```rust
pub struct Sample {
    pub ttl: u8,
    pub handshake_window: Option<u16>,
}

pub enum BaselineStatus {
    NeedMore { collected: usize, required: usize },
    Ready(RouteProfile),
    Unstable { collected: usize },
}

pub struct RouteProfile {
    pub peer: Ipv4Addr,
    pub peer_port: u16,
    pub verified_ttl: u8,
    pub ttl_tolerance: u8,
    pub handshake_window: Option<u16>,
    pub sample_count: usize,
}
```

Rules:

- Each `observe` call counts as one TTL sample. Once the profile is locked, later calls return the same `Ready` profile.
- The verified TTL is the mode. Ties break toward the larger TTL.
- The profile locks once `samples >= required_samples` and `mode_count * 100 >= samples * mode_min_percent`.
- Otherwise collection continues. At `max_samples` the status is `Unstable`.
- `handshake_window` is the lower median of the window values the host chose to pass. The server passes the window from the client SYN (`SYN` set, `ACK` clear). The client passes the window from the server SYN-ACK (both set). An empty window list yields `None`.
- `reset` clears samples and the lock, and keeps the peer and the config.
- `profile` returns the locked `RouteProfile` after `Ready`, and `None` before that.

Defaults: `required_samples = 5`, `mode_min_percent = 60`, `max_samples = 15`, `ttl_tolerance = 3`.

Integer percent avoids treating `3/5` as less than `0.6` under binary floating point. Three matching samples out of five lock the profile. Two out of five do not.

### Anomaly tracker (`anomaly`)

```rust
pub enum Anomaly {
    TtlShift { expected: u8, observed: u8 },
    InjectionRace { seq: u32 },
    RstZeroIpIdWithTtlShift { observed_ttl: u8 },
}

pub enum FrameVerdict {
    Forward,
    Drop(Anomaly),
}
```

`AnomalyTracker::observe` always records the segment for race detection.

- **Injection race.** Inside `race_window`, the same sequence appears again with a different TTL or a different payload hash. A repeat with the same TTL and the same hash is a retransmission and produces no anomaly.
- **TTL shift.** Once an expected TTL is set, `abs(expected - observed) > ttl_tolerance` records `TtlShift`.
- **RST with a zero IP ID.** If that TTL shift is on a segment with RST set and IP ID 0, the recorded anomaly is `RstZeroIpIdWithTtlShift` instead of `TtlShift`.
- A RST with window 0, a matching TTL, and a non-zero IP ID produces no anomaly.
- A zero IP ID with a matching TTL produces no anomaly.
- Any returned anomaly sets `compromised` for the life of that tracker.

`screen(remote, remote_port, tracker, packet, now)` returns `Forward` when the packet source is not that remote. Otherwise it returns `Drop` of the first anomaly, or `Forward`.

Defaults: `race_window = 2s`, `history_limit = 64`.

### Probe monitor (`probe`)

```rust
pub enum SubnetRelation {
    ExactMatch,       // same address
    LocalSubnet24,    // same /24
    RegionalSubnet16, // same /16, different /24
    ForeignNetwork,
}

pub enum ProbeVerdict {
    Known { score: f64 },
    Allow { score: f64 },
    Suspect { score: f64 },
}
```

`subnet_relation` compares octets. No routing table is consulted.

`evaluate(incoming, now)`:

- A registered address returns `Known` with score `0.0`.
- Every other registered session whose age is at most `critical_window * 2` contributes `exp(-age_seconds / critical_window_seconds) * coefficient`.
- The verdict uses the maximum of those scores. A score greater than or equal to `block_threshold` is `Suspect`. Anything lower is `Allow`. No registered sessions yields `Allow` with score `0.0`.

Coefficients:

| Relation | Coefficient |
|---|---|
| Exact match | 0.0 |
| /24 | 0.15 |
| /16 | 0.50 |
| Neither | 1.00 |

Worked checks used by tests, with a 45 second window:

| Age | Relation | Score | Verdict at threshold 0.65 |
|---|---|---|---|
| 3.5 s | /24 | `exp(-3.5/45) * 0.15` ≈ 0.139 | Allow |
| 12 s | /16 | `exp(-12/45) * 0.50` ≈ 0.383 | Allow |
| 6 s | foreign | `exp(-6/45)` ≈ 0.875 | Suspect |
| 8 s | foreign | `exp(-8/45)` ≈ 0.837 | Suspect |

`register` records the arrival time. `mark_suspected` sets `suspected_until = now + lease` on an address that is already registered. `suspect_correlated` marks every registered session whose own pairwise score against this arrival is at least the threshold. `is_suspected` is true while `now < suspected_until`. `prune` drops a session when its suspicion has expired and its arrival is older than the horizon.

Defaults: `critical_window = 45s`, `block_threshold = 0.65`, coefficients as the table, `lease = 600s`.

Prefix distance is a heuristic. A /16 is a large set of addresses, and two unrelated clients can share one. The score exists to slow enrollment during the hot window, which is the behavior under “Decision tables”.

### Decoy generator (`decoy`)

```rust
pub enum DecoyProfile {
    NginxWelcome,      // 200
    ApacheNotFound,    // 404
    CloudflareDenied,  // 403
}

pub struct HttpMessage {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
```

`DecoyGenerator::generate(now)` fills a profile-specific body and headers. The `Date` value is the UTC time of `now`, formatted as an IMF-fixdate ending in the literal `GMT` (`%a, %d %b %Y %H:%M:%S GMT`). Spacer length, cookie, debug id, and ray id come from the caller-supplied `Rng`.

`HttpMessage::to_bytes` writes the status line and headers, replaces any `Content-Length` with the body’s length, and appends the body. Header names and values contain no CR or LF; the generator does not accept them from outside the crate except through `set_header`. `set_header` replaces an existing name case-insensitively.

Profile signatures:

- Nginx: `Server: nginx/1.24.0 (Ubuntu)`, HTML contains `Welcome to nginx!`, `Set-Cookie` begins with `SESSIONID=`.
- Apache: `Server: Apache/2.4.52 (Unix) OpenSSL/1.1.1t`, status 404, body contains `404 Not Found`.
- Cloudflare: status 403, a `CF-RAY` header ending in `-SJC`, body contains `CF Ray ID:`.

`Connection: close` is present on every profile.

### Fallback carrier (`fallback`)

```rust
pub struct FallbackDirective {
    pub backup_port: u16,
    pub token: [u8; 16],
}

pub struct HeaderCarrier {
    pub header_name: String,
}
```

`embed` sets the header to `{backup_port};{token as 32 lowercase hex chars}`. `extract` finds that header in an HTTP message and parses it. A bad port, a bad token length, or a missing header returns `None`. Header-name match is case-insensitive.

The default header name is `X-Request-Id`. Any fixed name can be learned by an observer. This carrier is the v1 mechanism so a client can recover a port and a token; a host with a private encoding can write a different carrier later without changing session rules. The library has no second carrier in this version.

A directive is attached only in the cases listed in the decision tables. Probe responses omit it.

### Server engine (`server`)

```rust
pub enum ArrivalKind {
    BaselineAsset,
    HandshakeAttempt,
    Unrecognized,
}

pub trait HandshakeProof {
    fn classify(&self, payload: &[u8]) -> ArrivalKind;
}

pub enum ServerAction {
    ServeBaseline { embed: Option<FallbackDirective> },
    AcceptHandshake,
    Decoy { message: HttpMessage },
}
```

`HandshakeProof` belongs to the host. Tests use a classifier that looks for the prefixes `GET /favicon.ico ` and `PROOF `. Those prefixes are fixtures, not a protocol.

`ServerConfig` holds the baseline, anomaly, and probe configs, plus:

- `confirmation_quiet` default `2s`
- `decoy_profile`
- `carrier_header` default `X-Request-Id`
- `fallback: Option<FallbackDirective>`

State:

- Per client address: a collector, `ready_at`, and `authorized`.
- Per `FlowKey`: an `AnomalyTracker`.
- One `ProbeMonitor`.

`observe_packet(packet, now) -> Vec<Anomaly>`:

- Ensures a collector for `packet.src`.
- Feeds a sample. The handshake window is included only when SYN is set and ACK is clear.
- On the transition to `Ready`, sets `ready_at` if it was empty, and installs the expected TTL on every tracker whose flow source is that address.
- Observes the packet on its flow tracker and returns that tracker’s anomalies. A non-empty result marks the flow compromised. It also marks the registered client suspected when that address is registered.

`on_payload(flow, payload, now) -> ServerAction` uses `flow.src` as the client and follows the decision tables. `prune(now)` drops expired probe sessions and drops client or flow state whose last activity is older than the probe horizon and that is neither authorized nor inside a suspicion lease.

Authorization becomes true on a later `on_payload` for that address once `ready_at` is set and `now.duration_since(ready_at) >= confirmation_quiet`. A clock step backward is treated as a zero duration, so it does not authorize early.

### Client engine (`client`)

```rust
pub enum ClientPacketDecision {
    NeedMore { collected: usize, required: usize },
    ProfileLocked(RouteProfile),
    Forward,
    Drop(Anomaly),
    Unstable { collected: usize },
}

pub enum ClientPayloadDecision {
    Continue,
    Pivot(FallbackDirective),
}
```

`observe_packet` ignores packets whose source address or source port is not the configured server, and returns `Forward`.

Until a profile locks, each packet from the server is a sample. The handshake window is recorded when both SYN and ACK are set. `NeedMore`, `ProfileLocked`, and `Unstable` all mean the host may deliver this packet. `ProfileLocked` means later packets use the anomaly rules. `Unstable` means the host should call `reset_baseline` before trusting the route.

After the lock, `screen` decides `Forward` or `Drop`.

`observe_payload` returns `Pivot` when the carrier extracts a directive, and `Continue` otherwise.

`profile` returns the locked route profile once sampling has reached `Ready`. The packet that causes the lock is recorded for later race checks and is returned as `ProfileLocked` when that recording produced no anomaly. Expected-TTL checks apply to later packets, so a clean sample that completes the profile is delivered.

## Decision tables

`Registered` means `ProbeMonitor::register` has run for that address. Registration happens only when an unregistered address is `Allow` or `Known` and the payload is `BaselineAsset`.

Suspicion and flow compromise apply only after registration. A high score against someone else does not by itself register the new address.

### Unregistered address

| Probe verdict | Arrival kind | Action | Enroll | Mark correlated clients |
|---|---|---|---|---|
| Suspect | BaselineAsset | `ServeBaseline { embed: None }` | no | no |
| Suspect | HandshakeAttempt or Unrecognized | `Decoy` with no directive | no | yes |
| Allow | BaselineAsset | `ServeBaseline { embed: None }` | yes | no |
| Allow | HandshakeAttempt or Unrecognized | `Decoy` with no directive | no | no |

A visitor who only fetches the public asset during a hot window receives that asset and can try again after the score falls. An arrival that is not a baseline asset, while the score is hot, is treated as probe behavior: the answer is a decoy, and the earlier clients that produced the high score enter the suspicion lease.

### Registered address

Evaluate `authorized` from the quiet period before matching this table. `Dirty` means the suspicion lease is active or this flow’s tracker is compromised.

| Dirty | Arrival kind | Authorized | Action |
|---|---|---|---|
| no | BaselineAsset | either | `ServeBaseline { embed: None }` |
| no | HandshakeAttempt | yes | `AcceptHandshake` |
| no | HandshakeAttempt | no | `Decoy` with directive if configured |
| no | Unrecognized | either | `Decoy` with directive if configured |
| yes | BaselineAsset | either | `ServeBaseline { embed: Some(directive) }` when configured, else `None` |
| yes | HandshakeAttempt or Unrecognized | either | `Decoy` with directive if configured |

When no directive is configured, the `embed` field is `None` and the decoy message has no carrier header. The HTTP status and body are still produced.

`ServeBaseline` does not include a body. The host serves its own asset and, when `embed` is set, runs `HeaderCarrier::embed` on that response before writing it.

## Data flow

### Clean upgrade

1. Client SYN and data packets reach `observe_packet` until the collector returns `Ready`.
2. The host waits out `confirmation_quiet`.
3. A baseline payload enrolls the address and, once the quiet period has elapsed, sets `authorized`.
4. A later payload classified as `HandshakeAttempt` returns `AcceptHandshake`.
5. Bytes after that point belong to the host. The crate does not read them.

### On-path injection

1. The profile TTL is locked.
2. A segment on that flow arrives with a TTL outside the tolerance, or a repeated sequence with a different hash or TTL.
3. `observe_packet` returns the anomaly and marks the flow compromised. A registered client also starts a suspicion lease.
4. The next payload from that client follows the dirty row of the registered table. The decoy or the baseline response can carry the directive.
5. The client engine, seeing the injected segment, returns `Drop`. A later segment whose TTL matches the profile returns `Forward`. `observe_payload` on that payload returns `Pivot`.

The server half is written on a normal TCP socket so the observer sees a completed HTTP response and a close. The client half can only ignore an injected RST if its host refrains from delivering `Drop` packets to the kernel. `screen` is the function that host calls. This crate does not install firewall rules.

### Active probe

1. A registered client exists.
2. Within the horizon, a new address in a foreign prefix sends a payload that is not a baseline asset, and the decay score is at least `0.65`.
3. That connection receives a decoy with no directive and is not enrolled.
4. The registered client is suspected until the lease ends, so its handshake attempts take the dirty row.
5. After `suspected_until`, a handshake is eligible again if the flow itself was never compromised.

## Error handling

| Condition | Result |
|---|---|
| Truncated, non-IPv4, non-TCP, or fragmented datagram | `ParseError` from the parser. Engines do not see it. |
| Ethernet frame with a different EtherType | `ParseError` |
| Baseline still below the mode percent at `max_samples` | `Unstable`. The server never authorizes that collector until `reset`. The client returns `Unstable`. |
| `fallback` is `None` | Actions that would attach a directive omit it. |
| `now` earlier than a stored timestamp | Duration is zero. Suspicion checks use the same `now` the host passed in. |
| Header value that fails directive parsing | `extract` returns `None`. The client continues. |

`ParseError` carries a static reason string. Library paths do not panic on packet input.

## Testing

All tests are `cargo test` on the host crate. They construct datagrams with `write_ipv4_tcp`, drive engines with `SystemTime` values, and use `StdRng::seed_from_u64` for decoy bytes.

Required stories:

1. Five equal TTLs lock the mode. A 3/5 split locks. A split that never reaches 60 percent by `max_samples` is `Unstable`. The lower median window is stored.
2. A retransmission is quiet. The same sequence with a different payload hash is `InjectionRace`. A TTL delta of 4 is `TtlShift`. A RST with IP ID 0 and that delta is `RstZeroIpIdWithTtlShift`. A RST with window 0 and the expected TTL is quiet.
3. The four rows of the probe score table produce Allow, Allow, Suspect, Suspect.
4. Decoy bytes contain the profile signature, a `Date` equal to the injected time, and a `Content-Length` equal to the body. Two seeds differ. `set_header` keeps `Content-Length` correct.
5. A directive round-trips through a decoy. A probe decoy has no carrier header.
6. Clean path: samples, quiet period, baseline payload, handshake payload, `AcceptHandshake`. A handshake before the quiet period is a decoy with a directive.
7. After authorization, an injected RST marks the flow and the next handshake is a decoy with a directive.
8. Foreign arrival 6 seconds later with an unrecognized payload decoys that arrival without a directive and sends the registered client down the dirty path. A /24 arrival 3.5 seconds later with a baseline payload is served and enrolled, and the first client stays clean.
9. Suspicion at `lease` boundary: `now < suspected_until` still dirty; equal timestamp is clean again if the flow is intact.
10. Client: five SYN-ACKs lock the profile; a RST at TTL `expected - 5` is `Drop`; the following matching HTTP payload is `Forward` and `Pivot`.

## Project layout

```text
Cargo.toml
src/lib.rs
src/packet.rs
src/baseline.rs
src/anomaly.rs
src/probe.rs
src/decoy.rs
src/fallback.rs
src/server.rs
src/client.rs
tests/session_story.rs
README.md
```

Public types are re-exported from `src/lib.rs`. Modules stay private except through those exports.

## Global constraints

- Edition `2021`. Rust `1.74` minimum.
- Crate name `gfwck`.
- Dependencies: `chrono` `0.4.39` (formatting UTC), `rand` `0.8` (decoy entropy and `StdRng`). No Tokio, `pnet`, `smoltcp`, or `pcap` in this crate.
- No `unsafe`.
- No background threads and no process-global maps.
- IPv4 only.
- Checksums are not verified.
- Default numbers, copied for the plan: TTL tolerance `3`; baseline samples `5`; mode percent `60`; max samples `15`; race window `2` seconds; race history `64`; probe window `45` seconds; block threshold `0.65`; /24 coefficient `0.15`; /16 coefficient `0.50`; foreign coefficient `1.0`; suspicion lease `600` seconds; confirmation quiet period `2` seconds; carrier header `X-Request-Id`.
- Library code contains no protocol banner and no magic handshake constant.

## Later work

A follow-on can add a host binary that reads frames, calls `ipv4_payload_from_ethernet` and `ClientEngine::observe_packet`, and forwards `Forward` / `NeedMore` / `ProfileLocked` bytes into a user-space stack. Another can accept kernel TCP connections and call `ServerEngine`. Neither binary belongs in this version, because each needs privileges or a network and neither changes the decisions specified here.

## Spec review notes

- Placeholder scan: no open requirements. Defaults are numeric. `write_ipv4_tcp` returns `Result`. `screen` takes `now`.
- Consistency: server and client share `BaselineCollector`, `AnomalyTracker`, `DecoyGenerator`, and `HeaderCarrier`. Session phase is expressed by `ready_at`, `authorized`, tracker `compromised`, and probe suspicion rather than a separate phase enum.
- Scope: one crate, one implementation plan. Capture and user-space TCP are consumers.
- Ambiguity closed: baseline bodies belong to the host; decoy bodies belong to the crate; directives ride only on the registered dirty paths and on the “handshake too early / unrecognized but registered” paths; a hot-window stranger who fetches the public asset is not enrolled and does not taint existing clients.
