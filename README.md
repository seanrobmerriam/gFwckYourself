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
