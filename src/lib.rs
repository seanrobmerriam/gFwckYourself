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

mod anomaly;
mod baseline;
mod client;
mod decoy;
mod fallback;
mod packet;
mod probe;
mod server;

pub use anomaly::{screen, Anomaly, AnomalyConfig, AnomalyTracker, FrameVerdict};
pub use baseline::{BaselineCollector, BaselineConfig, BaselineStatus, RouteProfile, Sample};
pub use client::{ClientConfig, ClientEngine, ClientPacketDecision, ClientPayloadDecision};
pub use decoy::{DecoyGenerator, DecoyProfile, HttpMessage};
pub use fallback::{FallbackDirective, HeaderCarrier};
pub use packet::{
    fnv1a64, ipv4_payload_from_ethernet, parse_ipv4_tcp, write_ipv4_tcp, FlowKey, Ipv4TcpPacket,
    ParseError, TcpFlags,
};
pub use probe::{subnet_relation, ProbeConfig, ProbeMonitor, ProbeVerdict, SubnetRelation};
pub use server::{ArrivalKind, HandshakeProof, ServerAction, ServerConfig, ServerEngine};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(env!("CARGO_PKG_NAME"), "gfwck");
    }
}
