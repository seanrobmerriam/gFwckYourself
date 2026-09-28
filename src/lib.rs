mod anomaly;
mod baseline;
mod decoy;
mod fallback;
mod packet;
mod probe;

pub use anomaly::{screen, Anomaly, AnomalyConfig, AnomalyTracker, FrameVerdict};
pub use baseline::{BaselineCollector, BaselineConfig, BaselineStatus, RouteProfile, Sample};
pub use decoy::{DecoyGenerator, DecoyProfile, HttpMessage};
pub use fallback::{FallbackDirective, HeaderCarrier};
pub use packet::{
    fnv1a64, ipv4_payload_from_ethernet, parse_ipv4_tcp, write_ipv4_tcp, FlowKey, Ipv4TcpPacket,
    ParseError, TcpFlags,
};
pub use probe::{subnet_relation, ProbeConfig, ProbeMonitor, ProbeVerdict, SubnetRelation};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(env!("CARGO_PKG_NAME"), "gfwck");
    }
}
