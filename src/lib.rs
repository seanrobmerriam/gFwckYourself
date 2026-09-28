mod anomaly;
mod baseline;
mod packet;

pub use anomaly::{screen, Anomaly, AnomalyConfig, AnomalyTracker, FrameVerdict};
pub use baseline::{BaselineCollector, BaselineConfig, BaselineStatus, RouteProfile, Sample};
pub use packet::{
    fnv1a64, ipv4_payload_from_ethernet, parse_ipv4_tcp, write_ipv4_tcp, FlowKey, Ipv4TcpPacket,
    ParseError, TcpFlags,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(env!("CARGO_PKG_NAME"), "gfwck");
    }
}
