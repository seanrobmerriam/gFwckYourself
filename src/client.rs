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
