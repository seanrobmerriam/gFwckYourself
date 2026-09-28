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
