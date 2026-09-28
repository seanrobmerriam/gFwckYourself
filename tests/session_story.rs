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
