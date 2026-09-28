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
