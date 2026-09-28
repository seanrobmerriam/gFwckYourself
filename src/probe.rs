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
        Self {
            config,
            sessions: HashMap::new(),
        }
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
            let suspected = session
                .suspected_until
                .map(|until| now < until)
                .unwrap_or(false);
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
