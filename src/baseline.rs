use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineConfig {
    pub required_samples: usize,
    pub mode_min_percent: u8,
    pub max_samples: usize,
    pub ttl_tolerance: u8,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            required_samples: 5,
            mode_min_percent: 60,
            max_samples: 15,
            ttl_tolerance: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub ttl: u8,
    pub handshake_window: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProfile {
    pub peer: Ipv4Addr,
    pub peer_port: u16,
    pub verified_ttl: u8,
    pub ttl_tolerance: u8,
    pub handshake_window: Option<u16>,
    pub sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineStatus {
    NeedMore { collected: usize, required: usize },
    Ready(RouteProfile),
    Unstable { collected: usize },
}

#[derive(Debug, Clone)]
pub struct BaselineCollector {
    config: BaselineConfig,
    peer: Ipv4Addr,
    peer_port: u16,
    ttl_histogram: HashMap<u8, usize>,
    windows: Vec<u16>,
    samples: usize,
    locked: Option<RouteProfile>,
    unstable: bool,
}

impl BaselineCollector {
    pub fn new(config: BaselineConfig, peer: Ipv4Addr, peer_port: u16) -> Self {
        Self {
            config,
            peer,
            peer_port,
            ttl_histogram: HashMap::new(),
            windows: Vec::new(),
            samples: 0,
            locked: None,
            unstable: false,
        }
    }

    pub fn profile(&self) -> Option<&RouteProfile> {
        self.locked.as_ref()
    }

    pub fn reset(&mut self) {
        self.ttl_histogram.clear();
        self.windows.clear();
        self.samples = 0;
        self.locked = None;
        self.unstable = false;
    }

    pub fn observe(&mut self, sample: Sample) -> BaselineStatus {
        if let Some(profile) = &self.locked {
            return BaselineStatus::Ready(profile.clone());
        }
        if self.unstable {
            return BaselineStatus::Unstable { collected: self.samples };
        }
        *self.ttl_histogram.entry(sample.ttl).or_insert(0) += 1;
        if let Some(window) = sample.handshake_window {
            self.windows.push(window);
        }
        self.samples += 1;
        if self.samples < self.config.required_samples {
            return BaselineStatus::NeedMore {
                collected: self.samples,
                required: self.config.required_samples,
            };
        }
        let (mode_ttl, mode_count) = mode_ttl(&self.ttl_histogram);
        let percent = u32::from(self.config.mode_min_percent);
        if (mode_count as u32) * 100 < (self.samples as u32) * percent {
            if self.samples >= self.config.max_samples {
                self.unstable = true;
                return BaselineStatus::Unstable { collected: self.samples };
            }
            return BaselineStatus::NeedMore {
                collected: self.samples,
                required: self.config.required_samples,
            };
        }
        let profile = RouteProfile {
            peer: self.peer,
            peer_port: self.peer_port,
            verified_ttl: mode_ttl,
            ttl_tolerance: self.config.ttl_tolerance,
            handshake_window: lower_median(&self.windows),
            sample_count: self.samples,
        };
        self.locked = Some(profile.clone());
        BaselineStatus::Ready(profile)
    }
}

fn mode_ttl(hist: &HashMap<u8, usize>) -> (u8, usize) {
    let mut best_ttl = 0u8;
    let mut best_count = 0usize;
    for (&ttl, &count) in hist {
        if count > best_count || (count == best_count && ttl > best_ttl) {
            best_ttl = ttl;
            best_count = count;
        }
    }
    (best_ttl, best_count)
}

fn lower_median(values: &[u16]) -> Option<u16> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mid = (sorted.len() - 1) / 2;
    Some(sorted[mid])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn collector() -> BaselineCollector {
        BaselineCollector::new(
            BaselineConfig::default(),
            Ipv4Addr::new(203, 0, 113, 10),
            443,
        )
    }

    #[test]
    fn five_equal_ttls_lock_the_mode_and_lower_median_window() {
        let mut c = collector();
        assert_eq!(BaselineConfig::default().ttl_tolerance, 3);
        assert_eq!(BaselineConfig::default().required_samples, 5);
        for window in [10u16, 40, 20, 30] {
            let status = c.observe(Sample { ttl: 52, handshake_window: Some(window) });
            assert!(matches!(status, BaselineStatus::NeedMore { .. }));
        }
        let status = c.observe(Sample { ttl: 52, handshake_window: None });
        match status {
            BaselineStatus::Ready(profile) => {
                assert_eq!(profile.verified_ttl, 52);
                assert_eq!(profile.handshake_window, Some(20));
                assert_eq!(profile.sample_count, 5);
                assert_eq!(profile.peer_port, 443);
            }
            other => panic!("expected ready, got {other:?}"),
        }
        assert!(c.profile().is_some());
        let again = c.observe(Sample { ttl: 9, handshake_window: Some(1) });
        assert!(matches!(again, BaselineStatus::Ready(p) if p.verified_ttl == 52));
    }

    #[test]
    fn three_of_five_locks_and_a_tie_prefers_the_higher_ttl() {
        let mut c = collector();
        for ttl in [40u8, 40, 52, 52, 52] {
            let _ = c.observe(Sample { ttl, handshake_window: None });
        }
        assert!(matches!(c.profile(), Some(p) if p.verified_ttl == 52));

        // 2/5 is 40 percent. With the minimum set to 40, 10 and 20 tie and 20 wins.
        let mut tied = BaselineCollector::new(
            BaselineConfig {
                required_samples: 5,
                mode_min_percent: 40,
                max_samples: 15,
                ttl_tolerance: 3,
            },
            Ipv4Addr::new(203, 0, 113, 10),
            443,
        );
        for ttl in [10u8, 10, 20, 20, 30] {
            let _ = tied.observe(Sample { ttl, handshake_window: None });
        }
        assert!(matches!(tied.profile(), Some(p) if p.verified_ttl == 20));
    }

    #[test]
    fn unbalanced_samples_become_unstable_at_the_cap() {
        let mut c = BaselineCollector::new(
            BaselineConfig {
                required_samples: 4,
                mode_min_percent: 60,
                max_samples: 4,
                ttl_tolerance: 3,
            },
            Ipv4Addr::LOCALHOST,
            1,
        );
        let mut last = BaselineStatus::NeedMore { collected: 0, required: 4 };
        for ttl in [1u8, 1, 2, 2] {
            last = c.observe(Sample { ttl, handshake_window: None });
        }
        assert!(matches!(last, BaselineStatus::Unstable { collected: 4 }));
    }

    #[test]
    fn reset_clears_a_locked_profile() {
        let mut c = collector();
        for _ in 0..5 {
            let _ = c.observe(Sample { ttl: 52, handshake_window: None });
        }
        c.reset();
        assert!(c.profile().is_none());
        assert!(matches!(c.observe(Sample { ttl: 7, handshake_window: None }), BaselineStatus::NeedMore { collected: 1, .. }));
    }
}
