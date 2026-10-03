//! Bounded, fair runtime scheduling and public diagnostics for the VPN pool.
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug, Serialize)]
pub struct PoolEvent {
    pub timestamp: u64,
    pub server_ref: Option<String>,
    pub outcome: &'static str,
}

#[derive(Clone, Default, Debug, Serialize)]
pub struct PoolRuntime {
    #[serde(skip)]
    cursor: usize,
    pub last_probe: Option<PoolEvent>,
    pub next_attempt_unix: u64,
    pub transitions: VecDeque<PoolEvent>,
}

impl PoolRuntime {
    pub fn next(
        &self,
        refs: &[String],
        available: &[String],
        cooldown: &HashMap<String, u64>,
        now: u64,
    ) -> Option<String> {
        (0..refs.len())
            .map(|offset| &refs[(self.cursor + offset) % refs.len()])
            .find(|reference| {
                available.contains(reference)
                    && cooldown.get(*reference).is_none_or(|until| *until <= now)
            })
            .cloned()
    }

    pub fn record(
        &mut self,
        refs: &[String],
        reference: Option<String>,
        outcome: &'static str,
        now: u64,
        selected: bool,
    ) {
        if let Some(index) = reference
            .as_ref()
            .and_then(|reference| refs.iter().position(|item| item == reference))
        {
            self.cursor = (index + 1) % refs.len().max(1);
        }
        let event = PoolEvent {
            timestamp: now,
            server_ref: reference,
            outcome,
        };
        self.last_probe = Some(event.clone());
        self.next_attempt_unix = now + if selected { 60 } else { 10 };
        if self.transitions.back().is_none_or(|previous| {
            previous.server_ref != event.server_ref || previous.outcome != event.outcome
        }) {
            self.transitions.push_back(event);
            while self.transitions.len() > 20 {
                self.transitions.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_cooldowns_cannot_starve_last_of_sixteen_members() {
        let refs: Vec<_> = (0..16)
            .map(|index| format!("srv-v1-test-{index}"))
            .collect();
        let mut runtime = PoolRuntime::default();
        let mut cooldown = HashMap::new();
        let mut seen = Vec::new();
        for index in 0..32 {
            let now = index * 64;
            let next = runtime
                .next(&refs, &refs, &cooldown, now)
                .expect("candidate");
            seen.push(next.clone());
            cooldown.insert(next.clone(), now + 900);
            runtime.record(&refs, Some(next), "upstream_unreachable", now, false);
        }
        assert_eq!(&seen[..16], &refs);
        assert_eq!(&seen[16..], &refs);
        assert!(runtime.transitions.len() <= 20);
    }
}
