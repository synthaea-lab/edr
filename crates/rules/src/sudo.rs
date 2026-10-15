//! A local privilege-escalation success (`sudo`/`su`) that follows authentication
//! failures for the same target account, T1548.003 (Sudo and Sudo Caching, #381).
//!
//! Both sides come from the same `AuthEvent` stream (`RuleState::on_auth`, one
//! journal tail, unlike T1021.001's two independent Windows event channels), so
//! out-of-order delivery is less likely here than for [`crate::rdp`] — but nothing
//! in `schema::AuthEvent` promises journal records arrive in timestamp order
//! (a restart replaying a backlog, a buffered writer), so this joins on event
//! time the same way, for the same reason: counting only what already arrived
//! would make the alert depend on delivery order.
//!
//! Keyed by `AuthEvent::target_user` alone, not by an external address — a local
//! privilege elevation has no remote origin to key on, and
//! `AuthEvent::source_address` is always `None` for it (see
//! `sensor-linux-journal::auth`'s module doc). That field is `su`'s real target
//! (`root`, or whoever `su` names) but `sudo`'s *invoker* — `sensor-linux-journal`
//! puts the one value there that a sudo failure and the success after it share,
//! since PAM authenticates the invoker for `sudo` and never learns the `-u`
//! target on a failed attempt (#838). This rule only ever sees that one string
//! per side and joins on it; it has no opinion on what it represents for either
//! service. History is bounded by the caps below and the least-recently-seen
//! account, never by time, for the same future-timestamp-pruning reason as
//! [`crate::rdp`].

use std::collections::VecDeque;

use schema::detection::Severity;
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD, SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS},
};

/// Distinct target accounts tracked; the least recently seen goes first.
const TARGETS_CAP: usize = 4_096;
/// Failure timestamps kept per target account.
const FAILURES_PER_TARGET_CAP: usize = 256;
/// Successes kept per target account until a failure can still complete their join.
const SUCCESSES_PER_TARGET_CAP: usize = 8;
/// Alerted windows remembered per target account.
const ALERTED_WINDOWS_CAP: usize = 16;

struct Success {
    timestamp_ns: u64,
    alerted: bool,
}

#[derive(Default)]
struct Target {
    /// Failure timestamps, oldest first.
    failures: VecDeque<u64>,
    /// Successes, oldest first.
    successes: VecDeque<Success>,
    /// The fixed windows (`timestamp / window`) an alert already fired for — see
    /// [`crate::rdp::Source::alerted_windows`]'s doc for why these are fixed
    /// slots, not "within a window of the last alert".
    alerted_windows: VecDeque<u64>,
}

/// Per-target-account history that joins a privilege-escalation success to the
/// authentication failures before it.
pub(crate) struct SudoSuccessAfterFailures {
    targets: BoundedMap<String, Target>,
}

impl SudoSuccessAfterFailures {
    pub(crate) fn new() -> Self {
        Self {
            targets: BoundedMap::new(TARGETS_CAP),
        }
    }

    /// An authentication failure for `target_user` at `timestamp_ns`. May
    /// complete the join of successes already seen, one per window.
    pub(crate) fn on_failure(&mut self, target_user: &str, timestamp_ns: u64) -> Vec<Alert> {
        let target = self
            .targets
            .get_or_insert_with(target_user.to_string(), Target::default);
        insert_sorted(&mut target.failures, timestamp_ns, FAILURES_PER_TARGET_CAP);
        target.join(target_user)
    }

    /// A privilege-escalation success for `target_user` at `timestamp_ns`.
    pub(crate) fn on_success(&mut self, target_user: &str, timestamp_ns: u64) -> Vec<Alert> {
        let target = self
            .targets
            .get_or_insert_with(target_user.to_string(), Target::default);
        let at = target
            .successes
            .partition_point(|s| s.timestamp_ns <= timestamp_ns);
        target.successes.insert(
            at,
            Success {
                timestamp_ns,
                alerted: false,
            },
        );
        if target.successes.len() > SUCCESSES_PER_TARGET_CAP {
            target.successes.pop_front();
        }
        target.join(target_user)
    }
}

/// Inserts `value` keeping `deque` sorted, dropping the oldest past `cap`.
fn insert_sorted(deque: &mut VecDeque<u64>, value: u64, cap: usize) {
    let at = deque.partition_point(|&t| t <= value);
    deque.insert(at, value);
    if deque.len() > cap {
        deque.pop_front();
    }
}

impl Target {
    /// Every remembered success that now has enough failures in the window
    /// ending at it, once per window — see [`crate::rdp::Source::join`]'s doc,
    /// this is the same join, keyed differently.
    fn join(&mut self, target_user: &str) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for success in &mut self.successes {
            if success.alerted {
                continue;
            }
            let from = success
                .timestamp_ns
                .saturating_sub(SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS);
            let count = self
                .failures
                .iter()
                .filter(|&&t| t >= from && t <= success.timestamp_ns)
                .count();
            let window = success.timestamp_ns / SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS;
            let recent = self.alerted_windows.contains(&window);
            if count >= SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD as usize && !recent {
                success.alerted = true;
                self.alerted_windows.push_back(window);
                if self.alerted_windows.len() > ALERTED_WINDOWS_CAP {
                    self.alerted_windows.pop_front();
                }
                alerts.push(Alert {
                    technique: "T1548.003",
                    severity: Severity::Medium,
                    message: format!(
                        "target={target_user}: a local privilege escalation (sudo/su) \
                         succeeded after {count} failed authentications for that account \
                         in {}s: guessed or sprayed credentials worked, or a shared \
                         account under sustained attempts",
                        SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS / 1_000_000_000,
                    ),
                });
            }
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const SECOND: u64 = 1_000_000_000;
    const EXPECTED_THRESHOLD: usize = 5;
    const EXPECTED_WINDOW_NS: u64 = 300_000_000_000;
    const EXPECTED_TARGETS_CAP: usize = 4_096;
    const EXPECTED_FAILURES_CAP: usize = 256;
    const EXPECTED_SUCCESSES_CAP: usize = 8;
    const TARGET: &str = "root";

    fn fixed_game(order: [usize; 6]) -> usize {
        let events = [
            (false, SECOND),
            (false, 2 * SECOND),
            (false, 3 * SECOND),
            (false, 4 * SECOND),
            (false, 5 * SECOND),
            (true, 10 * SECOND),
        ];
        let mut state = SudoSuccessAfterFailures::new();
        order
            .into_iter()
            .flat_map(|index| {
                let (success, timestamp) = events[index];
                if success {
                    state.on_success(TARGET, timestamp)
                } else {
                    state.on_failure(TARGET, timestamp)
                }
            })
            .count()
    }

    proptest! {
        #[test]
        fn every_permutation_of_one_game_has_the_same_alert_count(keys in any::<[u32; 6]>()) {
            let mut order = [0, 1, 2, 3, 4, 5];
            order.sort_by_key(|&index| (keys[index], index));
            prop_assert_eq!(fixed_game(order), 1);
        }

        #[test]
        fn several_successes_alert_once_per_window_in_any_delivery_order(
            successes in prop::collection::vec(301_u64..5_000, 1..=6),
            keys in prop::collection::vec(any::<u32>(), 36),
        ) {
            let mut events: Vec<(bool, u64)> = Vec::new();
            for &second in &successes {
                for before in 1..=5 {
                    events.push((false, (second - before) * SECOND));
                }
                events.push((true, second * SECOND));
            }
            let mut order: Vec<usize> = (0..events.len()).collect();
            order.sort_by_key(|&index| (keys[index], index));

            let mut state = SudoSuccessAfterFailures::new();
            let alerts = order
                .into_iter()
                .flat_map(|index| {
                    let (success, timestamp) = events[index];
                    if success {
                        state.on_success(TARGET, timestamp)
                    } else {
                        state.on_failure(TARGET, timestamp)
                    }
                })
                .count();

            let mut windows: Vec<u64> = successes
                .iter()
                .map(|second| second * SECOND / EXPECTED_WINDOW_NS)
                .collect();
            windows.sort_unstable();
            windows.dedup();
            prop_assert_eq!(alerts, windows.len());
        }

        #[test]
        fn fewer_than_five_failures_never_alert(
            timestamps in prop::collection::vec(any::<u64>(), 0..5),
            success_at in any::<u64>(),
        ) {
            let mut state = SudoSuccessAfterFailures::new();
            for timestamp in timestamps {
                prop_assert!(state.on_failure(TARGET, timestamp).is_empty());
            }
            prop_assert!(state.on_success(TARGET, success_at).is_empty());
        }
    }

    #[test]
    fn distinct_target_accounts_do_not_share_history() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..EXPECTED_THRESHOLD as u64 {
            state.on_failure("root", second * SECOND);
        }
        // "alice" never had a failure: her success must not borrow root's.
        assert!(state.on_success("alice", 10 * SECOND).is_empty());
        assert!(!state.on_success("root", 10 * SECOND).is_empty());
    }

    #[test]
    fn exact_window_boundaries_are_inclusive_at_both_ends() {
        let success = 500 * SECOND;
        let window = EXPECTED_WINDOW_NS;
        let before = [
            success - 4 * SECOND,
            success - 3 * SECOND,
            success - 2 * SECOND,
            success - SECOND,
        ];

        for (boundary, expected) in [
            (success - window, true),
            (success - window - 1, false),
            (success, true),
            (success + 1, false),
        ] {
            let mut state = SudoSuccessAfterFailures::new();
            for timestamp in before {
                state.on_failure(TARGET, timestamp);
            }
            state.on_failure(TARGET, boundary);
            assert_eq!(
                !state.on_success(TARGET, success).is_empty(),
                expected,
                "boundary timestamp {boundary}"
            );
        }
    }

    #[test]
    fn failure_cap_evicts_oldest_and_keeps_a_valid_alert() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 0..=EXPECTED_FAILURES_CAP as u64 {
            state.on_failure(TARGET, second * SECOND);
        }
        let target = state.targets.iter().next().unwrap().1;
        assert_eq!(target.failures.len(), EXPECTED_FAILURES_CAP);
        assert_eq!(target.failures.front(), Some(&SECOND));
        assert!(!state.on_success(TARGET, 300 * SECOND).is_empty());
    }

    #[test]
    fn ninth_success_evicts_oldest_but_newer_success_can_still_alert() {
        let mut state = SudoSuccessAfterFailures::new();
        for second in 100..109 {
            state.on_success(TARGET, second * SECOND);
        }
        let target = state.targets.iter().next().unwrap().1;
        assert_eq!(target.successes.len(), EXPECTED_SUCCESSES_CAP);
        assert_eq!(target.successes.front().unwrap().timestamp_ns, 101 * SECOND);
        for second in 100..105 {
            state.on_failure(TARGET, second * SECOND);
        }
        assert!(
            state
                .targets
                .iter()
                .next()
                .unwrap()
                .1
                .successes
                .iter()
                .any(|success| success.alerted)
        );
    }

    #[test]
    fn out_of_order_timestamps_join_by_event_time() {
        let mut state = SudoSuccessAfterFailures::new();
        state.on_success(TARGET, 10 * SECOND);
        for second in [9, 2, 8, 1, 7] {
            let alert = state.on_failure(TARGET, second * SECOND);
            if second != 7 {
                assert!(alert.is_empty());
            } else {
                assert!(!alert.is_empty());
            }
        }
    }

    #[test]
    fn alerted_windows_evict_the_oldest_at_the_fixed_cap() {
        let mut state = SudoSuccessAfterFailures::new();
        let mut alerts = 0;
        for window in 0..=ALERTED_WINDOWS_CAP as u64 {
            let start = window * SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS;
            for offset in 0..SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD as u64 {
                assert!(state.on_failure(TARGET, start + offset).is_empty());
            }
            alerts += state.on_success(TARGET, start + 10).len();
        }

        let target = state.targets.iter().next().unwrap().1;
        assert_eq!(alerts, ALERTED_WINDOWS_CAP + 1);
        assert_eq!(target.alerted_windows.len(), ALERTED_WINDOWS_CAP);
        assert_eq!(target.alerted_windows.front(), Some(&1));
        assert_eq!(
            target.alerted_windows.back(),
            Some(&(ALERTED_WINDOWS_CAP as u64))
        );
    }

    #[test]
    fn zero_and_u64_max_timestamps_do_not_overflow() {
        let mut at_zero = SudoSuccessAfterFailures::new();
        for _ in 0..EXPECTED_THRESHOLD {
            at_zero.on_failure(TARGET, 0);
        }
        assert!(!at_zero.on_success(TARGET, 0).is_empty());

        let mut at_max = SudoSuccessAfterFailures::new();
        for _ in 0..EXPECTED_THRESHOLD {
            at_max.on_failure(TARGET, u64::MAX);
        }
        assert!(!at_max.on_success(TARGET, u64::MAX).is_empty());
    }

    #[test]
    fn one_hundred_thousand_pseudorandom_events_respect_every_capacity() {
        let mut state = SudoSuccessAfterFailures::new();
        let mut random = 0x4d59_5df4_d0f3_3173_u64;
        for index in 0..100_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let target = format!("user{}", (random >> 16) % (EXPECTED_TARGETS_CAP as u64 * 2));
            let timestamp = random.rotate_left(23);
            if random & 1 == 0 {
                state.on_failure(&target, timestamp);
            } else {
                state.on_success(&target, timestamp);
            }
            if index % 256 == 255 || index == 99_999 {
                assert!(state.targets.len() <= EXPECTED_TARGETS_CAP);
                assert!(state.targets.iter().all(|(_, target)| {
                    target.failures.len() <= EXPECTED_FAILURES_CAP
                        && target.successes.len() <= EXPECTED_SUCCESSES_CAP
                }));
            }
        }
    }
}
