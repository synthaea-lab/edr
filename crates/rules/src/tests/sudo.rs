//! sudo/su success-after-failures rule (T1548.003, #381).

use schema::{AuthEvent, AuthKind, AuthOutcome, User, fixtures};

use super::*;
use crate::exclusions::{
    SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD, SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS,
};

const SEC: u64 = 1_000_000_000;
const THRESHOLD: u64 = SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD as u64;

fn failure(target_user: &str, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            ..meta()
        },
        outcome: AuthOutcome::Failure,
        kind: AuthKind::LogonFailure,
        target_user: target_user.to_string(),
        ..fixtures::auth()
    }
}

fn success(target_user: &str, kind: AuthKind, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            ..meta()
        },
        outcome: AuthOutcome::Success,
        kind,
        target_user: target_user.to_string(),
        ..fixtures::auth()
    }
}

#[test]
fn privileged_session_after_five_failures_alerts_once_per_window() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }

    let alerts = state.on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1548.003");
    assert_eq!(alerts[0].severity, schema::detection::Severity::Medium);
    assert!(alerts[0].message.contains("target=root"));
    assert!(alerts[0].message.contains("5 failed authentications"));
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 11 * SEC))
            .is_empty()
    );
}

#[test]
fn explicit_credentials_success_also_joins_the_burst() {
    // `su`/`sudo -u other` map to `ExplicitCredentials`, not `PrivilegedSession`
    // (schema::AuthKind's own doc) — both must complete the join.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("deploy", i * SEC));
    }
    let alerts = state.on_auth(&success("deploy", AuthKind::ExplicitCredentials, 10 * SEC));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1548.003");
}

#[test]
fn a_plain_logon_success_does_not_join_the_burst() {
    // `AuthKind::Logon` (e.g. a plain `login`/`su` session, not an elevation) is
    // not the signal T1548.003 is about.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::Logon, 10 * SEC))
            .is_empty()
    );
}

#[test]
fn a_windows_identity_success_does_not_join_the_local_burst() {
    // This join is for local (Unix) privilege escalation; a Windows success
    // reaches the rules through `rdp_success`/`on_session`, not here.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    let mut windows_success = success("root", AuthKind::PrivilegedSession, 10 * SEC);
    windows_success.meta.user = User::Windows {
        sid: "S-1-5-18".into(),
        integrity_level: None,
    };
    assert!(state.on_auth(&windows_success).is_empty());
}

#[test]
fn failures_from_a_windows_identity_do_not_feed_the_local_join() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        let mut windows_failure = failure("root", i * SEC);
        windows_failure.meta.user = User::Windows {
            sid: "S-1-5-18".into(),
            integrity_level: None,
        };
        state.on_auth(&windows_failure);
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC))
            .is_empty()
    );
}

#[test]
fn distinct_target_accounts_do_not_share_the_burst() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("alice", AuthKind::ExplicitCredentials, 10 * SEC))
            .is_empty()
    );
}

#[test]
fn below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC))
            .is_empty()
    );
}

#[test]
fn failures_outside_the_window_do_not_count() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    let late = SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS + 10 * SEC;
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, late))
            .is_empty()
    );
}

#[test]
fn success_delivered_before_the_last_failure_still_alerts() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC))
            .is_empty(),
        "four failures are not enough yet"
    );

    let alerts = state.on_auth(&failure("root", 6 * SEC));
    let sudo: Vec<_> = alerts
        .iter()
        .filter(|a| a.technique == "T1548.003")
        .collect();
    assert_eq!(sudo.len(), 1, "the late failure completes the join");
}

#[test]
fn failure_timestamped_after_the_success_does_not_count() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("root", i * SEC));
    }
    state.on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC));

    let alerts = state.on_auth(&failure("root", 11 * SEC));
    assert!(
        alerts.iter().all(|a| a.technique != "T1548.003"),
        "a failure after the success is not a failure before it"
    );
}
