//! Maps [`JournalEvent`]s into [`schema::AuthEvent`] — the shared logon/session
//! shape Windows Security-log logons also normalize into (issue #94,
//! `docs/adr/0005-windows-logon-events-shared-auth-event-type.md`). Deliberately
//! narrow, mirroring `sensor-windows-eventlog`'s own discipline (see its
//! `sensor.rs`): a category with a field this mapping needs but can't extract is
//! skipped (`None`) rather than fabricated.
//!
//! **Not every allowlisted [`JournalEvent`] maps to an `AuthEvent`:**
//! - [`JournalEvent::PamSessionOpened`]/[`JournalEvent::PamSessionClosed`] for the
//!   `"sshd"` and `"sudo"` PAM services are the *same real action* as
//!   [`JournalEvent::SshAccepted`]/[`JournalEvent::SudoCommand`] — mapping both
//!   would double-count one login/privilege-elevation as two `AuthEvent`s. Only
//!   `"su"` (no dedicated classifier — [`ExplicitCredentials`](schema::AuthKind)
//!   is the closest existing signal for "became another user") and `"login"`
//!   (local console, not covered elsewhere) get a PAM-session-based mapping.
//! - Unit lifecycle ([`JournalEvent::UnitStarted`]/`Stopped`/`Failed`) never maps
//!   into an `AuthEvent` — a login/session shape is the wrong fit for "a service
//!   started". [`crate::persistence::UnitPersistenceTracker`] maps a unit's first
//!   observed start into `schema::FileOpenEvent` instead, once issue #224
//!   (Windows' own service-lifecycle event reconciliation) confirmed the
//!   precedent to follow (reuse `FileOpenEvent` + a flag, no new `Event`
//!   variant) — see that module's doc.

use schema::{AuthEvent, AuthKind, AuthOutcome, EventMeta, User};

use crate::{JournalEvent, JournalRecord};

/// Whether `record` was written by the program `program` (`"sudo"`/`"su"`), going
/// by the trusted `_COMM` journald stamps from the sender's process rather than by
/// `SYSLOG_IDENTIFIER`, which the logging client chooses (`logger -t sudo
/// 'pam_unix(sudo:auth): authentication failure; ... user=root'` is a line any local
/// user can write; its `_COMM` is `logger`). Without this check a local user could
/// inject sudo/su failures to fill another account's history, or a success to join
/// real failures (#838 review). A record with no `_COMM` is accepted: journald
/// stamps it on every record that comes from a process, so only a fixture built
/// by hand lacks it.
fn emitted_by(record: &JournalRecord, program: &str) -> bool {
    record.comm.as_deref().is_none_or(|comm| comm == program)
}

/// `record`/`event` come from the same [`crate::classify::classify`] call
/// ([`crate::tail::ClassifiedJournal`] always yields them paired) — `record` for
/// the reporting process's identity, `event` for what happened.
#[must_use]
pub fn to_auth_event(record: &JournalRecord, event: &JournalEvent) -> Option<AuthEvent> {
    let (outcome, kind, target_user, source_address) = match event {
        JournalEvent::SshAccepted { user, source_addr } => (
            AuthOutcome::Success,
            AuthKind::Logon,
            user.clone()?,
            parse_addr(source_addr),
        ),
        JournalEvent::SshFailed { user, source_addr } => (
            AuthOutcome::Failure,
            AuthKind::LogonFailure,
            user.clone()?,
            parse_addr(source_addr),
        ),
        JournalEvent::SudoCommand {
            invoking_user,
            target_user,
            ..
        } => {
            if !emitted_by(record, "sudo") {
                return None;
            }
            let real_target = target_user.clone()?;
            // Default target (no `-u`) is root — plain privilege elevation.
            // Any other explicit target is the same "became someone else" signal
            // as `su`, per AuthKind::ExplicitCredentials's own doc.
            let kind = if real_target == "root" {
                AuthKind::PrivilegedSession
            } else {
                AuthKind::ExplicitCredentials
            };
            // `target_user` here is the invoking account, not `real_target` above.
            // `sudo`'s PAM check authenticates the *invoker's own* password (unless
            // the host sets `rootpw`/`targetpw`, not assumed here) — a failed
            // attempt's `pam_unix(sudo:auth)` line (`PamAuthFailure` below) never
            // names the `-u` target the invoker was trying to reach, only the
            // invoker. Reporting the real target here would make a sudo success
            // un-joinable with the failures that preceded it (#838 review): the two
            // sides would key on different strings. Falls back to `real_target` if
            // `logname=`/the `user :` prefix couldn't be read, rather than dropping
            // the event. `su` needs no such swap: there PAM authenticates the real
            // target's password, so its `user=`/session-open line already is it.
            let target_user = invoking_user.clone().unwrap_or(real_target);
            (AuthOutcome::Success, kind, target_user, None)
        }
        JournalEvent::PamSessionOpened {
            service,
            target_user,
        } if service == "su" => {
            if !emitted_by(record, "su") {
                return None;
            }
            (
                AuthOutcome::Success,
                AuthKind::ExplicitCredentials,
                target_user.clone()?,
                None,
            )
        }
        JournalEvent::PamSessionOpened {
            service,
            target_user,
        } if service == "login" => (
            AuthOutcome::Success,
            AuthKind::Logon,
            target_user.clone()?,
            None,
        ),
        // `classify` only emits this for the "sudo"/"su" services (sshd's own PAM
        // auth failure would double-count `SshFailed`), so no service guard is
        // needed here beyond the sender check. The account is `classify_pam`'s
        // `" user="` field, which already is the right join key for both services:
        // for `su` it is the real target (PAM checks the target's own password); for
        // `sudo` it is the invoker (PAM checks the invoker's own password) — the
        // same value the `SudoCommand` arm above swaps in for its own
        // `target_user`, so a sudo failure and the success after it key identically
        // (#838). For `sudo` a line without `user=` still names the invoker through
        // `logname=` (the same account there), so it is not dropped; `su` has no
        // such stand-in (`logname=` is who typed the password, not whose it was),
        // so a `su` failure with no `user=` is skipped, not fabricated.
        JournalEvent::PamAuthFailure {
            service,
            invoking_user,
            target_user,
        } => {
            if !emitted_by(record, service) {
                return None;
            }
            let account = if service == "sudo" {
                target_user.clone().or_else(|| invoking_user.clone())
            } else {
                target_user.clone()
            }?;
            (AuthOutcome::Failure, AuthKind::LogonFailure, account, None)
        }
        _ => return None,
    };

    Some(AuthEvent {
        meta: reporter_meta(record)?,
        outcome,
        kind,
        target_user,
        target_user_sid: None, // Linux: no SID concept.
        source_address,
        status_code: None, // Nothing informative beyond `outcome`/`kind` today.
    })
}

/// Identity of the reporting process (`sshd`, `sudo`, ...) — not the account being
/// authenticated, see [`schema::AuthEvent::meta`]'s own doc. `None` if `_PID`/`_UID`
/// aren't both present (never observed in practice for journald's own trusted
/// fields, but not fabricated if missing).
fn reporter_meta(record: &JournalRecord) -> Option<EventMeta> {
    let pid: u32 = record.pid.as_deref()?.parse().ok()?;
    let uid: u32 = record.uid.as_deref()?.parse().ok()?;
    let user = match record.gid.as_deref().and_then(|g| g.parse().ok()) {
        Some(gid) => User::Unix { uid, gid },
        None => User::Unknown,
    };
    Some(EventMeta {
        pid,
        // journald has no `_PPID` trusted field. This is a session/auth-subsystem
        // event, not a process-lineage one (same reasoning as
        // `sensor-windows-eventlog` hardcoding 0 for its own `AuthEvent`s).
        ppid: 0,
        user,
        timestamp_ns: record.realtime_us.saturating_mul(1_000),
        comm: record
            .syslog_identifier
            .clone()
            .unwrap_or_else(|| "journald".to_string()),
        container: None, // Auth subsystem events aren't attributed to a container.
        process_generation: None,
        parent_process_generation: None,
    })
}

fn parse_addr(addr: &Option<String>) -> Option<core::net::IpAddr> {
    addr.as_deref().and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_record;

    fn record_with(fields: &[(&str, &str)]) -> JournalRecord {
        let mut obj = serde_json::Map::new();
        obj.insert("__CURSOR".into(), "c".into());
        obj.insert("__REALTIME_TIMESTAMP".into(), "1000".into());
        obj.insert("MESSAGE".into(), "irrelevant for this mapping test".into());
        for (k, v) in fields {
            obj.insert((*k).to_string(), (*v).into());
        }
        let line = serde_json::to_string(&obj).unwrap();
        parse_record(&line).unwrap()
    }

    #[test]
    fn ssh_accepted_maps_to_logon_success() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            ("_PID", "4242"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::SshAccepted {
            user: Some("alice".into()),
            source_addr: Some("10.0.0.5".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.outcome, AuthOutcome::Success);
        assert_eq!(auth.kind, AuthKind::Logon);
        assert_eq!(auth.target_user, "alice");
        assert_eq!(auth.meta.pid, 4242);
        assert_eq!(auth.meta.comm, "sshd");
        assert_eq!(
            auth.source_address,
            Some("10.0.0.5".parse::<core::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn ssh_failed_maps_to_logon_failure() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            ("_PID", "4242"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::SshFailed {
            user: Some("root".into()),
            source_addr: Some("10.0.0.5".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.outcome, AuthOutcome::Failure);
        assert_eq!(auth.kind, AuthKind::LogonFailure);
        assert_eq!(auth.target_user, "root");
    }

    #[test]
    fn sudo_to_root_is_privileged_session_keyed_on_the_invoker() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let event = JournalEvent::SudoCommand {
            invoking_user: Some("lab".into()),
            target_user: Some("root".into()),
            command: Some("/bin/echo hi".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        // `kind` still reflects the real target (root) — only the join key
        // (`target_user`) swaps to the invoker, see the mapping's own comment.
        assert_eq!(auth.kind, AuthKind::PrivilegedSession);
        assert_eq!(auth.target_user, "lab");
    }

    #[test]
    fn sudo_to_other_user_is_explicit_credentials_keyed_on_the_invoker() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let event = JournalEvent::SudoCommand {
            invoking_user: Some("lab".into()),
            target_user: Some("deploy".into()),
            command: Some("/bin/echo hi".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.kind, AuthKind::ExplicitCredentials);
        assert_eq!(auth.target_user, "lab");
    }

    #[test]
    fn a_sudo_success_with_no_invoking_user_falls_back_to_the_real_target() {
        // `invoking_user` comes from a `" :"` split on the command line (#838);
        // if that ever fails to parse, keying on the real target still produces
        // a usable (if unjoinable) event instead of dropping it.
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let event = JournalEvent::SudoCommand {
            invoking_user: None,
            target_user: Some("root".into()),
            command: Some("/bin/echo hi".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.target_user, "root");
    }

    #[test]
    fn a_sudo_failure_and_the_success_after_it_key_on_the_same_invoker() {
        // The real shape of the bug (#838 review): the invoker (`omss`) fails
        // sudo, then succeeds as `root`. The PAM failure line never names
        // `root` — `pam_unix(sudo:auth)` only authenticates the invoker — so
        // the two sides must key on the invoker, not on the escalation target,
        // or a real success-after-failures join can never fire for `sudo`.
        let failure_record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "6805"),
            ("_UID", "1000"),
            ("_GID", "1000"),
        ]);
        let failure = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("omss".into()),
            target_user: Some("omss".into()),
        };
        let failure_auth = to_auth_event(&failure_record, &failure).expect("should map");

        let success_record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "6810"),
            ("_UID", "1000"),
            ("_GID", "1000"),
        ]);
        let success = JournalEvent::SudoCommand {
            invoking_user: Some("omss".into()),
            target_user: Some("root".into()),
            command: Some("/bin/whoami".into()),
        };
        let success_auth = to_auth_event(&success_record, &success).expect("should map");

        assert_eq!(failure_auth.target_user, success_auth.target_user);
        assert_eq!(failure_auth.target_user, "omss");
    }

    #[test]
    fn su_pam_session_is_explicit_credentials() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "su"),
            ("_PID", "200"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let event = JournalEvent::PamSessionOpened {
            service: "su".into(),
            target_user: Some("root".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.kind, AuthKind::ExplicitCredentials);
    }

    #[test]
    fn sshd_pam_session_is_not_double_mapped() {
        // Same real login as SshAccepted — must not also produce an AuthEvent here.
        let record = record_with(&[("SYSLOG_IDENTIFIER", "sshd"), ("_PID", "1"), ("_UID", "0")]);
        let event = JournalEvent::PamSessionOpened {
            service: "sshd".into(),
            target_user: Some("alice".into()),
        };
        assert!(to_auth_event(&record, &event).is_none());
    }

    #[test]
    fn pam_auth_failure_for_sudo_maps_to_logon_failure() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        // `pam_unix(sudo:auth)` authenticates the invoker's own password, so a
        // real failure's `" user="` field (`target_user` here) names the
        // invoker, never the `-u` target (#838) — `target_user: Some("root")`
        // with a different `invoking_user` is not a line `classify_pam` ever
        // actually produces for `sudo`.
        let event = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("lab".into()),
            target_user: Some("lab".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.outcome, AuthOutcome::Failure);
        assert_eq!(auth.kind, AuthKind::LogonFailure);
        assert_eq!(auth.target_user, "lab");
        assert_eq!(auth.source_address, None);
    }

    #[test]
    fn unit_lifecycle_has_no_mapping() {
        let record = record_with(&[("_PID", "1"), ("_UID", "0")]);
        let event = JournalEvent::UnitStarted {
            unit: Some("sshd.service".into()),
        };
        assert!(to_auth_event(&record, &event).is_none());
    }

    #[test]
    fn missing_pid_skips_mapping_rather_than_fabricating_one() {
        let record = record_with(&[("SYSLOG_IDENTIFIER", "sshd"), ("_UID", "0")]);
        let event = JournalEvent::SshAccepted {
            user: Some("alice".into()),
            source_addr: None,
        };
        assert!(to_auth_event(&record, &event).is_none());
    }

    // --- who actually wrote the line (`_COMM`, not the spoofable identifier) -----

    #[test]
    fn a_sudo_line_written_by_another_program_is_not_mapped() {
        // `logger -t sudo '...'` sets `SYSLOG_IDENTIFIER=sudo` freely, but the
        // trusted `_COMM` is `logger`: a local user must not be able to feed the
        // sudo/su join with fabricated failures or successes (#838 review).
        let spoofed = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_COMM", "logger"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let failure = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("victim".into()),
            target_user: Some("victim".into()),
        };
        let success = JournalEvent::SudoCommand {
            invoking_user: Some("victim".into()),
            target_user: Some("root".into()),
            command: Some("/bin/id".into()),
        };
        let su_session = JournalEvent::PamSessionOpened {
            service: "su".into(),
            target_user: Some("root".into()),
        };
        assert!(to_auth_event(&spoofed, &failure).is_none());
        assert!(to_auth_event(&spoofed, &success).is_none());
        assert!(to_auth_event(&spoofed, &su_session).is_none());
    }

    #[test]
    fn a_sudo_line_written_by_sudo_itself_is_mapped() {
        let genuine = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_COMM", "sudo"),
            ("_PID", "100"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let success = JournalEvent::SudoCommand {
            invoking_user: Some("lab".into()),
            target_user: Some("root".into()),
            command: Some("/bin/id".into()),
        };
        let auth = to_auth_event(&genuine, &success).expect("should map");
        assert_eq!(auth.target_user, "lab");
    }

    #[test]
    fn a_sudo_failure_without_user_falls_back_to_logname() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("lab".into()),
            target_user: None,
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.target_user, "lab");
        assert_eq!(auth.outcome, AuthOutcome::Failure);
    }

    #[test]
    fn a_su_failure_without_user_is_skipped_not_guessed() {
        // For `su`, `logname=` is who typed the password, not whose account it was
        // checked against, so it cannot stand in for the missing `user=`.
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "su"),
            ("_PID", "100"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::PamAuthFailure {
            service: "su".into(),
            invoking_user: Some("lab".into()),
            target_user: None,
        };
        assert!(to_auth_event(&record, &event).is_none());
    }
}
