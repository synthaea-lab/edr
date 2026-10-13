//! AVC-only `NETLINK_AUDIT` subscription (#780): a second, independent read of the
//! same multicast stream `AuditSensor` subscribes to, filtered to `PolicyDenial`
//! events only. The agent binary's `select_sensor` picks eBPF or the audit sensor
//! for exec/connect telemetry — never both — so on a host where eBPF loads
//! (the normal case on a hardened, up-to-date `SELinux`-Enforcing box), `AuditSensor`
//! never runs and its AVC classification, the only place that produces
//! `PolicyDenial` events, goes with it. `AvcReader` exists so the caller can keep
//! that one source alive regardless of which primary sensor was chosen.
//!
//! Netlink multicast delivers one copy of each record per subscribed socket (not
//! one copy total, handed to whichever socket asks first), so a second socket here
//! does not steal records from `AuditSensor`'s own subscription. The reverse also
//! holds: running both at once (audit chosen as primary, `AvcReader` started
//! anyway) would only double up `PolicyDenial` events, not corrupt anything — the
//! caller's job to avoid by starting this reader only when the audit sensor is not
//! already running, not a safety property this type has to enforce itself.

use std::os::unix::io::{AsRawFd, RawFd};

use schema::sensor::EventSink;

use crate::{AuditError, AuditEvent, AuditSocket, classify, normalize, parse};

/// Records drained per call to [`AvcReader::drain`] before returning control to
/// the caller — same budget and reasoning as `AuditSensor`'s own drain loop
/// (`sensor.rs`): bounds one call's cost so a flood can't starve the caller's own
/// stop check, which lives outside this type.
const DRAIN_BUDGET: usize = 256;

/// Reads `NETLINK_AUDIT` for `PolicyDenial` events only — see this module's doc.
pub struct AvcReader {
    socket: AuditSocket,
}

impl AvcReader {
    /// Opens a fresh, independent subscription to the audit multicast group.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Netlink` if the socket can't be opened or bound —
    /// typically a privilege error, see [`AuditSocket::open`]'s doc.
    pub fn open() -> Result<Self, AuditError> {
        Ok(Self {
            socket: AuditSocket::open()?,
        })
    }

    /// Waits up to `timeout_ms` for the socket to become readable, then drains
    /// what's queued (bounded by [`DRAIN_BUDGET`]), forwarding only `PolicyDenial`
    /// events to `sink`. Exec/Connect records on the same stream are classified
    /// and discarded — not this reader's job, see this module's doc. A kernel
    /// buffer overrun (`ENOBUFS`) is reported through the return value, not an
    /// error: the socket is still usable, same posture as `AuditSensor`'s own loop.
    ///
    /// Returns `(forwarded, overran)`: `forwarded` is almost always `0` — the
    /// timeout elapsing with nothing queued, or only Exec/Connect records
    /// arriving, are both normal and frequent. A call returning at all, whatever
    /// the count, is what the caller's heartbeat needs: proof the thread is not
    /// stuck, not proof of real `SELinux` traffic.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Netlink` on a `poll`/`recv` failure other than
    /// `EAGAIN`/`EWOULDBLOCK` (handled internally, see above) or `ENOBUFS`
    /// (reported via `overran`, not this).
    pub fn drain(
        &mut self,
        sink: &dyn EventSink,
        timeout_ms: i32,
    ) -> Result<(usize, bool), AuditError> {
        if !self.wait_readable(timeout_ms)? {
            return Ok((0, false));
        }

        let mut buf = [0u8; 8192];
        let mut forwarded = 0;
        let mut overran = false;
        for _ in 0..DRAIN_BUDGET {
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    if forward_policy_denial(&buf[..n], sink) {
                        forwarded += 1;
                    }
                }
                Err(AuditError::Netlink(errno))
                    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK =>
                {
                    break;
                }
                Err(AuditError::Netlink(libc::ENOBUFS)) => {
                    overran = true;
                }
                Err(e) => return Err(e),
            }
        }
        Ok((forwarded, overran))
    }

    /// `poll(2)` on the raw fd with a timeout, so [`Self::drain`] returns control
    /// to the caller (for its own stop check and heartbeat pulse) even when the
    /// socket never has anything queued — blocking indefinitely would make a
    /// quiet host's reader thread indistinguishable from a stuck one.
    fn wait_readable(&self, timeout_ms: i32) -> Result<bool, AuditError> {
        let mut pfd = libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: pfd is a valid, live pointer to one initialized pollfd; nfds=1
            // matches the single-element array it points at.
            let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if ready >= 0 {
                return Ok(ready > 0);
            }
            // SAFETY: __errno_location returns a valid pointer to thread-local errno.
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EINTR {
                return Err(AuditError::Netlink(errno));
            }
            // A signal interrupted the wait (e.g. the process's own Ctrl-C handler
            // elsewhere) — not a socket error, retry the wait.
        }
    }
}

impl AsRawFd for AvcReader {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Parses and classifies one raw record, forwarding it to `sink` only if it is a
/// `PolicyDenial` — an unparseable record or any other classified kind (Exec,
/// Connect, or one `classify` doesn't recognize) is silently skipped, the same
/// "never fatal, just not forwarded" posture `AuditSensor::forward` has for a bad
/// record (#504's lesson: a parse error here must never stop the reader).
fn forward_policy_denial(raw: &[u8], sink: &dyn EventSink) -> bool {
    let Ok(record) = parse::parse_audit_message(raw) else {
        return false;
    };
    let Some(event @ AuditEvent::PolicyDenial { .. }) = classify::classify(&record) else {
        return false;
    };
    let timestamp_ns =
        record.timestamp_sec * 1_000_000_000 + u64::from(record.timestamp_ms) * 1_000_000;
    sink.on_event(normalize::policy_denial_event(&event, timestamp_ns));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::build_wire_message;

    /// `AUDIT_AVC` (see `classify.rs`) — the real kernel netlink form (no
    /// `type=`/`msg=` text prefix, see `parse::tests::parses_the_kernel_netlink_form`),
    /// exercised through the real parser rather than a hand-built `AuditRecord`, so a
    /// mismatch between this module's logic and the parser's actual output can't hide.
    fn avc_wire_message(payload: &str) -> Vec<u8> {
        build_wire_message(1400, payload)
    }

    struct RecordingSink(std::sync::Mutex<Vec<schema::Event>>);

    impl EventSink for RecordingSink {
        fn on_event(&self, event: schema::Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn forwards_a_policy_denial_and_reports_its_event() {
        let bytes = avc_wire_message(
            "audit(1700000000.123:45): avc:  denied  { read } for  pid=1234 \
             comm=\"httpd\" scontext=httpd_t tcontext=shadow_t tclass=file",
        );
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(forward_policy_denial(&bytes, &sink));
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let schema::Event::PolicyDenial(denial) = &events[0] else {
            panic!("expected a PolicyDenial event, got {:?}", events[0]);
        };
        assert_eq!(denial.action.as_deref(), Some("read"));
        assert_eq!(denial.object_class.as_deref(), Some("file"));
    }

    #[test]
    fn does_not_forward_an_exec_record_on_the_same_stream() {
        let bytes = build_wire_message(
            1309, // AUDIT_EXECVE — the other record type this socket also carries
            "audit(1700000000.123:45): argc=1 a0=\"id\"",
        );
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(!forward_policy_denial(&bytes, &sink));
        assert!(
            sink.0.lock().unwrap().is_empty(),
            "an Exec record must never reach this reader's sink"
        );
    }

    #[test]
    fn an_avc_record_missing_scontext_and_tclass_is_not_forwarded() {
        // classify_avc itself drops this (see its doc) — confirms this reader
        // inherits that judgment rather than forwarding whatever classify hands back.
        let bytes = avc_wire_message("audit(1700000000.123:45): comm=\"httpd\"");
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(!forward_policy_denial(&bytes, &sink));
        assert!(sink.0.lock().unwrap().is_empty());
    }

    #[test]
    fn an_unparseable_record_is_skipped_not_fatal() {
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        assert!(!forward_policy_denial(
            b"\xff\xfe not an audit record",
            &sink
        ));
        assert!(sink.0.lock().unwrap().is_empty());
    }
}
