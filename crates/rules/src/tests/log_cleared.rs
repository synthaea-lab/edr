use schema::{Event, LogClearedEvent};

use crate::evaluate_log_cleared;

fn event(event_id: u32, channel: &str) -> LogClearedEvent {
    LogClearedEvent {
        meta: schema::fixtures::meta(),
        channel: channel.into(),
        subject_user_sid: Some("S-1-5-21-1-2-3-1001".into()),
        subject_user_name: Some("alice".into()),
        subject_domain_name: Some("LAB".into()),
        subject_logon_id: Some("0x1234".into()),
        source_event_id: event_id,
    }
}

#[test]
fn log_clear_records_fire_t1070_001_at_high() {
    for event_id in [1102, 104] {
        let alerts = evaluate_log_cleared(&event(event_id, "Security"));
        assert_eq!(alerts.len(), 1, "event id {event_id}");
        assert_eq!(alerts[0].technique, "T1070.001");
        assert_eq!(alerts[0].severity, schema::detection::Severity::High);
        assert!(alerts[0].message.contains("Security"));
        assert!(alerts[0].message.contains("LAB\\alice"));
        assert!(alerts[0].message.contains("(SID S-1-5-21-1-2-3-1001)"));
    }
}

#[test]
fn empty_actor_fields_are_not_reported_as_identities() {
    let mut record = event(1102, "Security");
    record.subject_user_name = Some("  ".into());
    record.subject_domain_name = None;
    record.subject_user_sid = Some("\t".into());

    let alerts = evaluate_log_cleared(&record);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("unknown account"));
    assert!(!alerts[0].message.contains("SID"));
}

#[test]
fn unrelated_source_event_id_does_not_fire() {
    assert!(evaluate_log_cleared(&event(6005, "System")).is_empty());
}

#[test]
fn log_clearing_is_a_schema_event() {
    let event = Event::LogCleared(event(104, "Application"));
    assert_eq!(
        event.meta().timestamp_ns,
        schema::fixtures::meta().timestamp_ns
    );
}
