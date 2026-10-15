//! Documented Event Log clear records and hostile-field behavior (#799).

use sensor_windows_eventlog::xml::parse_log_cleared_block;

const EVENT_1102: &str = include_str!("fixtures/log_cleared_1102.xml");
const EVENT_104: &str = include_str!("fixtures/log_cleared_104.xml");

#[test]
fn parses_documented_security_1102_fields() {
    let event = parse_log_cleared_block(EVENT_1102).expect("1102 fixture parses");
    assert_eq!(event.record_id, 1_087_729);
    assert_eq!(event.event_id, 1102);
    assert_eq!(event.channel, "Security");
    assert_eq!(
        event.subject_user_sid.as_deref(),
        Some("S-1-5-21-3457937927-2839227994-823803824-1104")
    );
    assert_eq!(event.subject_user_name.as_deref(), Some("dadmin"));
    assert_eq!(event.subject_domain_name.as_deref(), Some("CONTOSO"));
    assert_eq!(event.subject_logon_id.as_deref(), Some("0x55cd1d"));
    assert_eq!(event.timestamp_ns, Some(1_444_955_998_656_871_200));
}

#[test]
fn parses_documented_system_104_channel_and_unicode_account() {
    let event = parse_log_cleared_block(EVENT_104).expect("104 fixture parses");
    assert_eq!(event.record_id, 21_592);
    assert_eq!(event.event_id, 104);
    assert_eq!(event.channel, "Windows PowerShell");
    assert_eq!(event.subject_user_sid, None);
    assert_eq!(event.subject_user_name.as_deref(), Some("Élodie"));
    assert_eq!(event.subject_domain_name.as_deref(), Some("LAB"));
    assert_eq!(event.subject_logon_id, None);
}

#[test]
fn missing_user_data_keeps_1102_but_skips_104_without_a_target_channel() {
    let missing = EVENT_1102.replace(
        "<UserData><LogFileCleared xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\"><SubjectUserSid>S-1-5-21-3457937927-2839227994-823803824-1104</SubjectUserSid><SubjectUserName>dadmin</SubjectUserName><SubjectDomainName>CONTOSO</SubjectDomainName><SubjectLogonId>0x55cd1d</SubjectLogonId></LogFileCleared></UserData>",
        "",
    );
    let event = parse_log_cleared_block(&missing).expect("1102 remains a clear signal");
    assert_eq!(event.channel, "Security");
    assert_eq!(event.subject_user_name, None);

    let missing = EVENT_104.replace(
        "<UserData><LogFileCleared xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\"><SubjectUserName>Élodie</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName><Channel>Windows PowerShell</Channel><BackupPath/></LogFileCleared></UserData>",
        "",
    );
    assert!(parse_log_cleared_block(&missing).is_none());
}

#[test]
fn empty_system_104_channel_is_rejected() {
    let block = EVENT_104.replace(
        "<Channel>Windows PowerShell</Channel>",
        "<Channel> </Channel>",
    );
    assert!(parse_log_cleared_block(&block).is_none());
}

#[test]
fn an_oversized_account_field_is_dropped_without_dropping_the_clear() {
    let huge = format!("<SubjectUserName>{}</SubjectUserName>", "x".repeat(8192));
    let block = EVENT_1102.replace("<SubjectUserName>dadmin</SubjectUserName>", &huge);
    let event = parse_log_cleared_block(&block).expect("clear event remains usable");
    assert_eq!(event.subject_user_name, None);
    assert_eq!(
        event.subject_user_sid.as_deref(),
        Some("S-1-5-21-3457937927-2839227994-823803824-1104")
    );
}

#[test]
fn an_account_field_at_the_limit_is_retained() {
    let value = "x".repeat(4096);
    let field = format!("<SubjectUserName>{value}</SubjectUserName>");
    let block = EVENT_1102.replace("<SubjectUserName>dadmin</SubjectUserName>", &field);
    let event = parse_log_cleared_block(&block).expect("clear event remains usable");
    assert_eq!(event.subject_user_name.as_deref(), Some(value.as_str()));
}

proptest::proptest! {
    #[test]
    fn arbitrary_unicode_xml_never_panics(input in ".{0,2048}") {
        let _ = parse_log_cleared_block(&input);
    }
}
