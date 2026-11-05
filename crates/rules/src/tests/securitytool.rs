//! SECURITY-TOOL-STOP (T1562.001, #379): a command that stops a named security tool.

use super::*;
use crate::Severity;

/// The T1562.001 alerts one command raises through the stateless dispatcher.
fn stops(command: &str) -> Vec<crate::Alert> {
    let comm = command.split_whitespace().next().unwrap();
    crate::evaluate_exec(&exec_event_full(2000, 600, comm, command, 0))
        .into_iter()
        .filter(|a| a.technique == "T1562.001")
        .collect()
}

#[test]
fn stopping_a_listed_security_tool_alerts_once_and_names_it() {
    for (command, tool) in [
        ("systemctl stop falco", "falco"),
        ("systemctl stop auditd", "auditd"),
        ("systemctl stop falcon-sensor.service", "falcon-sensor"),
        ("systemctl disable --now osqueryd", "osqueryd"),
        ("systemctl mask --now wazuh-agent", "wazuh-agent"),
        ("service clamav-daemon stop", "clamav-daemon"),
        ("sc stop Sysmon64", "sysmon64"),
        ("sc stop WinDefend", "windefend"),
        ("net stop sense", "sense"),
        (
            "powershell Stop-Service -Name CSFalconService -Force",
            "csfalconservice",
        ),
        (
            "launchctl bootout system/com.crowdstrike.falcond",
            "com.crowdstrike.falcond",
        ),
        (
            "launchctl unload -w /Library/LaunchDaemons/com.microsoft.wdav.plist",
            "com.microsoft.wdav",
        ),
    ] {
        let alerts = stops(command);
        assert_eq!(alerts.len(), 1, "{command}: {alerts:?}");
        assert_eq!(alerts[0].severity, Severity::Medium, "{command}");
        assert!(
            alerts[0].message.contains(tool),
            "{command}: {}",
            alerts[0].message
        );
    }
}

#[test]
fn stopping_other_services_does_not_alert() {
    for command in [
        "systemctl stop nginx",
        "systemctl stop postgresql",
        "service apache2 stop",
        "sc stop Spooler",
        "net stop wuauserv",
        "launchctl bootout system/com.apple.dock",
        "systemctl stop auditd-helper",
    ] {
        assert!(stops(command).is_empty(), "{command}");
    }
}

#[test]
fn a_command_that_does_not_stop_anything_does_not_alert() {
    for command in [
        "systemctl status falco",
        "systemctl start auditd",
        "systemctl restart falco",
        "systemctl enable --now osqueryd",
        "systemctl disable falco",
        "sc query WinDefend",
        "sc start Sysmon64",
        "launchctl list com.crowdstrike.falcond",
        "service auditd status",
    ] {
        assert!(stops(command).is_empty(), "{command}");
    }
}

#[test]
fn a_command_stopping_several_security_tools_is_one_alert() {
    let alerts = stops("systemctl stop falco osqueryd auditd");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn a_security_tool_among_other_services_is_still_found() {
    let alerts = stops("systemctl stop nginx falco postfix");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].message.contains("falco"), "{}", alerts[0].message);
}

#[test]
fn the_names_are_compared_without_regard_to_case() {
    assert_eq!(stops("sc stop SYSMON64").len(), 1);
    assert_eq!(stops("net stop WinDefend").len(), 1);
}

#[test]
fn the_event_log_service_is_left_to_its_own_rule() {
    // T1562.002 (#800) owns the EventLog service; this rule must not double it.
    assert!(stops("sc stop eventlog").is_empty());
    assert!(stops("net stop eventlog").is_empty());
}

#[test]
fn the_agents_own_service_is_not_a_security_tool_here() {
    assert!(stops("systemctl stop synthaea-agent").is_empty());
    assert!(stops("launchctl bootout system/dev.synthaea.agent").is_empty());
}

#[test]
fn the_burst_rule_and_this_one_are_independent() {
    // Five services, one of them a security tool: the burst alert (T1489) and this one both
    // fire, on different exec events' worth of state, without one hiding the other.
    let mut state = RuleState::new();
    let mut techniques = Vec::new();
    for (i, unit) in ["mysqld", "postgresql", "veeam", "postfix", "falco"]
        .iter()
        .enumerate()
    {
        let command = format!("systemctl stop {unit}");
        let event = exec_event_full(
            3000 + i as u32,
            600,
            "systemctl",
            &command,
            i as u64 * 1_000_000_000,
        );
        techniques.extend(crate::evaluate_exec(&event).iter().map(|a| a.technique));
        techniques.extend(state.on_exec(&event).iter().map(|a| a.technique));
    }
    assert!(techniques.contains(&"T1562.001"), "{techniques:?}");
    assert!(techniques.contains(&"T1489"), "{techniques:?}");
}

// ---- Kernel-mediated stops (#1138) ----

fn throttle_alerts(command: &str) -> Vec<crate::Alert> {
    stops(command)
}

#[test]
fn freezing_or_limiting_a_listed_tool_alerts_medium_and_names_it() {
    for (command, tool) in [
        ("systemctl freeze auditd", "auditd"),
        ("systemctl freeze falco.service", "falco"),
        ("systemctl --runtime freeze osqueryd", "osqueryd"),
        ("systemctl set-property auditd MemoryMax=1M", "auditd"),
        (
            "systemctl set-property --runtime falco.service MemoryHigh=1M",
            "falco",
        ),
        ("systemctl set-property auditd TasksMax=1", "auditd"),
        (
            "systemctl set-property auditd CPUQuota=50% MemoryMax=1M",
            "auditd",
        ),
    ] {
        let alerts = throttle_alerts(command);
        assert_eq!(alerts.len(), 1, "{command}: {alerts:?}");
        assert_eq!(alerts[0].severity, Severity::Medium, "{command}");
        assert!(
            alerts[0].message.contains(tool),
            "{command}: {}",
            alerts[0].message
        );
    }
}

#[test]
fn benign_freezes_and_limits_do_not_alert() {
    for command in [
        "systemctl freeze nginx",
        "systemctl thaw auditd",
        "systemctl set-property nginx MemoryMax=1M",
        "systemctl set-property auditd MemoryMax=infinity",
        "systemctl set-property auditd MemoryMax=",
        "systemctl set-property auditd CPUQuota=50%",
        "systemctl status auditd",
        "systemctl freeze auditd-helper",
    ] {
        assert!(throttle_alerts(command).is_empty(), "{command}");
    }
}

#[test]
fn prlimit_setting_cpu_or_as_on_a_pid_is_low_and_names_no_tool() {
    for command in [
        "prlimit --pid 744 --cpu=1:1",
        "prlimit --cpu=1:1 --pid=744",
        "prlimit -p 744 --cp=1",
        "prlimit -p 744 -t1:1",
        "prlimit --pid 744 --as=1000000",
    ] {
        let alerts = throttle_alerts(command);
        assert_eq!(alerts.len(), 1, "{command}: {alerts:?}");
        assert_eq!(alerts[0].severity, Severity::Low, "{command}");
    }
}

#[test]
fn prlimit_that_only_reads_or_runs_a_command_does_not_alert() {
    for command in [
        "prlimit --pid 744 --cpu",
        "prlimit --pid 744",
        "prlimit --cpu=60 sleep 1",
        "prlimit --pid 744 --nofile=1024",
        "prlimit --pid 744 --core=0",
    ] {
        assert!(throttle_alerts(command).is_empty(), "{command}");
    }
}

fn cgroup_open(path: &str, flags: u32, pid: u32) -> schema::FileOpenEvent {
    let mut event = file_open_event(path, flags);
    event.meta.pid = pid;
    event
}

const O_WRONLY: u32 = 0o1;
const O_TRUNC: u32 = 0o1000;

#[test]
fn a_write_to_a_listed_units_throttle_file_alerts() {
    for path in [
        "/sys/fs/cgroup/system.slice/auditd.service/memory.max",
        "/sys/fs/cgroup/system.slice/auditd.service/memory.high",
        "/sys/fs/cgroup/system.slice/falco.service/cgroup.freeze",
        "/sys/fs/cgroup/system.slice/osqueryd.service/pids.max",
        "/sys/fs/cgroup/memory/system.slice/auditd.service/memory.limit_in_bytes",
        "/sys/fs/cgroup/freezer/system.slice/auditd.service/freezer.state",
    ] {
        for flags in [O_WRONLY, O_WRONLY | O_TRUNC, 0o2] {
            let alerts = all_file_open_alerts(&cgroup_open(path, flags, 4242));
            assert_eq!(alerts.len(), 1, "{path} {flags:o}: {alerts:?}");
            assert_eq!(alerts[0].technique, "T1562.001");
            assert_eq!(alerts[0].severity, Severity::Medium);
        }
    }
}

#[test]
fn reads_other_units_other_files_and_the_manager_do_not_alert() {
    let cases = [
        (
            "/sys/fs/cgroup/system.slice/auditd.service/memory.max",
            0,
            4242,
        ),
        (
            "/sys/fs/cgroup/system.slice/nginx.service/memory.max",
            O_WRONLY,
            4242,
        ),
        (
            "/sys/fs/cgroup/system.slice/auditd.service/cgroup.procs",
            O_WRONLY,
            4242,
        ),
        (
            "/sys/fs/cgroup/system.slice/auditd.service/memory.max",
            O_WRONLY,
            1,
        ),
        ("/sys/fs/cgroup/system.slice/memory.max", O_WRONLY, 4242),
        ("/tmp/auditd.service/memory.max", O_WRONLY, 4242),
        (
            "/sys/fs/cgroup/system.slice/auditd.scope/memory.max",
            O_WRONLY,
            4242,
        ),
    ];
    for (path, flags, pid) in cases {
        let alerts = all_file_open_alerts(&cgroup_open(path, flags, pid));
        assert!(
            alerts.iter().all(|a| a.technique != "T1562.001"),
            "{path} {flags:o} pid {pid}: {alerts:?}"
        );
    }
}
