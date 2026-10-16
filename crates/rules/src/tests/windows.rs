//! The Windows-calibrated stateful rules: SELF-SPAWN (T1059), PARENT-SUSPECT
//! (T1204/T1059), LOLBIN (T1218/T1127), BEACON (T1071/T1041).

use super::*;

// ── SELF-SPAWN (T1059) ────────────────────────────────────────────────────
// Windows-only (the rule is gated on `User::Windows` — #159), so these build
// events with `exec_event_win`.

#[test]
fn self_spawn_stays_quiet_on_a_unix_shell_loop() {
    // #159: `for i in 1..N; do sh -c …; done` spawns `sh` from the same ppid
    // repeatedly. The rule is Windows-calibrated and must not fire on Linux —
    // `exec_event_full` builds a `User::Unix` event.
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        alerts.extend(state.on_exec(&exec_event_full(
            200 + i,
            1,
            "sh",
            "sh -c true",
            u64::from(i) * sec,
        )));
    }
    assert!(
        alerts.iter().all(|a| a.technique != "T1059"),
        "SELF-SPAWN must not fire for a Unix shell loop (#159)"
    );
}

#[test]
fn self_spawn_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..SELF_SPAWN_THRESHOLD - 1 {
        let alerts = state.on_exec(&exec_event_win(200 + i, 1, "cmd.exe", "cmd.exe", i as u64));
        assert!(alerts.is_empty());
    }
}

#[test]
fn self_spawn_third_spawn_triggers_alert() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 1_000_000_000));
    let alerts = state.on_exec(&exec_event_win(202, 1, "cmd.exe", "cmd.exe", 2_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn excluded_name_from_untrusted_path_still_alerts() {
    // Name-based exclusion bypass: a payload renamed to an excluded name
    // (wermgr.exe) running from /tmp must NOT inherit the exclusion.
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let mut e = exec_event_win(300 + i, 1, "wermgr.exe", "wermgr.exe", u64::from(i) * sec);
        e.image_path = "/tmp/wermgr.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "masqueraded excluded name must still trigger self-spawn"
    );
}

#[test]
fn excluded_name_from_system_path_stays_excluded() {
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(300 + i, 1, "wermgr.exe", "wermgr.exe", u64::from(i) * sec);
        e.image_path = "C:\\Windows\\System32\\wermgr.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().all(|a| a.technique != "T1059"),
        "the real wermgr.exe must keep its exclusion"
    );
}

#[test]
fn self_spawn_window_slides_instead_of_resetting() {
    // Review finding: the reset-bucket scheme dropped in-window events at the
    // boundary — spawns at t=0s, 29s, 31s, 33s never alerted with a 30s window,
    // even though 29/31/33 are three spawns within 4 seconds.
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 29 * sec));
    state.on_exec(&exec_event_win(202, 1, "cmd.exe", "cmd.exe", 31 * sec));
    let alerts = state.on_exec(&exec_event_win(203, 1, "cmd.exe", "cmd.exe", 33 * sec));
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "three spawns within 4s straddling the bucket boundary must alert"
    );
}

#[test]
fn self_spawn_does_not_realert_past_threshold() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 1_000_000_000));
    state.on_exec(&exec_event_win(202, 1, "cmd.exe", "cmd.exe", 2_000_000_000)); // alerts here
    // 4th spawn, still within the window: already alerted (flag), no duplicate.
    let alerts = state.on_exec(&exec_event_win(203, 1, "cmd.exe", "cmd.exe", 3_000_000_000));
    assert!(alerts.is_empty());
}

#[test]
fn self_spawn_excluded_process_does_not_alert() {
    // MpCmdRun.exe: false positive documented in lab (2026-08-24), explicitly excluded.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_win(200, 1, "MpCmdRun.exe", "MpCmdRun.exe", 0));
    state.on_exec(&exec_event_win(
        201,
        1,
        "MpCmdRun.exe",
        "MpCmdRun.exe",
        1_000_000_000,
    ));
    let alerts = state.on_exec(&exec_event_win(
        202,
        1,
        "MpCmdRun.exe",
        "MpCmdRun.exe",
        2_000_000_000,
    ));
    assert!(alerts.is_empty());
}

// ── Agent's own children (issue #403) ─────────────────────────────────────

#[test]
fn agent_own_wevtutil_child_does_not_alert() {
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(
            6000 + i,
            1084,
            "wevtutil.exe",
            "wevtutil.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\System32\\wevtutil.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.is_empty(),
        "the agent's own wevtutil.exe poll children must not self-alert (#403)"
    );
}

#[test]
fn agent_own_logman_orphan_sweep_does_not_alert() {
    // #408's startup sweep: one `logman query -ets` + one `logman stop` per
    // orphan, all within milliseconds — two orphans already reach the threshold.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(7000 + i, 1084, "logman.exe", "logman.exe", u64::from(i));
        e.image_path = "C:\\Windows\\System32\\logman.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.is_empty(),
        "the agent's own logman.exe orphan-sweep children must not self-alert (#408)"
    );
}

#[test]
fn agent_own_auditpol_child_does_not_alert() {
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(
            6100 + i,
            1084,
            "auditpol.exe",
            "auditpol.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\System32\\auditpol.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.is_empty(),
        "the agent's own auditpol.exe startup child must not self-alert (#403)"
    );
}

#[test]
fn spoofed_own_pid_with_non_allowlisted_image_still_alerts() {
    // Done-when criterion from #403: a process spawned with a spoofed parent (the
    // agent's own pid) and a non-allowlisted image must still trigger SELF-SPAWN —
    // ppid alone must never become a blanket exclusion.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let e = exec_event_win(6200 + i, 1084, "cmd.exe", "cmd.exe", u64::from(i) * sec);
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "spoofing the agent's pid as parent must not exempt an arbitrary child"
    );
}

#[test]
fn agent_child_name_from_untrusted_path_still_alerts() {
    // Same masquerade guard as SELF_SPAWN_EXCLUSIONS: a payload named wevtutil.exe
    // but not living at the real system path must not inherit the exclusion, even
    // with a matching (possibly spoofed) ppid.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let mut e = exec_event_win(
            6300 + i,
            1084,
            "wevtutil.exe",
            "wevtutil.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\Temp\\wevtutil.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "a masqueraded wevtutil.exe outside System32 must still trigger self-spawn"
    );
}

#[test]
fn wevtutil_child_of_a_different_parent_still_alerts() {
    // The exclusion is keyed on the *agent's own* pid, not on the name alone —
    // wevtutil.exe spawned by anything else is not the agent's poll loop.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let mut e = exec_event_win(
            6400 + i,
            9999,
            "wevtutil.exe",
            "wevtutil.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\System32\\wevtutil.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "wevtutil.exe spawned by a pid other than the agent's own must still alert"
    );
}

#[test]
fn self_spawn_outside_window_resets_counter() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 1_000_000_000));
    // 40s later, outside the 30s window: the counter restarts at 1, no 3rd spawn
    // reached.
    let alerts = state.on_exec(&exec_event_win(
        202,
        1,
        "cmd.exe",
        "cmd.exe",
        40_000_000_000,
    ));
    assert!(alerts.is_empty());
}

// ── SELF-SPAWN on system images (#432) ───────────────────────────────────

/// `n` spawns of `child` by pid 1, one second apart, with both image paths set.
fn spawn_burst(child_image: &str, parent_image: Option<&str>, n: u32) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let comm = child_image.rsplit('\\').next().unwrap_or(child_image);
    let mut alerts = Vec::new();
    for i in 0..n {
        let mut e = exec_event_win(500 + i, 1, comm, comm, u64::from(i) * 1_000_000_000);
        e.image_path = child_image.to_string();
        e.parent_image_path = parent_image.map(str::to_string);
        alerts.extend(state.on_exec(&e));
    }
    alerts
        .into_iter()
        .filter(|a| a.technique == "T1059")
        .collect()
}

const SYSTEM_POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

#[test]
fn three_system_children_of_a_system_parent_do_not_alert() {
    // #432: an operator running `schtasks` three times from PowerShell, and
    // svchost → taskhostw.exe, both read as self-spawn at the base threshold.
    assert!(
        spawn_burst(
            r"C:\Windows\System32\schtasks.exe",
            Some(SYSTEM_POWERSHELL),
            3
        )
        .is_empty()
    );
    assert!(
        spawn_burst(
            r"C:\Windows\System32\taskhostw.exe",
            Some(r"C:\Windows\System32\svchost.exe"),
            3
        )
        .is_empty()
    );
}

#[test]
fn an_installed_cli_run_from_a_shell_does_not_alert() {
    assert!(
        spawn_burst(
            r"C:\Program Files\Synthaea\cli.exe",
            Some(SYSTEM_POWERSHELL),
            3
        )
        .is_empty()
    );
}

#[test]
fn a_system_to_system_storm_still_alerts() {
    let taskhostw = r"C:\Windows\System32\taskhostw.exe";
    let svchost = Some(r"C:\Windows\System32\svchost.exe");
    assert!(spawn_burst(taskhostw, svchost, SELF_SPAWN_TRUSTED_THRESHOLD - 1).is_empty());
    assert_eq!(
        spawn_burst(taskhostw, svchost, SELF_SPAWN_TRUSTED_THRESHOLD).len(),
        1
    );
}

#[test]
fn a_system_shell_looping_a_script_host_alerts_at_the_base_threshold() {
    // #494 review: a malicious .ps1 respawning powershell.exe a few times
    // from a system shell, below SELF_SPAWN_TRUSTED_THRESHOLD.
    for child in [
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\wscript.exe",
    ] {
        let alerts = spawn_burst(child, Some(SYSTEM_POWERSHELL), SELF_SPAWN_THRESHOLD);
        assert_eq!(alerts.len(), 1, "{child}");
    }
}

#[test]
fn a_script_host_child_matches_case_insensitively() {
    let alerts = spawn_burst(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE",
        Some(r"C:\Windows\System32\svchost.exe"),
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
}

#[test]
fn a_dropped_parent_spawning_a_system_child_alerts_at_the_base_threshold() {
    // The 2026-09-07 malware3 capture: malware3.exe → powershell.exe, 20 in 30s.
    let alerts = spawn_burst(
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        Some(r"C:\Users\Public\malware3.exe"),
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
}

#[test]
fn a_dropped_child_of_a_system_shell_alerts_at_the_base_threshold() {
    let alerts = spawn_burst(
        r"C:\Users\victim\AppData\Local\Temp\payload.exe",
        Some(r"C:\Windows\System32\cmd.exe"),
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
}

#[test]
fn an_unknown_parent_image_keeps_the_base_threshold() {
    let alerts = spawn_burst(
        r"C:\Windows\System32\schtasks.exe",
        None,
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
}

// ── PARENT-SUSPECT (T1204/T1059) ──────────────────────────────────────────

#[test]
fn winword_spawning_powershell_matches_parent_suspect() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "winword.exe", "winword.exe", 0));
    let alerts = state.on_exec(&exec_event_full(
        101,
        100,
        "powershell.exe",
        "powershell.exe",
        1,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1204/T1059");
}

/// #725: Windows reuses pids quickly. An interpreter whose parent pid now
/// belongs to another incarnation than the cached `winword.exe` gets no Office
/// lineage; the same parent incarnation still alerts.
#[test]
fn a_recycled_windows_parent_pid_does_not_lend_office_lineage() {
    let mut state = RuleState::new();
    let mut word = exec_event_win(100, 1, "winword.exe", "winword.exe", 0);
    word.meta.process_generation = Some(7001);
    state.on_exec(&word);

    let mut child = exec_event_win(101, 100, "powershell.exe", "powershell.exe", 1);
    child.meta.parent_process_generation = Some(7002);
    assert!(state.on_exec(&child).is_empty());

    child.meta.parent_process_generation = Some(7001);
    let alerts = state.on_exec(&child);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1204/T1059");
}

#[test]
fn winword_spawning_notepad_does_not_match_parent_suspect() {
    // notepad.exe is not in SUSPECT_CHILDREN_WIN.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "winword.exe", "winword.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "notepad.exe", "notepad.exe", 1));
    assert!(alerts.is_empty());
}

#[test]
fn explorer_spawning_powershell_does_not_match_parent_suspect() {
    // explorer.exe is not in SUSPECT_PARENTS_WIN — normal manual launch.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "explorer.exe", "explorer.exe", 0));
    let alerts = state.on_exec(&exec_event_full(
        101,
        100,
        "powershell.exe",
        "powershell.exe",
        1,
    ));
    assert!(alerts.is_empty());
}

// ── LOLBIN (T1218/T1127) ─────────────────────────────────────────────────

#[test]
fn cmd_spawning_msbuild_matches_lolbin() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "cmd.exe", "cmd.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "msbuild.exe", "msbuild.exe", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1218/T1127");
}

#[test]
fn devenv_spawning_msbuild_does_not_match_lolbin() {
    // devenv.exe: legitimate parent (dev environment), see LOLBIN_LEGIT_PARENTS.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "devenv.exe", "devenv.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "msbuild.exe", "msbuild.exe", 1));
    assert!(alerts.is_empty());
}

#[test]
fn cmd_spawning_notepad_does_not_match_lolbin() {
    // notepad.exe is not in LOLBINS.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "cmd.exe", "cmd.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "notepad.exe", "notepad.exe", 1));
    assert!(alerts.is_empty());
}

// ── BEACON (T1071/T1041) ──────────────────────────────────────────────────

#[test]
fn beacon_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..BEACON_THRESHOLD - 1 {
        let alerts = state.on_connect(&connect_event_full(
            300,
            "malware.exe",
            [10, 0, 0, 1],
            4444,
            i as u64,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn beacon_third_connection_triggers_alert() {
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        0,
    ));
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1071/T1041");
}

#[test]
fn beacon_standard_port_does_not_alert() {
    // Port 443 is in STANDARD_PORTS: expected legitimate HTTPS traffic, not beaconing.
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(300, "app.exe", [10, 0, 0, 1], 443, 0));
    state.on_connect(&connect_event_full(
        300,
        "app.exe",
        [10, 0, 0, 1],
        443,
        1_000_000_000,
    ));
    let alerts = state.on_connect(&connect_event_full(
        300,
        "app.exe",
        [10, 0, 0, 1],
        443,
        2_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn beacon_browser_does_not_alert() {
    // chrome.exe is in BROWSERS: repeated outbound connections = normal behavior.
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(
        300,
        "chrome.exe",
        [10, 0, 0, 1],
        4444,
        0,
    ));
    state.on_connect(&connect_event_full(
        300,
        "chrome.exe",
        [10, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_connect(&connect_event_full(
        300,
        "chrome.exe",
        [10, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn beacon_outside_window_resets_counter() {
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        0,
    ));
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    // 90s later, outside the 60s window: the counter restarts at 1.
    let alerts = state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        90_000_000_000,
    ));
    assert!(alerts.is_empty());
}

// ── Download-then-exec (T1105) on Windows paths (#442) ──────────────────────

/// A Windows download by `downloader` of `path`, then an exec of `comm` 5s later.
fn windows_download_then_exec(downloader: &str, path: &str, comm: &str) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let _ = state.on_file_open(&file_open_event_full(
        50,
        downloader,
        path,
        O_WRONLY | O_CREAT,
        0,
    ));
    state.on_exec(&exec_event_win(51, 1, comm, path, 5_000_000_000))
}

#[test]
fn curl_exe_download_then_exec_matches_on_windows() {
    // Regression (#442): the downloader list said `curl` (the ETW comm is
    // `curl.exe`) and the leaf was cut on `/`, so the rule never fired on Windows.
    let alerts = windows_download_then_exec(
        "curl.exe",
        r"C:\Users\victim\AppData\Local\Temp\payload.exe",
        "payload.exe",
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].technique, "T1105");
}

#[test]
fn certutil_download_then_exec_matches() {
    let alerts = windows_download_then_exec("certutil.exe", r"C:\ProgramData\p.exe", "p.exe");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn windows_leaf_match_ignores_case_like_ntfs() {
    let alerts = windows_download_then_exec("curl.exe", r"C:\Temp\PAYLOAD.EXE", "payload.exe");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn unc_path_download_then_exec_matches() {
    let alerts = windows_download_then_exec("curl.exe", r"\\share\drop\p.exe", "p.exe");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn powershell_writes_do_not_feed_the_download_join() {
    // Deliberately not a downloader: powershell.exe writes far too many files.
    let alerts = windows_download_then_exec("powershell.exe", r"C:\Temp\p.exe", "p.exe");
    assert!(alerts.iter().all(|a| a.technique != "T1105"), "{alerts:?}");
}

#[test]
fn a_linux_leaf_match_stays_case_sensitive() {
    let mut state = RuleState::new();
    let _ = state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/Payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        5_000_000_000,
    ));
    assert!(alerts.iter().all(|a| a.technique != "T1105"), "{alerts:?}");
}

// ── POLICY-DENIAL-DRIFT via AppLocker / WDAC (#796, PolicyDenialEvent) ──

fn applocker_denial(class: &str, path: &str, enforced: bool) -> PolicyDenialEvent {
    PolicyDenialEvent {
        action: Some("execute".to_string()),
        object_path: Some(path.to_string()),
        ..policy_denial_event_full("applocker", None, None, Some(class), enforced)
    }
}

fn wdac_denial(process: &str, file: &str, enforced: bool) -> PolicyDenialEvent {
    PolicyDenialEvent {
        action: Some("load".to_string()),
        object_path: Some(file.to_string()),
        ..policy_denial_event_full("wdac", Some(process), None, Some("user-mode"), enforced)
    }
}

#[test]
fn applocker_alerts_once_per_blocked_file_not_once_per_rule_collection() {
    // The #781 key collapsed every AppLocker denial to its rule collection: the
    // second blocked .exe of the run never alerted.
    let mut state = RuleState::new();
    let first = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\a.exe", true));
    let second = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\b.exe", true));
    let repeat = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\a.exe", true));
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert!(repeat.is_empty(), "{repeat:?}");
    assert!(
        first[0].message.contains(r"C:\Users\x\a.exe"),
        "{}",
        first[0].message
    );
}

#[test]
fn applocker_paths_match_case_insensitively() {
    // FullFilePath keeps the original case; an expanded FilePath is upper-case.
    let mut state = RuleState::new();
    let full = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\Evil.exe", true));
    let expanded = state.on_policy_denial(&applocker_denial("EXE", r"C:\USERS\X\EVIL.EXE", true));
    assert_eq!(full.len(), 1);
    assert!(expanded.is_empty(), "{expanded:?}");
}

#[test]
fn applocker_same_file_in_another_rule_collection_is_a_new_shape() {
    let mut state = RuleState::new();
    let exe = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\run.ps1", true));
    let script = state.on_policy_denial(&applocker_denial("SCRIPT", r"C:\Users\x\run.ps1", true));
    assert_eq!(exe.len(), 1);
    assert_eq!(script.len(), 1);
}

#[test]
fn an_enforced_windows_denial_is_medium_and_an_audit_one_low() {
    let mut state = RuleState::new();
    let blocked = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\a.exe", true));
    let audited = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\b.exe", false));
    assert_eq!(blocked[0].severity, schema::detection::Severity::Medium);
    assert_eq!(audited[0].severity, schema::detection::Severity::Low);
    assert!(
        audited[0].message.contains("audit mode"),
        "{}",
        audited[0].message
    );
    assert!(
        blocked
            .iter()
            .chain(&audited)
            .all(|a| a.technique == "T1562")
    );
}

#[test]
fn wdac_is_keyed_by_the_loading_process_and_the_file() {
    let rundll = r"\Device\HarddiskVolume3\Windows\System32\rundll32.exe";
    let regsvr = r"\Device\HarddiskVolume3\Windows\System32\regsvr32.exe";
    let dll = r"\Device\HarddiskVolume3\Users\Public\x.dll";
    let mut state = RuleState::new();
    let first = state.on_policy_denial(&wdac_denial(rundll, dll, true));
    let other_process = state.on_policy_denial(&wdac_denial(regsvr, dll, true));
    let repeat = state.on_policy_denial(&wdac_denial(
        &rundll.to_uppercase(),
        &dll.to_uppercase(),
        true,
    ));
    assert_eq!(first.len(), 1);
    assert_eq!(other_process.len(), 1);
    assert!(repeat.is_empty(), "{repeat:?}");
    assert!(
        first[0].message.contains("rundll32.exe"),
        "{}",
        first[0].message
    );
}

#[test]
fn a_file_first_seen_in_audit_mode_alerts_again_when_the_policy_blocks_it() {
    // `enforced` is part of the key for AppLocker/WDAC: an audit-mode rollout followed by
    // enforcement must not leave the blocks silent because the Low alert came first.
    let mut state = RuleState::new();
    let audited = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\a.exe", false));
    let audited_again =
        state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\a.exe", false));
    let blocked = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\a.exe", true));
    let blocked_again =
        state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\a.exe", true));
    assert_eq!(audited[0].severity, schema::detection::Severity::Low);
    assert!(audited_again.is_empty(), "{audited_again:?}");
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].severity, schema::detection::Severity::Medium);
    assert!(blocked_again.is_empty(), "{blocked_again:?}");
}

#[test]
fn a_wdac_audit_denial_is_low() {
    let rundll = r"\Device\HarddiskVolume3\Windows\System32\rundll32.exe";
    let dll = r"\Device\HarddiskVolume3\Users\Public\x.dll";
    let mut state = RuleState::new();
    let audited = state.on_policy_denial(&wdac_denial(rundll, dll, false));
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].severity, schema::detection::Severity::Low);
    assert!(
        audited[0].message.contains("audit mode"),
        "{}",
        audited[0].message
    );
}

#[test]
fn the_wdac_signing_scenario_is_part_of_the_key() {
    let rundll = r"\Device\HarddiskVolume3\Windows\System32\rundll32.exe";
    let dll = r"\Device\HarddiskVolume3\Users\Public\x.dll";
    let user_mode = wdac_denial(rundll, dll, true);
    let kernel_mode = PolicyDenialEvent {
        object_class: Some("kernel-mode".to_string()),
        ..user_mode.clone()
    };
    let mut state = RuleState::new();
    assert_eq!(state.on_policy_denial(&user_mode).len(), 1);
    assert_eq!(
        state.on_policy_denial(&kernel_mode).len(),
        1,
        "the same process and file under another signing scenario is a new shape"
    );
    assert!(state.on_policy_denial(&user_mode).is_empty());
}

#[test]
fn a_wdac_denial_without_a_loading_process_is_still_keyed_by_the_file() {
    let anonymous = |file: &str| PolicyDenialEvent {
        subject_context: None,
        ..wdac_denial("unused", file, true)
    };
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_policy_denial(&anonymous(r"\Device\HarddiskVolume3\a.dll"))
            .len(),
        1
    );
    assert_eq!(
        state
            .on_policy_denial(&anonymous(r"\Device\HarddiskVolume3\b.dll"))
            .len(),
        1
    );
    assert!(
        state
            .on_policy_denial(&anonymous(r"\Device\HarddiskVolume3\a.dll"))
            .is_empty()
    );
}

#[test]
fn a_missing_path_and_an_empty_one_are_the_same_shape() {
    // Both sensors always report the file, so this is a degenerate event: it shares one
    // shape per (class, enforced) instead of alerting on every repeat, and `None` and
    // `Some("")` are not two different shapes.
    let mut state = RuleState::new();
    let no_path = PolicyDenialEvent {
        object_path: None,
        ..applocker_denial("EXE", "", true)
    };
    let empty_path = applocker_denial("EXE", "", true);
    let other_class = PolicyDenialEvent {
        object_path: None,
        ..applocker_denial("DLL", "", true)
    };
    assert_eq!(state.on_policy_denial(&no_path).len(), 1);
    assert!(state.on_policy_denial(&empty_path).is_empty());
    assert_eq!(state.on_policy_denial(&other_class).len(), 1);
}

#[test]
fn an_audit_mode_flood_does_not_use_up_the_budget_of_real_blocks_or_selinux() {
    // A fresh AppLocker audit rollout logs every unlisted binary once. Past the cap those are
    // shed, but the enforced Windows budget and the SELinux budget are separate.
    let mut state = RuleState::new();
    let mut audited = 0usize;
    for i in 0..=POLICY_DENIAL_ALERT_CAP {
        audited += state
            .on_policy_denial(&applocker_denial(
                "EXE",
                &format!(r"C:\Users\x\tool{i}.exe"),
                false,
            ))
            .len();
    }
    assert_eq!(
        audited, POLICY_DENIAL_ALERT_CAP as usize,
        "the (cap + 1)th audit-mode shape is shed"
    );

    let blocked = state.on_policy_denial(&applocker_denial("EXE", r"C:\Users\x\evil.exe", true));
    assert_eq!(blocked.len(), 1, "a real block still alerts");
    assert_eq!(blocked[0].severity, schema::detection::Severity::Medium);

    let selinux = state.on_policy_denial(&policy_denial_event_full(
        "selinux",
        Some("system_u:system_r:httpd_t:s0"),
        Some("system_u:object_r:user_home_t:s0"),
        Some("file"),
        true,
    ));
    assert_eq!(selinux.len(), 1, "SELinux has its own budget");
}

#[test]
fn a_windows_denial_alert_names_the_user_sid() {
    let event = PolicyDenialEvent {
        meta: schema::EventMeta {
            user: schema::User::Windows {
                sid: "S-1-5-21-1000".to_string(),
                integrity_level: None,
            },
            ..meta()
        },
        ..applocker_denial("EXE", r"C:\Users\x\a.exe", true)
    };
    let alerts = RuleState::new().on_policy_denial(&event);
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0].message.contains("sid=S-1-5-21-1000"),
        "{}",
        alerts[0].message
    );
}
