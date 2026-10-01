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

/// Spawns `n` same-name children of ppid 1, `spacing_ns` apart from `start_ns`,
/// and returns every alert raised.
fn spawn_burst(
    state: &mut RuleState,
    comm: &str,
    n: u32,
    start_ns: u64,
    spacing_ns: u64,
) -> Vec<crate::Alert> {
    (0..n)
        .flat_map(|i| {
            state.on_exec(&exec_event_win(
                200 + i,
                1,
                comm,
                comm,
                start_ns + u64::from(i) * spacing_ns,
            ))
        })
        .collect()
}

#[test]
fn self_spawn_alerts_on_the_threshold_spawn() {
    let mut state = RuleState::new();
    assert!(
        spawn_burst(
            &mut state,
            "cmd.exe",
            SELF_SPAWN_THRESHOLD - 1,
            0,
            1_000_000_000
        )
        .is_empty()
    );
    let alerts = state.on_exec(&exec_event_win(
        999,
        1,
        "cmd.exe",
        "cmd.exe",
        20_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn three_same_name_children_in_30s_is_ordinary_windows_activity() {
    // #432, all seen at exactly 3 on lab hosts: an operator running `cli.exe`
    // three times from a shell, a scenario creating three tasks, svchost
    // starting `taskhostw.exe`.
    let mut state = RuleState::new();
    for comm in ["cli.exe", "schtasks.exe", "taskhostw.exe"] {
        assert!(
            spawn_burst(&mut state, comm, 3, 0, 1_000_000_000).is_empty(),
            "{comm}"
        );
    }
}

#[test]
fn a_powershell_respawn_loop_alerts_within_15s() {
    // The pace of the malware3 capture (2026-09-07): ~1.4 s between respawns
    // until the 10th, at 13 s.
    let mut state = RuleState::new();
    let alerts = spawn_burst(&mut state, "powershell.exe", 11, 0, 1_400_000_000);
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0]
            .message
            .contains(&format!("spawned {SELF_SPAWN_THRESHOLD}x")),
        "{}",
        alerts[0].message
    );
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
    // boundary — a burst straddling the 30 s mark never alerted, even though
    // all of it fell within a few seconds.
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    state.on_exec(&exec_event_win(100, 1, "cmd.exe", "cmd.exe", 0));
    // 26 s .. 32.75 s: a 30 s bucket opened at 0 holds 7 of these, the next one 4.
    let alerts = spawn_burst(
        &mut state,
        "cmd.exe",
        SELF_SPAWN_THRESHOLD,
        26 * sec,
        750_000_000,
    );
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "a burst straddling the bucket boundary must alert"
    );
}

#[test]
fn self_spawn_does_not_realert_past_threshold() {
    let mut state = RuleState::new();
    let alerts = spawn_burst(
        &mut state,
        "cmd.exe",
        SELF_SPAWN_THRESHOLD + 3,
        0,
        1_000_000_000,
    );
    assert_eq!(
        alerts.len(),
        1,
        "one alert per window, not one per spawn past the threshold"
    );
}

#[test]
fn self_spawn_excluded_process_does_not_alert() {
    // MpCmdRun.exe: false positive documented in lab (2026-08-24), explicitly excluded.
    let mut state = RuleState::new();
    let alerts: Vec<_> = (0..SELF_SPAWN_THRESHOLD + 2)
        .flat_map(|i| {
            let mut e = exec_event_win(200 + i, 1, "MpCmdRun.exe", "MpCmdRun.exe", u64::from(i));
            e.image_path = r"C:\Windows\System32\MpCmdRun.exe".to_string();
            state.on_exec(&e)
        })
        .collect();
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
    // One spawn short of the threshold, then the last one 40 s later: the first
    // ones have slid out of the 30 s window.
    let mut state = RuleState::new();
    assert!(
        spawn_burst(
            &mut state,
            "cmd.exe",
            SELF_SPAWN_THRESHOLD - 1,
            0,
            100_000_000
        )
        .is_empty()
    );
    let alerts = state.on_exec(&exec_event_win(
        999,
        1,
        "cmd.exe",
        "cmd.exe",
        40_000_000_000,
    ));
    assert!(alerts.is_empty());
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
