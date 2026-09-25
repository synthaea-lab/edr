# File Activity Detection Patterns

Detection patterns for the file-activity event types introduced in issue #262:
`FileWrite`, `FileDelete`, and `FileRename`.

## Table of Contents

- [Overview](#overview)
- [Ransomware Detection](#ransomware-detection)
  - [Pattern 1: Mass Rename to Encrypted Extensions](#pattern-1-mass-rename-to-encrypted-extensions)
  - [Pattern 2: Burst Writes + Mass Renames](#pattern-2-burst-writes--mass-renames)
- [Evidence Destruction](#evidence-destruction)
- [FileWrite Correlation](#filewrite-correlation)
- [State Management](#state-management)

## Overview

File activity events provide real-time telemetry for detecting:
- **Ransomware**: burst writes + mass renames to encrypted extensions
- **Evidence destruction**: deletion of logs, forensic artifacts
- **Data exfiltration**: unusual write volume to removable media
- **Tampering**: writes to sensitive system files

**Critical:** `FileWriteEvent` carries no path (see `schema::FileWriteEvent` docs for
rationale). Detection rules must correlate `FileOpen` → `FileWrite` to get file paths.

## Ransomware Detection

### Pattern 1: Mass Rename to Encrypted Extensions

**Signal:** Many files renamed to suspicious extensions (`.locked`, `.encrypted`,
`.crypted`, `.enc`, `.crypt`) within a short time window.

```rust,ignore
// Pseudo-code: detect mass rename to ransomware extensions
fn check_mass_rename(state: &mut State, event: FileRenameEvent) -> Option<Alert> {
    // Check if new_path has a ransomware extension
    let suspicious_extensions = [".locked", ".encrypted", ".crypted", ".enc", ".crypt"];
    let is_suspicious = suspicious_extensions.iter()
        .any(|ext| event.new_path.ends_with(ext));

    if !is_suspicious {
        return None;
    }

    // Track renames per pid in a sliding 60-second window
    let window = Duration::from_secs(60);
    state.track_rename(event.meta.pid, event.meta.timestamp_ns, window);

    let rename_count = state.count_renames(event.meta.pid, window);

    // Alert if >= 50 renames in 60 seconds
    if rename_count >= 50 {
        Some(Alert {
            severity: Critical,
            technique: "T1486", // Data Encrypted for Impact
            title: "Suspected ransomware: mass file rename",
            context: format!(
                "{} renamed {} files to encrypted extensions in 60s",
                event.meta.comm, rename_count
            ),
        })
    } else {
        None
    }
}
```

**Real-world thresholds:**
- **50+ renames in 60s**: high confidence (typical ransomware burst)
- **20-49 renames in 60s**: medium confidence (slow ransomware or zip operations)
- **< 20 renames in 60s**: likely benign (normal file operations)

**False positive mitigation:**
- Exclude known archiver processes: `zip`, `tar`, `7z`
- Exclude paths: `/tmp`, `/var/tmp` (compression temp files)
- Require **diverse** source paths (not all in one directory)

### Pattern 2: Burst Writes + Mass Renames

**Signal:** High write volume followed by mass renames — the full ransomware kill chain.

```rust,ignore
// Pseudo-code: correlate burst writes with mass renames
fn check_ransomware_kill_chain(state: &mut State, event: Event) -> Option<Alert> {
    match event {
        Event::FileWrite(write) => {
            // Track write volume per pid in a 60-second sliding window
            state.add_write_volume(
                write.meta.pid,
                write.bytes_requested,
                write.meta.timestamp_ns,
            );
        }
        Event::FileRename(rename) => {
            let window = Duration::from_secs(60);

            // Get recent write volume for this pid
            let bytes_written = state.get_write_volume(rename.meta.pid, window);
            let rename_count = state.count_renames(rename.meta.pid, window);

            // Alert if: high write volume + mass renames
            // Threshold: 100MB written + 50 renames in 60s
            if bytes_written >= 100 * 1024 * 1024 && rename_count >= 50 {
                return Some(Alert {
                    severity: Critical,
                    technique: "T1486",
                    title: "Suspected ransomware: burst write + mass rename",
                    context: format!(
                        "{} wrote {}MB and renamed {} files in 60s",
                        rename.meta.comm,
                        bytes_written / (1024 * 1024),
                        rename_count
                    ),
                });
            }
        }
        _ => {}
    }
    None
}
```

**Why correlate both signals?**
- **Write volume alone**: false positives (video encoding, database writes, compilers)
- **Renames alone**: false positives (zip extraction, git operations)
- **Combined**: high-confidence ransomware indicator

**Tuning:**
- Adjust thresholds per environment (file server vs laptop)
- Consider write **diversity**: writes to many different files (not one log)
- Weight by file type: documents > system files

## Evidence Destruction

**Signal:** Deletion of log files, forensic artifacts, or history files.

```rust,ignore
// Pseudo-code: detect log destruction
fn check_log_destruction(event: FileDeleteEvent) -> Option<Alert> {
    // Suspicious paths: logs, audit trails, shell history
    let suspicious_paths = [
        "/var/log/",
        "/var/audit/",
        "/.bash_history",
        "/.zsh_history",
        "/var/log/auth.log",
        "/var/log/secure",
    ];

    let is_log = suspicious_paths.iter()
        .any(|prefix| event.path.starts_with(prefix));

    if !is_log {
        return None;
    }

    // Higher severity if deleted by non-root or unusual process
    let severity = if event.meta.uid != 0 {
        High
    } else {
        Medium
    };

    Some(Alert {
        severity,
        technique: "T1070.002", // Indicator Removal: Clear Linux or Mac System Logs
        title: "Log file deletion",
        context: format!(
            "{} (uid={}) deleted {}",
            event.meta.comm, event.meta.uid, event.path
        ),
    })
}
```

**Detection variants:**
- **Mass deletion**: many log files deleted in short window
- **Selective deletion**: specific audit logs (auth.log, secure) deleted
- **History clearing**: `.bash_history`, `.zsh_history` deleted

## FileWrite Correlation

**Critical:** `FileWriteEvent` has no path. Rules must correlate with `FileOpen`.

### Correlation State Management

```rust,ignore
// Track open fds to correlate FileOpen → FileWrite
struct FdTracker {
    // Key: (pid, fd) → Value: (path, timestamp)
    fds: BoundedMap<(u32, u32), (String, u64)>,
}

impl FdTracker {
    fn track_open(&mut self, event: FileOpenEvent) {
        let key = (event.meta.pid, event.fd);
        let value = (event.path.clone(), event.meta.timestamp_ns);

        // Bounded map prevents unbounded growth
        self.fds.insert(key, value);
    }

    fn get_path(&self, pid: u32, fd: u32) -> Option<&str> {
        self.fds.get(&(pid, fd)).map(|(path, _)| path.as_str())
    }

    fn cleanup_old(&mut self, now_ns: u64, max_age_ns: u64) {
        // Remove fds older than max_age to bound memory
        self.fds.retain(|_, (_, ts)| now_ns - *ts < max_age_ns);
    }
}
```

### Correlated Write Detection

```rust,ignore
// Example: detect writes to sensitive system files
fn check_sensitive_write(
    tracker: &FdTracker,
    event: FileWriteEvent,
) -> Option<Alert> {
    // Look up the path from prior FileOpen
    let path = tracker.get_path(event.meta.pid, event.fd)?;

    let sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/boot/grub/grub.cfg",
    ];

    if !sensitive_paths.iter().any(|p| path.starts_with(p)) {
        return None;
    }

    Some(Alert {
        severity: High,
        technique: "T1098", // Account Manipulation
        title: "Write to sensitive system file",
        context: format!(
            "{} (uid={}) wrote {} bytes to {}",
            event.meta.comm,
            event.meta.uid,
            event.bytes_requested,
            path
        ),
    })
}
```

## State Management

**Memory bounds:** All detection state must be bounded to prevent DoS.

### Sliding Time Windows

```rust,ignore
// Time-bounded event tracking (replaces fixed-interval buckets)
struct SlidingWindow<T> {
    events: VecDeque<(u64, T)>, // (timestamp_ns, event)
    window_ns: u64,
}

impl<T> SlidingWindow<T> {
    fn add(&mut self, timestamp_ns: u64, event: T) {
        // Drop events outside the window
        let cutoff = timestamp_ns.saturating_sub(self.window_ns);
        while self.events.front().map(|(ts, _)| *ts < cutoff).unwrap_or(false) {
            self.events.pop_front();
        }

        self.events.push_back((timestamp_ns, event));
    }

    fn count(&self) -> usize {
        self.events.len()
    }
}
```

### Bounded Maps

```rust,ignore
// Use store::BoundedMap for all keyed state
use crate::store::BoundedMap;

// Example: track per-pid rename counts
let mut rename_counts: BoundedMap<u32, SlidingWindow<()>> =
    BoundedMap::new(1000); // Max 1000 pids tracked

// Insertion evicts oldest entry if at capacity
rename_counts.entry(pid).or_insert_with(|| SlidingWindow::new(60_000_000_000));
```

**Eviction policy:**
- **LRU eviction** when at capacity (oldest-accessed entry dropped)
- **Counted shedding**: log when events are dropped due to capacity
- **Observable**: metrics on state size, eviction rate

See `crates/store` for `BoundedMap` implementation details.

## Performance Considerations

**FileWrite volume:** `write(2)` is extremely frequent (10K+/sec under heavy I/O).

**Rule optimization:**
1. **Early filtering**: check conditions in cheapest-first order
   ```rust,ignore
   // Fast path: check extension before any state lookup
   if !path.ends_with(".locked") {
       return None;
   }
   ```

2. **Bounded state**: never track unbounded keys (pids, fds, paths)
   ```rust,ignore
   // WRONG: unbounded
   let mut fds: HashMap<(u32, u32), String> = HashMap::new();

   // RIGHT: bounded
   let mut fds: BoundedMap<(u32, u32), String> = BoundedMap::new(10_000);
   ```

3. **Cleanup old state**: expire fd mappings after reasonable timeout
   ```rust,ignore
   // Clean up fds not written to in 5 minutes
   tracker.cleanup_old(now_ns, 5 * 60 * 1_000_000_000);
   ```

**Event rate limits:** Consider sampling FileWrite events under sustained high load
(future work, issue #262 Phase 2).

## References

- Issue #262: File write/delete/rename telemetry (Phase 1 implementation)
- `schema::FileWriteEvent`: schema docs with correlation pattern
- `crates/store`: bounded state containers
- MITRE ATT&CK:
  - T1486: Data Encrypted for Impact (ransomware)
  - T1070.002: Indicator Removal: Clear Linux or Mac System Logs
  - T1098: Account Manipulation (sensitive file tampering)
