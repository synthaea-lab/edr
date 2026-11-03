//! UNEXPLAINED-UNIT-STOP (T1562.001, #1085): a security service stopped that nothing visible asked
//! for.
//!
//! The journal sensor reports a stop of a unit of [`SECURITY_SERVICES`] as a `FileOpenEvent`
//! carrying [`schema::FLAG_UNIT_STOPPED`]. The journal names no actor, so this rule asks the
//! other question: was the stop **explained**? `check_security_tool_stop` already alerts on a
//! `systemctl stop falco`; what it cannot see is a stop over D-Bus, from a script's API call, or
//! after the service was killed, and those are what is left once the explained stops are set
//! aside. A stop is explained when, judged once [`START_WITHIN_NS`] has passed over it:
//!
//! 1. an exec stopped the same unit just before ([`EXEC_LOOKBACK_NS`]), so the exec rule has
//!    already alerted and a second alert would be the same finding twice;
//! 2. the unit was started again within [`START_WITHIN_NS`] (a restart, or a package upgrade);
//! 3. the host was told to shut down just before ([`SHUTDOWN_WINDOW_NS`]).
//!
//! Anything else is Medium: a stop whose cause the agent did not see. An administrator who stops
//! a unit from a web console or a configuration-management agent over D-Bus looks the same, which
//! is why the severity is not higher.
//!
//! **No shutdown signal exists** in the stream (the journal sensor reports unit stops of the
//! listed services only, not `shutdown.target`), and the service-stop burst counts *execs*, not
//! journal stops, so neither can stand for condition 3. It is read from the exec of `shutdown`,
//! `reboot`, `poweroff`, `halt`, `systemctl reboot|poweroff|halt|kexec` and `init 0|6`. Only an
//! **immediate** shutdown (`shutdown now`, `+0`) opens the window: `shutdown +60` or `23:00`
//! schedules one that stops nothing yet, and would otherwise cloak any stop in the next five
//! minutes (`shutdown +99`, stop the tool, `shutdown -c`). `shutdown -c`/`--cancel` (and
//! `systemctl --when=cancel`) closes a window already open. A shutdown asked another way (power button, logind from a
//! desktop session, a hypervisor ACPI request) is a stated gap: its stops alert.
//!
//! Judging at the end of a wait, not on arrival, is what makes condition 2 possible and what makes
//! the order the exec and the journal events arrive in irrelevant: the journal and the eBPF exec
//! stream are drained independently. The cost is latency, and that a stop waits for the stream
//! clock (any later exec or file-open event) to pass it, like SETUID-ROOT-REQUEST's queue.

use std::collections::VecDeque;

use schema::{ExecEvent, FileOpenEvent, SECURITY_SERVICES, detection::Severity};
use store::BoundedMap;

use crate::{
    Alert,
    recon::{args, program},
    servicestop::services_stopped,
};

/// How long after a stop the unit may start again for the stop to count as a restart. A
/// `systemctl restart` is back in seconds, but a package upgrade stops the service in its
/// pre-remove script and starts it in post-install, with the unpack in between: two minutes
/// covers that for a large package without leaving a stopped security tool unreported for long.
/// A choice, not a measurement: no fleet data yet.
pub(crate) const START_WITHIN_NS: u64 = 120_000_000_000;

/// How long before the journal's stop record a stopping exec may have run. A stop is logged when
/// its job ends, up to systemd's `DefaultTimeoutStopSec` (90 s) after the exec asked for it; the
/// rest is margin.
pub(crate) const EXEC_LOOKBACK_NS: u64 = 120_000_000_000;

/// How long after a shutdown was asked for its stops are expected: the units stop in dependency
/// order, each bounded by `DefaultTimeoutStopSec` (90 s), so a shutdown's last stop can come
/// minutes later. A scheduled `shutdown +10` does not open it: its stops alert.
pub(crate) const SHUTDOWN_WINDOW_NS: u64 = 300_000_000_000;

/// Clock difference tolerated between the two sources: the journal's realtime timestamp and the
/// exec's boot-offset kernel time are not the same clock, so an exec may look a moment later than
/// the stop it caused.
pub(crate) const CLOCK_SKEW_NS: u64 = 5_000_000_000;

/// Stops waiting for their wait to end. Only the listed units are queued and a host has a handful
/// of them, so the bound is a flood guard: the oldest is judged at once, which errs towards an
/// alert.
const PENDING_CAP: usize = 64;

/// Units tracked. `SECURITY_SERVICES` has 24 names.
const UNIT_CAP: usize = 64;

/// Touches kept per unit, oldest dropped.
const TOUCHES_PER_UNIT: usize = 16;

/// What an exec did to a unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Touch {
    /// `systemctl stop`, `disable --now`, `mask --now`, `service X stop`: the exec rule's.
    Stop,
    /// `systemctl restart` / `try-restart`: a stop and a start.
    Restart,
    /// `systemctl start` / `reload-or-restart`, `enable --now`, `service X start`.
    Start,
}

/// The history and queue of UNEXPLAINED-UNIT-STOP, held by `RuleState`.
pub(crate) struct UnitStops {
    /// Unit (lowercase, no suffix) → its recent touches `(kind, exec time)`. LRU-bounded.
    touches: BoundedMap<String, Vec<(Touch, u64)>>,
    /// When the host was last told to shut down.
    shutdown_ns: Option<u64>,
    /// Stops waiting to be judged, oldest first.
    pending: VecDeque<FileOpenEvent>,
    /// Stops judged early because the queue overflowed, until the next [`Self::take_due`].
    ready: Vec<(FileOpenEvent, Alert)>,
    /// The latest timestamp of any exec or unit stop seen: the stream's clock.
    clock_ns: u64,
}

impl UnitStops {
    pub(crate) fn new() -> Self {
        Self {
            touches: BoundedMap::new(UNIT_CAP),
            shutdown_ns: None,
            pending: VecDeque::new(),
            ready: Vec::new(),
            clock_ns: 0,
        }
    }

    /// An exec: record what it does to a listed unit, or that it shuts the host down.
    pub(crate) fn on_exec(&mut self, event: &ExecEvent) {
        let ts = event.meta.timestamp_ns;
        self.clock_ns = self.clock_ns.max(ts);
        // The shutdown and start claims are name-keyed (the basename of the image), and each one
        // suppresses an alert: they count only from a system image path, or an unknown one
        // (`policy::name_exclusion_applies`), so a `/tmp/reboot` copy of `true` explains nothing.
        let trusted = policy::name_exclusion_applies(Some(&event.image_path));
        match shutdown_effect(event).filter(|_| trusted) {
            Some(Shutdown::Now) => self.shutdown_ns = Some(ts),
            Some(Shutdown::Cancel) => self.shutdown_ns = None,
            None => {}
        }
        for (touch, unit) in unit_touches(event, trusted) {
            let list = self.touches.get_or_insert_with(unit, Vec::new);
            if list.len() >= TOUCHES_PER_UNIT {
                list.remove(0);
            }
            list.push((touch, ts));
        }
    }

    /// A file-open event: a unit stop is queued, to be judged by [`Self::take_due`].
    pub(crate) fn on_file_open(&mut self, event: &FileOpenEvent) {
        self.clock_ns = self.clock_ns.max(event.meta.timestamp_ns);
        if event.flags & schema::FLAG_UNIT_STOPPED == 0 || listed_unit(&event.path).is_none() {
            return;
        }
        if self.pending.len() >= PENDING_CAP
            && let Some(oldest) = self.pending.pop_front()
            && let Some(alert) = self.judge(&oldest)
        {
            self.ready.push((oldest, alert));
        }
        self.pending.push_back(event.clone());
    }

    /// The queued stops whose wait is over, judged. The sink calls this after every exec and
    /// file-open event, which are what move the clock.
    pub(crate) fn take_due(&mut self) -> Vec<(FileOpenEvent, Alert)> {
        let mut due = std::mem::take(&mut self.ready);
        while let Some(front) = self.pending.front() {
            if front.meta.timestamp_ns.saturating_add(START_WITHIN_NS) > self.clock_ns {
                break;
            }
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            if let Some(alert) = self.judge(&event) {
                due.push((event, alert));
            }
        }
        due
    }

    /// `None` when the stop is explained, else the alert.
    fn judge(&self, event: &FileOpenEvent) -> Option<Alert> {
        let unit = listed_unit(&event.path)?;
        let at = event.meta.timestamp_ns;
        // The window an exec asking for the stop may sit in, either side of the record.
        let asked_from = at.saturating_sub(EXEC_LOOKBACK_NS);
        let asked_to = at.saturating_add(CLOCK_SKEW_NS);
        let touches = self.touches.peek(&unit).map_or(&[][..], Vec::as_slice);

        let stopped_by_exec = touches
            .iter()
            .any(|&(kind, ts)| kind == Touch::Stop && (asked_from..=asked_to).contains(&ts));
        let restarted = touches.iter().any(|&(kind, ts)| match kind {
            Touch::Restart => (asked_from..=asked_to).contains(&ts),
            Touch::Start => (at.saturating_sub(CLOCK_SKEW_NS)..=at.saturating_add(START_WITHIN_NS))
                .contains(&ts),
            Touch::Stop => false,
        });
        let shutting_down = self.shutdown_ns.is_some_and(|ts| {
            (at.saturating_sub(CLOCK_SKEW_NS)..=at.saturating_add(CLOCK_SKEW_NS)).contains(&ts)
                || (ts..=ts.saturating_add(SHUTDOWN_WINDOW_NS)).contains(&at)
        });
        if stopped_by_exec || restarted || shutting_down {
            return None;
        }
        Some(Alert {
            technique: "T1562.001",
            severity: Severity::Medium,
            message: format!(
                "the security service {unit} was stopped with no `systemctl stop` of it, no \
                 start of it within {}s and no host shutdown in progress: a stop over D-Bus or \
                 an API, a kill of the service, or the service exiting by itself (the journal \
                 names no actor)",
                START_WITHIN_NS / 1_000_000_000,
            ),
        })
    }
}

/// The listed unit a journal record's `path` names (lowercase, no `.service`), if it is one of
/// [`SECURITY_SERVICES`]. A launchd label or Windows service never reaches here: the journal is
/// Linux, so only the listed names count and the label prefixes are not consulted.
fn listed_unit(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let name = lower.strip_suffix(".service").unwrap_or(&lower);
    SECURITY_SERVICES.contains(&name).then(|| name.to_owned())
}

/// What an exec does to listed units. A stop is read whatever the image (the exec rule alerts
/// on it); a start or restart is a claim that explains a stop, so it counts only when `trusted`
/// (see [`UnitStops::on_exec`]) and, for an init script, only from `/etc/init.d/`.
fn unit_touches(event: &ExecEvent, trusted: bool) -> Vec<(Touch, String)> {
    let mut touches: Vec<(Touch, String)> = services_stopped(event)
        .into_iter()
        .filter_map(|service| listed_unit(&service))
        .map(|unit| (Touch::Stop, unit))
        .collect();
    let program = program(event);
    let args = args(event);
    let image = event.image_path.to_ascii_lowercase();
    let named: Vec<(Touch, String)> = match program.as_str() {
        _ if !trusted && !image.starts_with("/etc/init.d/") => Vec::new(),
        "systemctl" if trusted => systemctl_starts(&args),
        "service" | "rc-service" | "invoke-rc.d" if trusted => init_script_starts(&args),
        "deb-systemd-invoke" if trusted => deb_systemd_invoke_starts(&args),
        _ if image.starts_with("/etc/init.d/") => args
            .first()
            .and_then(|verb| verb_touch(verb))
            .map(|touch| vec![(touch, program.clone())])
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    touches.extend(
        named
            .into_iter()
            .filter_map(|(touch, unit)| listed_unit(&unit).map(|unit| (touch, unit))),
    );
    touches
}

/// The touch a start-like verb makes; `None` for a verb that does not start anything.
fn verb_touch(verb: &str) -> Option<Touch> {
    match verb {
        "restart" | "try-restart" | "force-reload" | "condrestart" => Some(Touch::Restart),
        "start" | "reload-or-restart" | "try-reload-or-restart" => Some(Touch::Start),
        _ => None,
    }
}

/// Whether `systemctl`-style arguments act on a manager other than the host's system one:
/// `--user` (a user manager has no system unit), `--host`/`-H`, `--machine`/`-M` (another host or
/// a container). Such a call neither starts a local unit nor shuts the local host down.
fn targets_another_manager(args: &[String]) -> bool {
    args.iter().any(|a| {
        // A long option is read by prefix, as `systemctl_effect` reads it: `--us`, `--mach=c` and
        // `--ho=h` mean `--user`, `--machine` and `--host` (measured on systemd 258).
        if let Some(long) = a.strip_prefix("--").filter(|long| !long.is_empty()) {
            let name = long.split('=').next().unwrap_or(long);
            return matches!(
                resolve_long(SYSTEMCTL_LONG, name),
                Some(("user" | "host" | "machine" | "capsule", _))
            );
        }
        // `-H`/`-M`, lowercased by `recon::args` (`-h` is `--help`, which acts on nothing).
        a.starts_with("-h") || a.starts_with("-m")
    })
}

/// `systemctl start|restart|try-restart|reload-or-restart a b`, `systemctl enable --now a`.
fn systemctl_starts(args: &[String]) -> Vec<(Touch, String)> {
    if targets_another_manager(args) {
        return Vec::new();
    }
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    let Some(verb) = positional.next() else {
        return Vec::new();
    };
    let touch = if verb == "enable" && args.iter().any(|a| a == "--now") {
        Touch::Start
    } else if let Some(touch) = verb_touch(verb) {
        touch
    } else {
        return Vec::new();
    };
    positional.map(|unit| (touch, unit.clone())).collect()
}

/// `service X start|restart`, `rc-service X restart`, `invoke-rc.d X restart`.
fn init_script_starts(args: &[String]) -> Vec<(Touch, String)> {
    match args {
        [name, verb, ..] if !name.starts_with('-') => verb_touch(verb)
            .map(|touch| vec![(touch, name.clone())])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// `deb-systemd-invoke [--user] start|restart a b` (Debian maintainer scripts).
fn deb_systemd_invoke_starts(args: &[String]) -> Vec<(Touch, String)> {
    if targets_another_manager(args) {
        return Vec::new();
    }
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    let Some(touch) = positional.next().and_then(|verb| verb_touch(verb)) else {
        return Vec::new();
    };
    positional.map(|unit| (touch, unit.clone())).collect()
}

/// What an exec does to the host's shutdown state.
#[derive(Debug, PartialEq, Eq)]
enum Shutdown {
    /// The host is told to go down now: the units stop in the next minutes.
    Now,
    /// A scheduled shutdown is cancelled: the window it opened is closed.
    Cancel,
}

/// Whether `arg` names the long option `full` the way `getopt_long` resolves it: the exact name,
/// or any prefix of it at least `min` bytes long, with or without `=value`. The outer `Option`
/// says whether it matched; the inner one carries the `=value` where there was one.
///
/// systemd's tools parse with `getopt_long`, which accepts any **unambiguous** abbreviation, so
/// matching a long option by equality lets the same command through under a shorter spelling
/// (review of #1109). Measured on systemd 258: `reboot --w --help` and `systemctl --whe=+1h
/// --help` are both accepted, while `reboot --no-w` and `systemctl --wh` are refused as
/// ambiguous. `min` is that shortest unambiguous prefix for the tool in question, so a spelling
/// the tool itself rejects is not matched here either.
fn long_option<'a>(arg: &'a str, full: &str, min: usize) -> Option<Option<&'a str>> {
    let (name, value) = match arg.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (arg, None),
    };
    (name.len() >= min && full.starts_with(name)).then_some(value)
}

/// The long options `reboot`, `poweroff` and `halt` accept, each with the shortest prefix
/// `getopt_long` resolves for it (the floors for [`long_option`]), and whether it still leaves
/// the host going down. Measured on systemd 258 with `<tool> <option> --help` on Fedora 43: the
/// three tools share one parser, `--h`, `--n` and `--no-w` are ambiguous, and `--version`,
/// `--when`, `--message` and `--dry-run` do not exist for them.
const HALT_LONG_OPTIONS: [(&str, usize, bool); 9] = [
    ("--help", 4, false),
    ("--halt", 4, true),
    ("--poweroff", 3, true),
    ("--reboot", 3, true),
    ("--force", 3, true),
    ("--wtmp-only", 3, false),
    ("--no-wtmp", 7, true),
    ("--no-sync", 6, true),
    ("--no-wall", 7, true),
];

/// The short options the same parser accepts. `-w` is `--wtmp-only`; `-i` and `-h` are legacy
/// no-ops it still takes.
const HALT_SHORT_OPTIONS: &str = "nihpfdw";

/// Whether this argument of `reboot`/`poweroff`/`halt` leaves the host going down. Fail-closed:
/// only an option the tool really accepts, and that really acts, counts. Anything it refuses
/// (an ambiguous or unknown spelling, a value on an option that takes none) makes the command
/// exit with an error and the host stays up, and `--help` and `-w`/`--wtmp-only` print or write
/// wtmp and exit; none of those may explain a stop (review of #1109: `reboot --no-w` then
/// `stop` would cloak the stop for the whole window). Over-alerting on an odd spelling is the
/// safe error here.
fn halt_arg_lets_host_go_down(arg: &str) -> bool {
    if !arg.starts_with('-') || arg == "-" || arg == "--" {
        return true; // an operand or the end of the options, not an option
    }
    if arg.starts_with("--") {
        return HALT_LONG_OPTIONS
            .iter()
            .find_map(|&(full, min, acts)| {
                // `Some(None)`: matched with no `=value`; a value is an error for all of them.
                (long_option(arg, full, min) == Some(None)).then_some(acts)
            })
            .unwrap_or(false);
    }
    arg.chars()
        .skip(1)
        .all(|c| HALT_SHORT_OPTIONS.contains(c) && c != 'w')
}

/// What `getopt_long` makes of `--name` against `table`: the option whose name is exactly `name`,
/// else the only option `name` is a prefix of. `None` when it is unknown, or ambiguous between
/// several options, which the tool refuses with an error. Checked against the real tools: every
/// prefix of every option of `systemctl` and `shutdown` on systemd 258 (Fedora 43) was run with
/// `<tool> --PREFIX --help` and the verdicts are in `tests/data/systemd258_prefixes.txt`.
pub(crate) fn resolve_long(
    table: &[(&'static str, bool)],
    name: &str,
) -> Option<(&'static str, bool)> {
    if name.is_empty() {
        return None;
    }
    if let Some(&exact) = table.iter().find(|(full, _)| *full == name) {
        return Some(exact);
    }
    let mut candidates = table.iter().filter(|(full, _)| full.starts_with(name));
    match (candidates.next(), candidates.next()) {
        (Some(&only), None) => Some(only),
        _ => None,
    }
}

/// An option the tool read, in the order it read it.
#[derive(Debug, PartialEq, Eq)]
enum Opt<'a> {
    /// A long option by its full name (an abbreviation is already resolved), and its value.
    Long(&'static str, Option<&'a str>),
    /// A short option, and its value where it takes one.
    Short(char, Option<&'a str>),
}

/// Reads `args` the way `getopt_long` does for the systemd tools, which permute: an option is an
/// option wherever it stands, so the operands (the verb, the time, the wall message) are what is
/// left, and only a bare `--` ends the options. `flags` are the short options without a value,
/// `valued` those with one (`-tservice` and `-t service` both work). `None` when the tool would
/// refuse the command line and exit with an error, so the host stays up: an unknown or ambiguous
/// long option, a value given to an option that takes none, a missing value, an unknown letter.
/// Values are not checked beyond that: an invalid one is another refusal this does not see.
fn parse_options<'a>(
    args: &'a [String],
    long: &[(&'static str, bool)],
    flags: &str,
    valued: &str,
) -> Option<(Vec<Opt<'a>>, Vec<&'a str>)> {
    let mut options = Vec::new();
    let mut operands = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        i += 1;
        if arg == "--" {
            operands.extend(args[i..].iter().map(String::as_str));
            break;
        }
        if let Some(body) = arg.strip_prefix("--") {
            let (name, value) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (body, None),
            };
            let (full, takes_value) = resolve_long(long, name)?;
            let value = match (takes_value, value) {
                (false, None) => None,
                (false, Some(_)) => return None,
                (true, Some(value)) => Some(value),
                (true, None) => {
                    let next = args.get(i)?.as_str();
                    i += 1;
                    Some(next)
                }
            };
            options.push(Opt::Long(full, value));
        } else if arg.len() > 1 && arg.starts_with('-') {
            for (at, letter) in arg.char_indices().skip(1) {
                if flags.contains(letter) {
                    options.push(Opt::Short(letter, None));
                } else if valued.contains(letter) {
                    let rest = &arg[at + letter.len_utf8()..];
                    let value = if rest.is_empty() {
                        let next = args.get(i)?.as_str();
                        i += 1;
                        next
                    } else {
                        rest
                    };
                    options.push(Opt::Short(letter, Some(value)));
                    break;
                } else {
                    return None;
                }
            }
        } else {
            operands.push(arg);
        }
    }
    Some((options, operands))
}

/// `systemctl`'s long options and whether each takes a value: the `options[]` table of
/// `src/systemctl/systemctl.c` at systemd v258, in source order.
pub(crate) const SYSTEMCTL_LONG: &[(&str, bool)] = &[
    ("help", false),
    ("version", false),
    ("type", true),
    ("property", true),
    ("all", false),
    ("reverse", false),
    ("after", false),
    ("before", false),
    ("show-types", false),
    ("failed", false),
    ("full", false),
    ("job-mode", true),
    ("fail", false),
    ("irreversible", false),
    ("ignore-dependencies", false),
    ("ignore-inhibitors", false),
    ("check-inhibitors", true),
    ("value", false),
    ("user", false),
    ("system", false),
    ("global", false),
    ("capsule", true),
    ("wait", false),
    ("no-block", false),
    ("legend", true),
    ("no-legend", false),
    ("no-pager", false),
    ("no-wall", false),
    ("dry-run", false),
    ("quiet", false),
    ("verbose", false),
    ("no-warn", false),
    ("root", true),
    ("image", true),
    ("image-policy", true),
    ("force", false),
    ("no-reload", false),
    ("kill-whom", true),
    ("kill-value", true),
    ("signal", true),
    ("no-ask-password", false),
    ("host", true),
    ("machine", true),
    ("runtime", false),
    ("lines", true),
    ("output", true),
    ("plain", false),
    ("state", true),
    ("recursive", false),
    ("with-dependencies", false),
    ("preset-mode", true),
    ("firmware-setup", false),
    ("boot-loader-menu", true),
    ("boot-loader-entry", true),
    ("now", false),
    ("message", true),
    ("show-transaction", false),
    ("what", true),
    ("reboot-argument", true),
    ("timestamp", true),
    ("read-only", false),
    ("mkdir", false),
    ("marked", false),
    ("drop-in", true),
    ("when", true),
    ("stdin", false),
    ("kill-subgroup", true),
];

/// `shutdown`'s long options (`src/systemctl/systemctl-compat-shutdown.c`, v258). None takes a value.
pub(crate) const SHUTDOWN_LONG: &[(&str, bool)] = &[
    ("help", false),
    ("halt", false),
    ("poweroff", false),
    ("reboot", false),
    ("kexec", false),
    ("no-wall", false),
    ("show", false),
];

/// The arguments after the program, exactly as given. `recon::args` lowercases them, which is
/// wrong for tools whose short options are case-sensitive: `-h` is help and `-H` a host for
/// `systemctl`, `-K` is kexec and `-k` a dry run for `shutdown`, and `reboot -H` or `reboot
/// --FORCE`, which the tool refuses, would read as the accepted `-h` and `--force`.
fn raw_args(event: &ExecEvent) -> Vec<String> {
    if event.argv.is_empty() {
        event
            .cmdline
            .split_whitespace()
            .skip(1)
            .map(str::to_owned)
            .collect()
    } else {
        event.argv.iter().skip(1).cloned().collect()
    }
}

/// What a `shutdown` command line does, read the way the tool reads it (`getopt_long`, options
/// anywhere): the **last** of `-H -P -r -K -h` / `-c` / `--show` decides the action (`-c -r +5`
/// schedules a reboot, `-r -c` cancels), `-k` only warns, `--help` and `--show` print, and a
/// spelling the tool refuses does nothing. Otherwise the first operand is the time and only
/// `now` / `+0` is immediate: `+N` and `HH:MM` schedule, a bare `shutdown` is `+1`.
///
/// Measured on systemd 258 (Fedora 43): `shutdown +120 -c` cancels the schedule it follows, and
/// `shutdown +120 labtest -r` schedules a reboot, so an option after the time is an option and
/// not part of the wall message; `shutdown --help now` prints; `shutdown --cancel` is refused
/// (`-c` has no long form).
fn shutdown_command_effect(args: &[String]) -> Option<Shutdown> {
    #[derive(PartialEq)]
    enum Action {
        Shut,
        Cancel,
        Show,
    }
    let (options, operands) = parse_options(args, SHUTDOWN_LONG, "HPrhkKafFc", "t")?;
    let mut action = Action::Shut;
    let mut dry_run = false;
    for option in options {
        match option {
            Opt::Long("help", _) => return None,
            Opt::Long("show", _) => action = Action::Show,
            Opt::Long("halt" | "poweroff" | "reboot" | "kexec", _) => action = Action::Shut,
            Opt::Long(..) => {}
            Opt::Short('c', _) => action = Action::Cancel,
            Opt::Short('k', _) => dry_run = true,
            Opt::Short('H' | 'P' | 'r' | 'K' | 'h', _) => action = Action::Shut,
            Opt::Short(..) => {}
        }
    }
    match action {
        Action::Cancel => return Some(Shutdown::Cancel),
        Action::Show => return None,
        Action::Shut if dry_run => return None,
        Action::Shut => {}
    }
    let time = operands.first()?;
    (*time == "now" || *time == "+0").then_some(Shutdown::Now)
}

/// What a `systemctl` command line does to the host's shutdown state, read the way the tool
/// reads it. The verb is the first operand, wherever the options stand around it. `--help`,
/// `--version` and `--dry-run` print and exit, and a spelling the tool refuses does nothing
/// (measured on systemd 258: `systemctl reboot --dry-run` exits 0 and the host stays up,
/// `systemctl reboot --bogus` and `--no-wall=1` exit 1). `--when=` schedules, or cancels with
/// `--when=cancel`; the last one given counts.
fn systemctl_effect(args: &[String]) -> Option<Shutdown> {
    let (options, operands) = parse_options(args, SYSTEMCTL_LONG, "halqvfiTr", "CtpPsHMno")?;
    let mut when = None;
    for option in &options {
        match option {
            Opt::Short('h', _) | Opt::Long("help" | "version" | "dry-run", _) => return None,
            // Another manager (a user manager, another host, a container, a capsule): the local
            // host does not go down.
            Opt::Short('H' | 'M' | 'C', _)
            | Opt::Long("user" | "host" | "machine" | "capsule", _) => return None,
            Opt::Long("when", value) => when = *value,
            _ => {}
        }
    }
    if !matches!(
        operands.first().copied(),
        Some("reboot" | "poweroff" | "halt" | "kexec" | "soft-reboot")
    ) {
        return None;
    }
    match when {
        None => Some(Shutdown::Now),
        Some("cancel") => Some(Shutdown::Cancel),
        Some(_) => None,
    }
}

/// Whether this exec tells the host to shut down or reboot **now** (`Now`), or cancels one
/// (`Cancel`). `shutdown` and `systemctl` are read by [`shutdown_command_effect`] and
/// [`systemctl_effect`]. `reboot`, `poweroff`, `halt` and `init`/`telinit 0|6` are immediate.
/// `reboot`/`poweroff`/`halt` are fail-closed ([`halt_arg_lets_host_go_down`]): a
/// `-w`/`--wtmp-only` (writes the wtmp record, host stays up), `--help`, or any spelling the
/// tool refuses would otherwise cloak any stop in the next five minutes without bringing the
/// host down. `-d`/`--no-wtmp` and `-f`/`--force` do bring the host down.
///
/// Long options are matched by abbreviation, since `getopt_long` accepts one: `reboot --w` and
/// `systemctl reboot --whe=+1h` mean the same as the full spellings, and matching only the full
/// ones left each cloak open under a shorter name.
fn shutdown_effect(event: &ExecEvent) -> Option<Shutdown> {
    let program = program(event);
    let args = raw_args(event);
    match program.as_str() {
        "reboot" | "poweroff" | "halt" => args
            .iter()
            .all(|a| halt_arg_lets_host_go_down(a))
            .then_some(Shutdown::Now),
        "shutdown" => shutdown_command_effect(&args),
        "systemctl" => systemctl_effect(&args),
        "init" | "telinit" => args
            .first()
            .is_some_and(|level| level == "0" || level == "6")
            .then_some(Shutdown::Now),
        _ => None,
    }
}
