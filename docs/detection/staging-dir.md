# Staging directory (STAGING-DIR, #380)

One rule over the file-open stream: `RuleState::check_staging_dir` (`crates/rules/src/state.rs`),
with the path knowledge in `crates/rules/src/staging.rs` and the constants in
`crates/rules/src/exclusions.rs`. It is the T1074.001 (local data staging) row of the Collection
and Exfiltration pack (#380) and needs no new telemetry. It is the stage before ARCHIVE-EXFIL
and EGRESS-VOLUME: data gathered in one place, ready to be packed and sent.

## The shape

One pid, inside ten minutes:

1. opens at least **100 distinct user-data files** for reading, from at least **10 directories**;
2. creates at least **50 distinct files** (`O_CREAT`) in **one staging directory**.

Medium, one alert per (pid, directory) per window. The message carries the pid, the process name,
the counts and the directory, never a file name from the sweep.

| Term | Means |
| --- | --- |
| user-data file | a path inside a profile (`/home/<u>`, `/Users/<u>`, `/root`, `C:\Users\<u>`), with no hidden component (`~/.config`, `.ssh`, dotfiles) and not under `AppData` |
| staging directory | the directory of a created file when it is a **subdirectory** of a temp root (`/tmp`, `/var/tmp`, `/dev/shm`, `/private/tmp`, `C:\Windows\Temp`, `%LOCALAPPDATA%\Temp`) or a **hidden** directory (`/tmp/.x`, `~/.stash`) |
| excluded | `.git`, `.cache`, `.trash` anywhere in the directory path (a `git add` writes thousands of objects; a cache is a cache) |

A file created straight in `/tmp` is not "one directory": every program does that. A `tmp/` inside
a project is that project's own build directory, so temp roots are matched from the filesystem
root (or the profile), not at any depth. Relative paths (the Linux `dfd` limitation) are skipped,
not guessed.

## Why the creating open and not the bytes

`FileWriteEvent` carries no path (only pid, fd, size), so the rule counts the opens that create
files, not the bytes written to them. Reads are `FileOpenEvent`s without write intent. The
evaluation runs on a create: a copy loop that interleaves reads and creates qualifies; a sweep
that reads everything and then creates fewer than 50 files does not.

## Provisional

All four numbers (100 files, 10 directories, 50 creates, 10 minutes) are **provisional**: there is
no lab capture of an ordinary copy, build or backup to calibrate against. They sit above what a
person does by hand (copying a folder of a few dozen files) and below a sweep. The distinct-path
counters hold 256 values, so no threshold may exceed that. State is bounded: 256 pids for the reads
and 256 for the directories, with counted eviction (about ten MB at the worst); a pid pushed out
by 256 busier ones loses its history, not its detection of the next burst.

## False positives to expect

`cp -r` or `rsync` of a user folder into `/tmp/x`, a backup tool, an indexer that spools into a
hidden directory, a build that reads sources from a home directory and writes objects into a temp
subdirectory (the 10-directory floor is what keeps a single source tree out). None is excluded,
because each is also what an attacker runs and no evidence-gated exclusion exists yet.

## Stated gaps

- **Same pid only.** `tar | gzip` style pipelines, or a collector that hands files to a writer
  process, spread the two halves over pids.
- **Staging in `~/.cache`** is excluded to keep caches quiet, and is a place an attacker can use.
  So is a macOS per-user temp directory (`/var/folders/.../T/`), not in the temp roots.
- **Reuse of an existing file** (open without `O_CREAT`) is not a new staged file.
- A reused pid is told apart by process generation; a sensor that stamps none cannot tell.
- Not run: the lab, a live capture, `cargo mutants`. Mutation-checked by hand (see the PR).
