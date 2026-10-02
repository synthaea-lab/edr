# Download provenance on Windows

How the agent ties an executed file back to a download, and where that link
breaks. On Windows, the mark-of-the-web (a `Zone.Identifier` alternate data
stream) is the platform's own provenance record. Only some writers set it, so
a second set of rules covers the tools that don't.

## The mark-of-the-web path

Browsers, mail clients, Office and Explorer (when it extracts a marked ZIP)
write a `Zone.Identifier` stream next to the file. The ETW sensor sees the
stream being written, reads it back, and reports a `FileQuarantine` event
carrying the `HostUrl`/`ReferrerUrl` (#365; credentials redacted per
ADR-0018). Two rules consume it:

| Rule | Fires when | Technique |
| --- | --- | --- |
| `check_quarantined_exec` | a marked file is executed within 10 min of the mark (`QUARANTINE_EXEC_WINDOW_NS`) | T1204.002 |
| `check_exec_after_motw_removal` | a file is executed within the same window after its mark was **removed**: `Unblock-File`, `Remove-Item -Stream Zone.Identifier`, Explorer's "Unblock" checkbox (#442) | T1553.005 |

Removing a mark doesn't alert on its own. `Unblock-File` over a downloaded
PowerShell module tree removes hundreds of marks legitimately. The removal is
still in the telemetry, as a `FileDelete` of the `…:Zone.Identifier` stream
path (Kernel-File event 26, `DeletePath`), so it can be hunted and matched by
Sigma.

## Downloaders that write no mark

None of these write a `Zone.Identifier`, so neither rule above ever sees their
downloads:

| Downloader | What covers it | Gap |
| --- | --- | --- |
| `curl.exe`, `wget.exe` | T1105 download→exec join (`check_download_then_exec`, `DOWNLOADER_COMMS`): the written path is executed within the window (#487) | a file renamed or copied before running doesn't join |
| `certutil.exe -urlcache -f` | same T1105 join (`certutil.exe` is in `DOWNLOADER_COMMS`); T1204/T1059 when an Office/PDF parent spawns it (`SUSPECT_CHILDREN_WIN`) | same as above |
| `bitsadmin` / BITS jobs | T1204/T1059 when an Office/PDF parent spawns `bitsadmin.exe`; nothing on the download itself | the BITS service (`svchost.exe`), not `bitsadmin.exe`, writes the file; BITS-Client telemetry is #284 |
| PowerShell `Invoke-WebRequest`, `Net.WebClient` | correlator T1105 (`rule_connect_filewrite`): one pid connects and writes an executable or a file under a temp/Downloads path in the same window | `powershell.exe` writes too many files to join on its writes, so it isn't in `DOWNLOADER_COMMS` |
| custom droppers | correlator T1105, and its full chain (spawn + connect + payload write, `rule_spawn_connect_filewrite`) | a dropper writing a non-executable name outside temp/Downloads |

## What this userland path can't see

- **Archive extractors that don't propagate the mark.** Nothing is removed,
  because nothing was ever written on the extracted file, so there is no
  event to join.
- **A mark stripped by rewriting the file** (a copy to a new file, or a tool
  that writes the data to a fresh name) instead of deleting the stream.
- **Raw-volume or driver-level stream tampering.**

The minifilter (#136) supersedes this path: it sees stream deletes, renames
and overwrites at the file-system level, whichever API issued them.
