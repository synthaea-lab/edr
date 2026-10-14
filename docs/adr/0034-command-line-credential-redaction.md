# ADR-0034: Command-line credential redaction

- **Status**: proposed
- **Date**: 2026-10-14

## Context

`ExecEvent.cmdline` and `argv` can contain credentials supplied to command-line
tools. Events are consumed by deterministic rules, Sigma, correlation, and the
ML feature code; the same fields can later reach the event spool, `events.jsonl`,
uploaded detections, alert output, and the baseline capture. Redacting the event
at sensor ingress would silently disable detections that inspect the original
command line. This is the command-line extension of ADR-0018's unconditional
output redaction, not a change to the `ExecEvent` schema.

## Decision

Keep the in-memory event raw through rules, Sigma, and correlation. A pure helper
redacts recognized command-line credential shapes on copies at output boundaries.
The enrichment worker redacts event copies before the spool and `events.jsonl`;
detection construction redacts its title/message and evidence event copies before
the verdict, alert log, recent-detection view, and detection spool; baseline
capture redacts before serializing its local training corpus. No command-line
hash is currently emitted. The existing SHA-256 is an image-file hash, not a
command-line hash, and remains unchanged. ML features may be computed from the
raw in-memory event, but their vectors are not persisted by the agent; future
training from baseline data must derive features from the redacted corpus and
runtime scoring must use the same redacted canonical input to avoid drift.

Replacement is the literal `REDACTED`. Recognized option names and quoting are
preserved; only the value is replaced. `argv` retains its number and order of
arguments. Matching is case-insensitive on the image basename, with `.exe`
removed. Supported shapes include URL userinfo and secret-named query values;
curl/wget user credentials; common long password/token/secret/API-key flags;
tool-scoped short password flags; sqlcmd/bcp `-P`; selected Windows `/p`,
`/password`, `/pass`, `/rp` forms; `net use` and `net user` positional passwords;
and Authorization, Proxy-Authorization, and X-Api-Key headers. Bearer credentials
are redacted only inside an authorization header; the word `bearer` elsewhere is
not a credential signal. A Unicode whitespace character after the authorization
scheme separates it from the value and is advanced by its UTF-8 width. `mysql`,
`mariadb`, and `mysqldump` redact attached `-pSECRET` and `--password=SECRET`;
spaced `-p` or `--password` means prompt and leaves the following database/option
untouched. The spaced `-p VALUE`
form is enabled only for PsExec and sshpass. Short and Windows flags are scoped
to known tools to avoid masking unrelated switches. Tokenization follows
Windows `CommandLineToArgvW` quote rules when the image is an `.exe` or Windows
path, and POSIX shell-like quote rules otherwise; this is not a full shell parser.

## Consequences

Detection retains the raw command line in memory and still sees secret-bearing
indicators. Persisted event, alert, and baseline output loses the recognized
secret values, while rule labels and argument structure remain useful. The
baseline corpus is intentionally redacted even though it is used for training;
feature generation must follow the same redacted input convention. This lowers
the risk of a raw command-line hash becoming a fleet-wide dictionary oracle and
prevents baseline files from becoming credential stores.

This is best-effort text parsing, not a shell interpreter. It can miss secrets
in environment variables, files or stdin, PowerShell `-EncodedCommand`, unknown
tool-specific flags, arbitrary positional arguments outside the documented
`net` forms, bearer-like values outside recognized authorization headers, and
Windows caret escapes. It can also redact a benign value when it follows a
recognized secret flag. Tests pin the supported quoting, URL, authorization, and
option forms; the listed unsupported forms remain out of scope. There is no policy opt-out: unconditional output redaction is required
because the runtime policy is not yet delivered to the agent. Detection rules
must continue to consume the raw event; redaction must not be moved into rules
or sensors.
