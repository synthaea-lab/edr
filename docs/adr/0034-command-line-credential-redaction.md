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
the verdict, alert log, recent-detection view, and detection spool; baseline and
raw event capture redact before serializing their local output. Every event copy
written by an agent command, including `capture-*`, crosses the same redaction
sink. Live run pipelines retain raw Exec events until detection has evaluated
them. No command-line hash is currently emitted. The existing SHA-256 is an
image-file hash, not a command-line hash, and remains unchanged. ML features may be computed from the
raw in-memory event, but their vectors are not persisted by the agent; future
training from baseline data must derive features from the redacted corpus and
runtime scoring must use the same redacted canonical input to avoid drift.

Replacement is the literal `REDACTED`. Recognized option names and quoting are
preserved; only the value is replaced. `argv` retains its number and order of
arguments. Matching is case-insensitive on the image basename, with `.exe`
removed. Supported shapes include URL userinfo and secret-named query values,
secret-key long options, common credential options for curl/wget, database and
directory tools, selected Windows password flags, `net`/`net1` passwords, and
secret headers. curl form-body values are filtered by key; ordinary fields remain.
Recognized wrappers include sudo/doas/nohup, env, timeout, nice, cmd, and one
shell or PowerShell `-Command` string. An unbalanced quote falls back to
whitespace tokenization from that token. Bearer credentials are redacted only
inside an authorization header. Tokenization follows Windows
`CommandLineToArgvW` quote rules for `.exe` images and POSIX-like rules otherwise.

## Known limits

This is best-effort text parsing, not a shell interpreter. General wrappers are
followed for at most eight layers. Shell and PowerShell command strings are
inspected one level deep; nested shell strings beyond that are not guaranteed.
Ambiguous `foo --password --verbose S3cret` keeps
`--verbose` and cannot safely identify the later positional value. Environment
variable values and secrets in files, stdin, PowerShell `-EncodedCommand`, shell
expansions, aliases, caret escapes, and unknown tool-specific options are not
decoded. Unknown positional values are kept except for documented `net` forms.
Command text in `ReadlineInput`, `ScriptBlock`, `AmsiContent`, and `WmiActivity`
is outside this ADR and needs a separate design. Best-effort matching may also
redact benign values following a recognized secret option.

## Consequences

Detection retains the raw command line in memory and still sees secret-bearing
indicators. Persisted event, alert, and baseline output loses the recognized
secret values, while rule labels and argument structure remain useful. The
baseline corpus is intentionally redacted even though it is used for training;
feature generation must follow the same redacted input convention. This lowers
the risk of a raw command-line hash becoming a fleet-wide dictionary oracle and
prevents baseline files from becoming credential stores.

Tests pin the supported quoting, URL, authorization, wrapper, and option forms;
the listed unsupported forms remain out of scope. There is no policy opt-out:
unconditional output redaction is required because the runtime policy is not yet
delivered to the agent. Detection rules
must continue to consume the raw event; redaction must not be moved into rules
or sensors.
