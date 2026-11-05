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
follows its own rules, below. Best-effort matching may also
redact benign values following a recognized secret option. The tool is chosen
from the image's basename alone (no path, hash, or signature check); the
recognized general wrappers (sudo/doas/nohup, env, timeout, nice, `cmd`, a shell
or PowerShell `-Command` string) are followed so the real command underneath is
still matched, but a tool invoked under a name this module does not recognize
(a renamed binary, an unlisted wrapper, an interpreter calling a library
function instead of spawning a new process image) is not. This is a known gap
of basename matching generally, not specific to any one shape (#843 review).

## Command text outside `Exec` (#895)

Four other events carry text a person or a script wrote: a typed shell line
(`ReadlineInput.input`), a PowerShell script block (`ScriptBlock.text`), an AMSI buffer
(`AmsiContent.text`), and a WQL query (`WmiActivity.query`). They follow the same
boundary as `Exec`. Detection reads them raw: the live `RedactingSink` leaves them alone
exactly as it leaves `Exec`. Every copy that leaves the process is redacted: `events.jsonl`,
the event spool, detection evidence, and the capture commands. The schema does not change.

`redact::redact_command_text(text, dialect)` cuts the text into statements at unquoted
separators and grouping characters (newlines, `;`, `|`, `&`, parentheses, braces, and the
POSIX backtick). It then redacts each statement as a command line of its own first word,
so `cd x && mysql -pS3cret` and a `net use … S3cret` inside a script block are both read.
Each field has its own dialect:

| Field | Dialect | Also redacted |
|---|---|---|
| `ReadlineInput.input` | POSIX | secret-named `NAME=value` assignments before a command or after `export`/`declare`/`local`/`readonly`/`typeset` (`*_FILE` names kept) |
| `ScriptBlock.text` | PowerShell | secret-named `-Parameter value` / `-Parameter:value`; the plain text given to `ConvertTo-SecureString`; quoted `$name = '…'` assignments to a secret-named variable (scope such as `env:` ignored); a leading `&` or `.` call operator is skipped so the program it calls is read |
| `AmsiContent.text` | PowerShell when `app_name` starts with `PowerShell`, otherwise opaque | `content_name` loses URL credentials |
| `WmiActivity.query` | opaque | — |

Opaque text (VBScript, JScript, VBA, .NET, WQL) is not parsed. It only loses the shapes
that do not depend on a tool: URL credentials, secret headers, and secret-named
`--option=value` pairs. A PowerShell value computed at run time is kept, because it holds
no literal and it tells an analyst where the secret came from: a variable (`$cred`), a
subexpression (`(Read-Host)`), a splat (`@args`), or a type. `ScriptBlock.path`,
`AmsiContent.app_name`, and the WMI `namespace`/`method` are names, not command text, and
are kept.

The AMSI rule quotes an excerpt of the raw buffer in its message. The agent swaps that
excerpt for the excerpt of the redacted buffer (`rules::amsi_excerpt`) before the message
reaches the alert log, the verdict, or the spool, as it already does for an `Exec` command
line.

A redacted value keeps its quote and escape characters, so a second pass cuts the text at
the same places. On hostile quoting the statement cut and the command-line tokenizer can
still disagree. `redact_command_text` therefore runs to a fixed point, at most sixteen
passes. Text with no secret costs one pass.

Limits, on top of the command-line ones above:
- A script block that ETW splits into fragments is redacted per fragment, so a secret cut
  across two fragments is not recognized.
- A shell string inside a typed line (`bash -c "a; mysql -p…"`) is still read as one
  command.
- PowerShell here-strings, `-EncodedCommand`, string concatenation, and secrets held in
  variables are not decoded.
- AMSI text cut at the sensor's limit may end in the middle of a secret.

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
