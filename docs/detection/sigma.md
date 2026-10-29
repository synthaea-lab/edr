# Sigma

Sigma rule support: supported constructs, compilation to the internal representation,
field mapping per platform.

Field value lists use implicit OR by default. Append `|all` after one matching
modifier to require every listed value to match, for example
`CommandLine|contains|all`. Supported combinations are `contains|all`,
`startswith|all`, and `endswith|all`; `all` must be last. An empty value list is
rejected for every field, not only with `|all`: `Image: []` and
`CommandLine|contains: []` loaded before and never matched, and now fail at load time
(`SigmaEngine::load_dir` skips the rule with a warning; `load_rule` returns the error).
A field and modifier specification duplicated with different casing
(such as `Image|endswith` and `image|EndsWith`) is rejected because evaluation
ANDs fields and would otherwise make the rule's meaning unclear.

## Log source (#719)

Every supported field is read from an `ExecEvent`, so every rule is evaluated against process
creations. `logsource` is read so that a rule written for other telemetry is refused at load
instead of being evaluated against the wrong events:

| `logsource` | Result |
|---|---|
| absent | `process_creation` (every rule shipped in `rules/sigma/` omits it) |
| `category: process_creation` | loads |
| `product: <p>` | loads only if `<p>` is the rule's platform directory (`windows`, `linux`, `macos`) |
| any other `category` (`network_connection`, `image_load`, ...) | refused, naming the category |
| a `service` (`security`, `sysmon`, `auditd`, ...) | refused: log channels are not mapped |
| no `category` | refused |

Matching is case-insensitive; other keys (`definition`) are ignored. So an upstream SigmaHQ
`process_creation` rule loads unchanged from the directory of its `product`. A macOS host also
runs `linux/` (see below), so a `product: linux` rule runs there too, as every `linux/` rule
already does.

## Fields

Supported today, on an `ExecEvent`: `Image`, `CommandLine`, `ParentImage`, and the PE
version-resource strings `OriginalFileName` (#983), `Company`, `Description` and `Product` (#719;
`company_name`, `file_description` and `product_name`, read by #983 in the same pass).
Everything else (`ParentCommandLine`, `Hashes`, `IntegrityLevel`, `User`, `CurrentDirectory`,
the fields of other categories) is refused at load, naming the field.

The PE version-resource strings come from `enrich::pe_info`, read once per enrichment cache miss
alongside the hash and signature: a Windows/PE concept with no Mach-O or ELF equivalent. A rule
using one is refused at load unless it is under the `windows/` platform directory — using it from
`linux/` or `macos/` would otherwise load fine and never match on the platforms that actually run
it (the exact silent-death failure mode this validator exists to kill). The platform directory is
the same one the loader decides by (the first directory under the rules root, or for
`load_rule` the innermost `linux`/`windows`/`macos` directory of the path), so a `windows` word in
the content root's own path does not let a Linux rule use one. A *particular* Windows event can
still lack the value (no version resource, a parse failure, an image over the enrichment size
budget) without the rule being refused — same posture as `ParentImage` when the sensor has no
lineage: the field is absent for that one event, not unsupported for the platform.

## Conditions (#978)

A rule's `condition` is a boolean expression over the named blocks of its `detection`. There is
no special `selection`: any block name works, and a rule may have several selections and filters.

| Form | Meaning |
|---|---|
| `name` | the block `name` matches |
| `not x` | `x` does not hold |
| `x and y` | both |
| `x or y` | either |
| `( x )` | grouping |
| `1 of prefix*` | at least one block whose name starts with `prefix` matches |
| `all of prefix*` | every block whose name starts with `prefix` matches |
| `1 of them` / `all of them` | the same over every block of the `detection` (filters included, as in Sigma) |
| `1 of name` / `all of name` | the one block named `name` |

Precedence is `not`, then `and`, then `or`. Keywords are case-insensitive, block names are not.
Typical rules: `selection and not 1 of filter_*`, `all of selection_*`, `1 of selection_* and not
filter`.

**Checked at load time, never at evaluation:**
- every block the condition refers to must exist, and a pattern (`1 of X*`, `all of X*`) that
  matches **no** block is a load error, not an empty match (which would be vacuously true or
  never true);
- every referenced block is validated as strictly as `selection` always was (supported fields and
  modifiers, no empty block, no interior wildcard); an unsupported field in a filter refuses the
  rule and names the block. A block the condition never refers to is not evaluated and not
  validated, as before.

**Refused at load, by name:** aggregations (`count()`, `min()`, `max()`, `avg()`, `sum()`,
`near`, any `|` pipe), `timeframe`, `N of` for N other than 1, `any of`, a `*` anywhere but at the
end of a pattern, a `*` pattern outside `1 of` / `all of`, a keyword where a block name belongs,
unbalanced parentheses, an empty condition, and any character that is not part of a block name.

**Bounds:** at most 1024 bytes, 128 tokens, 8 levels of nesting (parentheses and `not` together)
and 64 distinct referenced blocks per condition; the parser's recursion is capped by the nesting
bound. Evaluation short-circuits and evaluates each block at most once per event (a fixed array
on the stack), and lowercases each event field at most once however many blocks read it.

Not in this change: fields the event does not carry (see "Fields" above), and the `windash` /
`re` / `base64offset` / `fieldref` modifiers. A selection written as a list of maps (an OR of field
maps) has been supported since #982.

## Which rules a host loads

Content is organised by platform: `rules/sigma/linux/`, `windows/` and `macos/`. The agent loads
**only the directories its platform runs** (`SigmaEngine::load_dir_for(dir, platform)`, with
`Platform::host()` and `Platform::rule_dirs()`), so a rule written for another platform never runs
on the host:

| Host | Loads |
| --- | --- |
| Linux | `linux/` |
| Windows | `windows/` |
| macOS | `macos/` **and `linux/`** |

**macOS also runs the rules of `linux/`.** They are Unix-family command-line rules (shells,
`curl`, `base64`) that apply to macOS, and macOS hosts have run them since the agent loaded the
whole tree; a strict per-platform loader would have dropped them. This is a **choice, open to
challenge, not a final rule**: a shared `unix/` directory loaded by both is the alternative, and
one test (`crates/sigma/tests/platform.rs`, `EXPECTED`) pins the set, so changing it is visible.
The macOS rules do not run on Linux any more: `macos/web_server_spawned_shell` no longer fires
beside the Rust service-lineage rule (T1059) on a Linux host.

The platform is where a directory sits **under the rules directory**: only `<dir>/<d>/` for each
loaded directory is walked, and a content root such as `/home/linux/content/rules/sigma` does not
turn `windows/x.yml` into a Linux rule. A directory that does not exist contributes no rules, and a
rule outside a platform directory is loaded for no platform. `SigmaEngine::load_dir` is unchanged and
loads every platform: the content tests and tooling use it.

`load_dir` and `load_dir_for` check that a rule is under a known platform directory on its path
**relative to the rules directory** they were given (the first directory must be `linux`, `windows`
or `macos`), so a word in the content root's own path decides nothing. `load_rule` alone has no
root to measure from and takes the innermost `/linux/`, `/windows/` or `/macos/` of the whole path it
is given.
