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

Not in this change: `OriginalFileName` and other fields the event does not carry, field mapping
and `logsource` (#719), the `windash` / `re` / `base64offset` / `fieldref` modifiers, and a
selection written as a list of maps (an OR of field maps), which the loader still refuses with a
YAML error.

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

`load_rule` and `load_dir` still decide that a rule is under a known platform directory by looking
for `/linux/`, `/windows/` or `/macos/` in the **full path**, so a rule in an unknown directory
beneath a content root that has such a word in its path is accepted by them. The agent's loader does
not depend on that check. To fix after the condition-grammar work (#979) that also edits `validate.rs`:
pass the rules root to `validate` and check the relative path.
