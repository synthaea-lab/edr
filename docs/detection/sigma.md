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

## Which rules a host loads

Content is organised by platform: `rules/sigma/linux/`, `windows/` and `macos/`. The agent loads
**only the directory of the platform it is built for** (`SigmaEngine::load_dir_for(dir, platform)`,
with `Platform::host()`), so a rule written for another platform never runs on the host. The
platform is where the directory sits **under the rules directory**: only `<dir>/<platform>/` is
walked, and a content root such as `/home/linux/content/rules/sigma` does not turn
`windows/x.yml` into a Linux rule. A platform directory that does not exist gives an engine with no
rules, and a rule outside a platform directory is loaded for no platform. `SigmaEngine::load_dir`
is unchanged and loads every platform: the content tests and tooling use it. Rules meant for
several platforms (a shared directory, or a `platform` list in the YAML) are not supported yet.

`load_rule` and `load_dir` still decide that a rule is under a known platform directory by looking
for `/linux/`, `/windows/` or `/macos/` in the **full path**, so a rule in an unknown directory
beneath a content root that has such a word in its path is accepted by them. The agent's loader does
not depend on that check.

