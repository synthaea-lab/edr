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
