# Detection as Code

Detection content is software: versioned, reviewed, tested, and deployed like it.
Most of the pipeline already exists — this documents the contract and names the gaps.

## Already enforced
- **Versioned + reviewed**: all content lives in `rules/` (Sigma, YARA), changed only
  by PR.
- **Tested in CI**: the content workflow runs each engine's suite — every shipped
  rule must load/compile (hard failure naming the file) AND fire on a crafted
  matching sample, one per rule. Dead content cannot merge (this caught a rule that
  had been silently dead in the old iteration).
- **Loud engine validation**: unsupported constructs are rejected at load with the
  construct named, never silently skipped.

- **Rule metadata schema (#73)**: a Sigma rule is rejected at load unless it has a
  `level` (severity), at least one ATT&CK technique tag (`attack.t1059.004`), non-empty
  `falsepositives`, and sits under a known platform directory (`rules/sigma/{linux,
  windows,macos}/`): `crates/sigma/src/validate.rs`. A YARA rule must carry
  `severity`, `technique` and `falsepositives` in its `meta:` block
  (`crates/yara`, `extract_metadata`).
- **Per-rule matching and negative samples (#73)**: every shipped rule has exactly one
  crafted event that must fire it and one benign lookalike that must not
  (`crates/sigma/tests/content.rs`, `crates/yara/tests/content.rs`). For Sigma the samples
  are `<rule>.samples.json` beside the rule (ADR-0031) and the suite asserts every rule has
  its file and every file its rule; the YARA suite still asserts that sample titles equal
  the loaded rule titles. Either way a rule added, renamed or removed without its samples
  fails CI.

## Still to build
- **Ring deployment**: content ships via canary rings (`updater`/policy), with per-ring
  detection/FP telemetry and automatic halt: the same guardrails as models (gated on the
  #30 lab run).
- **Hunt graduation** (#618): the assisted draft is built (below): `POST /api/hunts/[id]/graduate`
  turns a saved hunt into a draft rule and its samples for a person to review and open as a
  PR; a hunt's page has the buttons. The IOC-set draft (#934, below) is built for hashes and
  addresses. Not built: opening the PR from the server, a draft from the raw event archive
  (`server/datalake`, #77), a Sigma draft from a hunt that matches events other than process
  starts, a YARA draft, and domains in the IOC-set draft.

### The IOC-set draft (#934)
`POST /api/hunts/[id]/graduate` with `{ kind: "ioc" }` (no platform, no negative: a set has
neither) answers one file, `rules/ioc/<slug>.txt`, in the line format `crates/intel` loads
(`docs/detection/ioc-matching.md`), and a `todo` list, or `422` with `problems`
(`lib/hunt-ioc-draft.ts`). It writes nothing. The lines are the indicators the matched
detections carry: the `sha256` of an `exec` event (when the enrichment hashed the image) and
the destination address of a `connect` or `network_flow` event, sorted and listed once. An
IPv4-mapped address is listed as IPv4, and loopback, unspecified and zoned addresses are left
out, as the engine refuses them; the `todo` counts them. A matched detection says something
suspicious happened, not that each value it names is bad, so the `todo` asks a person to drop
the benign ones. **Domains are not drafted:** a listed domain matches every name beneath it
and the device carries no public-suffix list, so a domain must pass the feed builder's check
first (ADR-0038 section 6); the `todo` counts the DNS queries it skipped. The path
`rules/ioc/` is this draft's proposal, since the content repo has no IOC directory or CI check
yet, and delivery to agents waits on #753. A fixture
(`server/tests/fixtures/ioc-draft-golden.txt`) is compared to the exporter's output by
`tests/unit/hunt-ioc-draft.test.ts` and loaded whole by `crates/intel/tests/draft_golden.rs`,
so the draft is checked against the engine the way the Sigma draft is checked against the
content suite.

### The assisted draft (#618)
`POST /api/hunts/[id]/graduate` with `{ platform, negative? }` reads the detections of the
hunt's newest finished run (`lib/hunt-graduation.ts`) and answers the two files and a `todo`
list, or `422` with `problems`. It writes nothing. The hunt's query is not compiled into a
rule, because it runs over the detection store, not over normalised events; the draft reads
what it needs off the matched detections instead:

- **Metadata:** the title is the hunt's name; the ATT&CK tag is the commonest technique id
  among the matches (within the hunt's `techniques` when it has some); `level` is the hunt's
  single severity, else the commonest one among the matches.
- **Selection:** `Image|endswith` the matching sample's file name, and `CommandLine|contains`
  the hunt's `text` when it is in the sample's command line. A hunt with no `text` gets an
  image-only selection and a `todo` saying it is broad.
- **Matching sample:** the newest matched `exec` event (with the hunt's text when it has
  one). A hunt that matched no process start gets `problems`, not a guess.
- **Negative sample:** sent as `negative`, or, when the hunt has a `text`, derived by taking
  the text out of the matching command line and flagged `DRAFT` in its `note`. With neither,
  `problems`. A negative that the draft's own selection would fire on is refused. This is
  the one part a person must really supply: a derived negative proves the pipeline, not the
  boundary of the rule.
- **Placeholders a person fills:** `falsepositives` (a `TODO(analyst)` line, which the lint
  accepts, so the `todo` list and the `# DRAFT` header are what say it is unfinished), the
  tactic and coverage tags.

The exporter reproduces the engine's verdict (the sample fires, the negative does not;
case-insensitive, as `crates/sigma/src/eval.rs`), and a draft was checked against the real
suite: `cargo test -p sigma --test content` passes with it in `rules/sigma/linux/` and fails
naming the file when its sample is broken.

### What a graduated draft has to satisfy
Derived from what CI enforces today:

1. **A rule file that loads**: Sigma limited to the supported subset (an unsupported
   construct is a hard load error naming it), the metadata above, in the right platform
   directory. A draft that fails this fails with the file and the missing field named.
2. **A matching sample and a negative sample for it**, in `<rule>.samples.json` beside the
   rule (ADR-0031; they were Rust test tables keyed by title until then). A rule file with
   no samples file fails naming both files, so an exporter emits the pair and nothing else
   has to be edited. A hunt's own matches are a natural source of the matching sample, but
   the negative sample (a benign lookalike) has to come from an analyst or from benign
   telemetry the hunt also touched. The assisted draft above does exactly
   this; its `selection` is read off one matched event, so it is a starting point (a hunt
   queries the *detection* store, not normalised events), until the raw event archive
   (`server/datalake`, #77) exists.
3. **A human in the loop**: the draft enters the normal PR and review path; graduation
   never merges or ships content by itself.
