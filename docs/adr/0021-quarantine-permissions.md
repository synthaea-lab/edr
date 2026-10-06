# ADR-0021: Platform permissions at the quarantine boundary

- **Status**: accepted
- **Date**: 2026-10-01

## Context

The `response` crate moves confirmed malicious payloads to a quarantine directory.
Its platform-neutral `set_readonly(true)` call leaves Unix execute bits intact and
does not restrict traversal of the directory. A quarantined payload can therefore
remain executable by another local user when the parent directory is traversable
(#569). The Windows agent does not yet enable automated quarantine, but its
eventual ACL policy needs the same security property.

## Decision

Permit a narrow platform-specific exception in `response::quarantine` for
filesystem permission enforcement. On Unix, tighten the quarantine directory to
`0700`, payloads to `0400`, and origin sidecars to `0600`, including directories
created by an older version. Reject a symlink used as the quarantine directory.
The restore action leaves the payload non-executable; an analyst must explicitly
change its mode before running it. Before enabling Windows quarantine, implement
and test an ACL that limits access to the service identity and administrators.

## Consequences

The privileged response boundary owns the permissions it relies on, while the
sensor crates remain independent of response actions. A service user needs
access to the quarantine directory to list and restore payloads. Existing Unix
quarantine directories are tightened on their next write. Windows ACL enforcement
is still required before that platform enables automated quarantine.
