//! Content-manifest fetch, verification, download, and apply (ADR-0016,
//! issue #30/#73): the agent-side half of "fetch a signed manifest for my
//! ring, verify it, download what changed, write it to disk."
//!
//! [`cmd_check_content_manifest`] does the fetch-and-verify-only report;
//! [`cmd_apply_content_manifest`] additionally downloads each missing/stale
//! entry via `GET /api/content/artifact` (already real server-side),
//! verifies its SHA-256 against the manifest, and writes it under a content
//! directory. Deliberately stops there — reloading rules/models into a
//! running `DetectionSink`, and any config-driven ring assignment or
//! periodic trigger, are follow-up work, not this slice.
//!
//! Composed here rather than in `crates/updater` because `updater` is a LEAF
//! crate and may not depend on `transport` (`tools/check-deps.py`) — see that
//! crate's module doc.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use updater::{ContentEntry, ContentManifest, UpdaterError, hash::hash_bytes};

/// What this agent has already applied for one ring — the local half of the
/// anti-rollback/dedup check. Persisted as plain JSON next to the agent's other
/// state (no signature: this is the agent's own record of its own state, not
/// something an adversary gains anything by forging locally — the same trust
/// boundary `updater::banlist` already accepts for its ban list).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ContentState {
    /// The highest `release_version` successfully applied, keyed by ring —
    /// per review (PR #509), a single shared counter would let an agent that
    /// is ever pointed at a different ring (a ring reassignment, or a
    /// mismatched manifest that predates the `plan` ring check) lock itself
    /// out of that ring's own real releases as "not newer than installed",
    /// even after the mismatch itself is caught. `None`/absent for a ring is
    /// day zero for it, same as `ReleaseManifest::check_release_version`'s
    /// `None` case.
    #[serde(default)]
    pub(crate) release_version: BTreeMap<String, u64>,
    /// path -> sha256 of every artifact currently applied.
    #[serde(default)]
    pub(crate) entries: BTreeMap<String, String>,
}

impl ContentState {
    /// Loads the persisted state from `path`. A missing file is a fresh
    /// install, not an error — same posture as `updater::banlist::BannedVersions::load`.
    pub(crate) fn load(path: &Path) -> Result<Self, std::io::Error> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// The last-applied `release_version` for `ring`, or `None` if this ring
    /// has never been applied.
    fn release_version_for(&self, ring: &str) -> Option<u64> {
        self.release_version.get(ring).copied()
    }
}

/// What a fetched manifest means for this agent, right now: whether it's
/// already fully applied, and if not, exactly which entries are missing or
/// stale.
#[derive(Debug, PartialEq)]
pub(crate) struct FetchPlan {
    pub(crate) release_version: u64,
    pub(crate) to_fetch: Vec<ContentEntry>,
}

/// Verifies `manifest` (signature + anti-rollback against `state`) and reports
/// which entries this agent still needs to fetch. Pure — no I/O, no network —
/// so it's unit-testable without a live server; `cmd_check_content_manifest`
/// is the thin composition that actually fetches and calls this.
///
/// # Errors
///
/// Propagates [`UpdaterError::SchemaVersionUnsupported`],
/// [`UpdaterError::SignatureInvalid`], [`UpdaterError::RingMismatch`] (checked
/// right after the signature — a valid signature only proves who signed the
/// manifest, not that it's the one for `ring`), or
/// [`UpdaterError::ReleaseNotNewer`] — the same checks a binary self-update
/// manifest gets, applied to content — or [`UpdaterError::UnsafeContentPath`]
/// if any entry's path would escape a local content root.
pub(crate) fn plan(
    manifest: &ContentManifest,
    ring: &str,
    state: &ContentState,
) -> Result<FetchPlan, UpdaterError> {
    manifest.verify_signature()?;
    manifest.check_ring(ring)?;
    manifest.check_release_version(state.release_version_for(ring))?;
    manifest.validate_entry_paths()?;
    let to_fetch = manifest
        .entries_to_fetch(&state.entries)
        .into_iter()
        .cloned()
        .collect();
    Ok(FetchPlan {
        release_version: manifest.release_version,
        to_fetch,
    })
}

/// Fetches the content manifest for `ring` from `server`, verifies it, and
/// prints a report of what has changed — does not download artifacts or apply
/// anything (see module doc). `state_path` is where this agent's own
/// [`ContentState`] is read from; a fresh install with no file yet reports
/// every entry in the manifest as needing a fetch.
///
/// # Errors
///
/// Returns an error if the server is unreachable, the manifest fails
/// verification, or it is not newer than the last-applied release for this
/// ring (an operator re-running the check sees this as "up to date", not a
/// crash — see the caller's own message mapping, `commands::content` on the
/// CLI side).
pub(crate) fn cmd_check_content_manifest(
    server: &str,
    ring: &str,
    cert: Option<&Path>,
    key: Option<&Path>,
    state_path: &Path,
) -> anyhow::Result<()> {
    let client = build_client(server, cert, key)?;
    let url = client.config().content_manifest_url(ring);
    let manifest: ContentManifest = client.get_json(&url)?;

    let state = ContentState::load(state_path)?;
    match plan(&manifest, ring, &state) {
        Ok(plan) => {
            println!(
                "ring {ring}: release {} available, {} entr{} to fetch",
                plan.release_version,
                plan.to_fetch.len(),
                if plan.to_fetch.len() == 1 { "y" } else { "ies" }
            );
            for entry in &plan.to_fetch {
                println!(
                    "  {} ({}, {} bytes, sha256={})",
                    entry.path, entry.content_type, entry.size, entry.sha256
                );
            }
        }
        Err(UpdaterError::ReleaseNotNewer { offered, current }) => {
            println!("ring {ring}: up to date (release {current}, server offers {offered})");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Builds a [`transport::TransportClient`] for `server`, with mTLS if both
/// `cert` and `key` are given — shared by [`cmd_check_content_manifest`] and
/// [`cmd_apply_content_manifest`].
///
/// # Errors
///
/// Returns an error if mTLS certificates are configured but cannot be loaded.
fn build_client(
    server: &str,
    cert: Option<&Path>,
    key: Option<&Path>,
) -> anyhow::Result<transport::TransportClient> {
    let mut config = transport::TransportConfig::new(server);
    if let (Some(cert), Some(key)) = (cert, key) {
        config = config.with_client_cert(PathBuf::from(cert), PathBuf::from(key));
    }
    Ok(transport::TransportClient::new(config)?)
}

/// Resolves `entry_path` (already checked safe by
/// [`ContentManifest::validate_entry_paths`], called from [`plan`]) onto
/// `root`, one path segment at a time — content paths are forward-slash-only
/// by contract (the field's own doc comment) regardless of the host's path
/// separator, so segments are joined individually rather than handing the
/// raw string to a single `Path::push`.
fn artifact_dest(root: &Path, entry_path: &str) -> PathBuf {
    let mut dest = root.to_path_buf();
    for segment in entry_path.split('/') {
        dest.push(segment);
    }
    dest
}

/// Downloads every entry in `fetch_plan.to_fetch` from the (already-real)
/// `/api/content/artifact` endpoint, verifies its SHA-256 against the
/// manifest's declared hash, and writes it under `content_dir`. Persists
/// `state` after each successful write — a crash or network failure partway
/// through leaves already-applied entries recorded, so a re-run's `plan()`
/// recomputes the diff against the updated file and only re-fetches what's
/// left. The ring's `release_version` is bumped and persisted only once
/// every entry has landed, so a caller retrying a partially-applied
/// manifest still passes `check_release_version` on the next attempt.
///
/// Deliberately stops there — does not reload anything into a running
/// `DetectionSink` (module doc).
///
/// # Errors
///
/// Returns an error if a download fails, a downloaded artifact's hash
/// doesn't match the manifest's declared value
/// ([`UpdaterError::StagedFileMismatch`]), or a filesystem write fails.
fn download_and_apply(
    client: &transport::TransportClient,
    fetch_plan: &FetchPlan,
    ring: &str,
    content_dir: &Path,
    state_path: &Path,
    mut state: ContentState,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(content_dir)?;

    for entry in &fetch_plan.to_fetch {
        let url = client.config().content_artifact_url();
        let bytes = client.get_bytes(
            &url,
            &[
                ("path", entry.path.as_str()),
                ("sha256", entry.sha256.as_str()),
            ],
            entry.size,
        )?;

        let actual = hash_bytes(&bytes);
        if actual != entry.sha256 {
            return Err(UpdaterError::StagedFileMismatch {
                path: PathBuf::from(&entry.path),
                expected: entry.sha256.clone(),
                actual,
            }
            .into());
        }

        let dest = artifact_dest(content_dir, &entry.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &bytes)?;

        state
            .entries
            .insert(entry.path.clone(), entry.sha256.clone());
        std::fs::write(state_path, serde_json::to_vec(&state)?)?;
    }

    state
        .release_version
        .insert(ring.to_string(), fetch_plan.release_version);
    std::fs::write(state_path, serde_json::to_vec(&state)?)?;
    Ok(())
}

/// Fetches the content manifest for `ring`, verifies it exactly like
/// [`cmd_check_content_manifest`], and — unlike that command — actually
/// downloads and writes every entry that's missing or stale under
/// `content_dir`, then records what was applied in `state_path`.
///
/// # Errors
///
/// Returns an error if the server is unreachable, the manifest fails
/// verification, or [`download_and_apply`] fails partway through (already-
/// applied entries stay recorded in `state_path` for the next attempt).
pub(crate) fn cmd_apply_content_manifest(
    server: &str,
    ring: &str,
    cert: Option<&Path>,
    key: Option<&Path>,
    content_dir: &Path,
    state_path: &Path,
) -> anyhow::Result<()> {
    let client = build_client(server, cert, key)?;
    let url = client.config().content_manifest_url(ring);
    let manifest: ContentManifest = client.get_json(&url)?;

    let state = ContentState::load(state_path)?;
    let fetch_plan = match plan(&manifest, ring, &state) {
        Ok(fetch_plan) => fetch_plan,
        Err(UpdaterError::ReleaseNotNewer { offered, current }) => {
            println!("ring {ring}: up to date (release {current}, server offers {offered})");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let fetched = fetch_plan.to_fetch.len();
    download_and_apply(&client, &fetch_plan, ring, content_dir, state_path, state)?;
    println!(
        "ring {ring}: applied release {} ({fetched} entr{} fetched)",
        fetch_plan.release_version,
        if fetched == 1 { "y" } else { "ies" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a manifest and signs it exactly the way `updater::content`'s own
    /// tests do (this crate can't call that module's private signing helper
    /// directly): canonical bytes with `signature` forced empty, 2-space-indent
    /// JSON, Ed25519 over that, hex-encoded. Then round-trips through JSON so
    /// tests exercise what a real fetch would actually deserialize.
    fn signed_manifest_json(release_version: u64, entries: Vec<ContentEntry>) -> ContentManifest {
        signed_manifest_json_for_ring("canary_0", release_version, entries)
    }

    fn signed_manifest_json_for_ring(
        ring: &str,
        release_version: u64,
        entries: Vec<ContentEntry>,
    ) -> ContentManifest {
        let mut m = ContentManifest {
            entries,
            release_version,
            released_at: "2026-09-23T16:00:00Z".to_string(),
            ring: ring.to_string(),
            schema_version: updater::content::CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        };
        let bytes = serde_json::to_vec_pretty(&m).unwrap();
        let sig = updater::key::test_key_pair().sign(&bytes);
        m.signature = updater::hash::hex_encode(sig.as_ref());
        serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap()
    }

    fn entry(path: &str) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: "a".repeat(64),
            size: 10,
            content_type: "rule".to_string(),
        }
    }

    #[test]
    fn a_fresh_install_needs_every_entry() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let state = ContentState::default();
        let result = plan(&manifest, "canary_0", &state).unwrap();
        assert_eq!(result.release_version, 1);
        assert_eq!(result.to_fetch.len(), 1);
    }

    #[test]
    fn an_already_applied_entry_is_not_refetched() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let mut state = ContentState::default();
        state
            .entries
            .insert("rules/a.sigma".to_string(), "a".repeat(64));
        let result = plan(&manifest, "canary_0", &state).unwrap();
        assert!(result.to_fetch.is_empty());
    }

    #[test]
    fn a_manifest_no_newer_than_the_applied_release_is_rejected() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let mut state = ContentState::default();
        state.release_version.insert("canary_0".to_string(), 1);
        assert!(matches!(
            plan(&manifest, "canary_0", &state),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 1,
                current: 1
            })
        ));
    }

    #[test]
    fn a_tampered_manifest_is_rejected_before_the_release_version_check() {
        let mut manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        manifest.entries.push(entry("rules/injected.sigma"));
        let state = ContentState::default();
        assert!(matches!(
            plan(&manifest, "canary_0", &state),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_correctly_signed_manifest_for_another_ring_is_rejected() {
        // Concrete attack this pins (PR #509 review): a prod agent requests
        // `prod` but is served (or a stale response cache/misrouted request
        // returns) a validly-signed `canary_0` manifest with a higher
        // release_version. Without a ring check this would verify and be
        // accepted, applying the least-vetted ring's content to a prod agent.
        let manifest = signed_manifest_json(99, vec![entry("rules/a.sigma")]);
        let state = ContentState::default();
        assert!(matches!(
            plan(&manifest, "prod", &state),
            Err(UpdaterError::RingMismatch { requested, found })
                if requested == "prod" && found == "canary_0"
        ));
    }

    #[test]
    fn anti_rollback_state_is_scoped_per_ring() {
        // A ring reassignment (or an agent that has fetched more than one
        // ring's manifest) must not have one ring's higher release_version
        // lock out another ring's own, independently-numbered releases.
        let mut state = ContentState::default();
        state.release_version.insert("canary_0".to_string(), 50);

        // release_version 10 for `prod` — lower than canary_0's 50, but prod
        // has never been applied in this state, so it must still pass.
        let prod_manifest = signed_manifest_json_for_ring("prod", 10, vec![entry("rules/a.sigma")]);

        let result = plan(&prod_manifest, "prod", &state).unwrap();
        assert_eq!(result.release_version, 10);
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("content-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn content_state_load_on_a_missing_file_is_a_fresh_default() {
        let dir = tmp("missing");
        let state = ContentState::load(&dir.join("does-not-exist.json")).unwrap();
        assert_eq!(state, ContentState::default());
    }

    #[test]
    fn content_state_round_trips_through_disk() {
        let dir = tmp("round-trip");
        let path = dir.join("content-state.json");
        let mut state = ContentState {
            release_version: BTreeMap::from([("canary_0".to_string(), 3)]),
            entries: BTreeMap::new(),
        };
        state
            .entries
            .insert("rules/a.sigma".to_string(), "a".repeat(64));
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();

        let loaded = ContentState::load(&path).unwrap();
        assert_eq!(loaded, state);
    }

    // ── artifact_dest ────────────────────────────────────────────────────

    #[test]
    fn artifact_dest_joins_forward_slash_segments_onto_root() {
        let root = std::path::Path::new("/var/lib/synthaea/content");
        assert_eq!(
            artifact_dest(root, "rules/beacon.sigma"),
            root.join("rules").join("beacon.sigma")
        );
    }

    // ── download_and_apply ──────────────────────────────────────────────
    //
    // A minimal one-shot HTTP server (std only, no new dev-dependency): the
    // agent-side download path issues one GET per entry, in `to_fetch`'s
    // order, so a fixed sequence of canned responses is enough to test it
    // without a real control plane.

    fn read_request(stream: &mut std::net::TcpStream) {
        use std::io::Read as _;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let Ok(n) = stream.read(&mut chunk) else {
                return;
            };
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).position(|w| w == b"\r\n\r\n").is_some() {
                return; // GET requests here carry no body
            }
            if n == 0 {
                return;
            }
        }
    }

    fn write_response(stream: &mut std::net::TcpStream, status: u16, body: &[u8]) {
        use std::io::Write as _;
        let reason = if status == 200 { "OK" } else { "NOPE" };
        let _ = write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(body);
    }

    /// Serves one canned `(status, body)` response per accepted connection,
    /// in order, then exits once the list is exhausted.
    fn artifact_server(responses: Vec<(u16, Vec<u8>)>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                read_request(&mut stream);
                write_response(&mut stream, status, &body);
            }
        });
        format!("http://{addr}")
    }

    fn entry_for(path: &str, bytes: &[u8]) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: hash_bytes(bytes),
            size: bytes.len() as u64,
            content_type: "rule".to_string(),
        }
    }

    #[test]
    fn download_and_apply_writes_verified_entries_and_persists_state() {
        let dir = tmp("apply-happy-path");
        let content_dir = dir.join("content");
        let state_path = dir.join("content-state.json");

        let e1 = entry_for("rules/beacon.sigma", b"title: beacon\n");
        let e2 = entry_for("models/cmdline/model.pkl", b"\x00\x01binary-model-bytes");
        let url = artifact_server(vec![
            (200, b"title: beacon\n".to_vec()),
            (200, b"\x00\x01binary-model-bytes".to_vec()),
        ]);
        let client =
            transport::TransportClient::new(transport::TransportConfig::new(&url)).unwrap();
        let fetch_plan = FetchPlan {
            release_version: 7,
            to_fetch: vec![e1.clone(), e2.clone()],
        };

        download_and_apply(
            &client,
            &fetch_plan,
            "canary_0",
            &content_dir,
            &state_path,
            ContentState::default(),
        )
        .unwrap();

        assert_eq!(
            std::fs::read(content_dir.join("rules").join("beacon.sigma")).unwrap(),
            b"title: beacon\n"
        );
        assert_eq!(
            std::fs::read(content_dir.join("models").join("cmdline").join("model.pkl")).unwrap(),
            b"\x00\x01binary-model-bytes"
        );

        let state = ContentState::load(&state_path).unwrap();
        assert_eq!(state.entries.get("rules/beacon.sigma"), Some(&e1.sha256));
        assert_eq!(
            state.entries.get("models/cmdline/model.pkl"),
            Some(&e2.sha256)
        );
        assert_eq!(state.release_version.get("canary_0"), Some(&7));
    }

    #[test]
    fn download_and_apply_rejects_a_hash_mismatch_before_writing_it() {
        let dir = tmp("apply-hash-mismatch");
        let content_dir = dir.join("content");
        let state_path = dir.join("content-state.json");

        // The manifest declares this hash, but the server actually serves
        // different bytes — the concrete tamper/corruption case this check
        // exists for.
        let mut entry = entry_for("rules/beacon.sigma", b"title: beacon\n");
        entry.sha256 = "f".repeat(64);
        let url = artifact_server(vec![(200, b"title: beacon\n".to_vec())]);
        let client =
            transport::TransportClient::new(transport::TransportConfig::new(&url)).unwrap();
        let fetch_plan = FetchPlan {
            release_version: 1,
            to_fetch: vec![entry],
        };

        let err = download_and_apply(
            &client,
            &fetch_plan,
            "canary_0",
            &content_dir,
            &state_path,
            ContentState::default(),
        )
        .expect_err("a hash mismatch must not be silently written");
        assert!(err.to_string().contains("hash mismatch"));
        assert!(!content_dir.join("rules").join("beacon.sigma").exists());
    }

    #[test]
    fn download_and_apply_preserves_progress_when_a_later_entry_fails() {
        let dir = tmp("apply-partial-progress");
        let content_dir = dir.join("content");
        let state_path = dir.join("content-state.json");

        let e1 = entry_for("rules/first.sigma", b"first");
        let mut e2 = entry_for("rules/second.sigma", b"second");
        e2.sha256 = "f".repeat(64); // will mismatch what the server serves
        let url = artifact_server(vec![(200, b"first".to_vec()), (200, b"second".to_vec())]);
        let client =
            transport::TransportClient::new(transport::TransportConfig::new(&url)).unwrap();
        let fetch_plan = FetchPlan {
            release_version: 5,
            to_fetch: vec![e1.clone(), e2],
        };

        download_and_apply(
            &client,
            &fetch_plan,
            "canary_0",
            &content_dir,
            &state_path,
            ContentState::default(),
        )
        .expect_err("the second entry's hash mismatch must surface");

        // The first entry landed and was recorded before the second failed.
        assert!(content_dir.join("rules").join("first.sigma").exists());
        let state = ContentState::load(&state_path).unwrap();
        assert_eq!(state.entries.get("rules/first.sigma"), Some(&e1.sha256));
        assert!(!state.entries.contains_key("rules/second.sigma"));
        // The release isn't marked applied until every entry lands.
        assert!(!state.release_version.contains_key("canary_0"));
    }
}
