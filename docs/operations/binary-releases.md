# Publishing a binary release

How a signed agent release gets from a build to the agents of a ring (ADR-0015, issue
#30). The agent side is `agent apply-release`; this is the control-plane side.

## Storage layout (dev, local filesystem)

Under the server's working directory:

```
storage/manifests/release-<ring>-v<N>.json   the signed manifest
storage/releases/v<N>/<path>                 one file per manifest entry
```

`manifestUrl` is `storage://manifests/release-<ring>-v<N>.json` (a production object
store URL is fetched over the network, as for content manifests).

## Steps

1. Build the release files (`agent`, `watchdog`, `cli`, ...) into one directory.
2. Build and sign the manifest **offline** with `release-tool` (workspace member
   `release-tool/`, not shipped to endpoints). The server never holds the private key,
   and does not verify the signature: every agent does, before staging.

   ```
   release-tool manifest --release-version N --dir dist/ --out manifest.json
   release-tool sign --kind release --key-file release.key manifest.json --out signed.json
   ```

   `manifest` hashes every regular file under `dist/` (a symlink is refused) into
   `{"schema_version":1,"release_version":N,"entries":{"agent":"<sha256>",...},"signature":""}`;
   the manifest carries no ring and no per-entry size. `sign` refuses a manifest the
   agent would reject whatever its signature (an entry path that escapes the release
   directory), prints the signing key's public half, and says whether the key embedded
   in this build of `updater` accepts the result; if it does not, agents built with
   that key will refuse the release. The key file holds the 32-byte Ed25519 seed as 64
   hex characters and must not be readable by group or others, and it must hold one of the
   public test seeds (ADR-0027: any other key file is refused, and a build without the
   `test-key` feature takes none). `--test-key` signs with the public checked-in test key, for
   lab releases only. Content manifests
   (`--kind content`) are signed the same way; they are written by hand or by a
   script, `release-tool` only signs them.

   **Signing from a PKCS#11 token (ADR-0027 decision 2).** A production key lives on a PIV
   token or an HSM and never leaves it: the tool sends the canonical manifest bytes to the
   token and takes the Ed25519 signature back.

   ```
   RELEASE_TOOL_PKCS11_PIN=... release-tool sign --kind release \
       --pkcs11 /usr/lib64/pkcs11/opensc-pkcs11.so --pkcs11-token release --pkcs11-key release \
       manifest.json --out signed.json
   release-tool public-key --pkcs11 <module> --pkcs11-token release --pkcs11-key release
   ```

   `--pkcs11` is the vendor's module, `--pkcs11-token` the token's label (not its slot
   number) and `--pkcs11-key` the label shared by the key's private and public objects; the
   key must be an Ed25519 key (`CKM_EDDSA`). The PIN is read from `RELEASE_TOOL_PKCS11_PIN`
   or from `--pkcs11-pin-file` (mode 0600), never from an argument. The tool refuses to
   guess: no token, two tokens, or no or several keys with the label is an error, and a
   signature that does not verify under the token's own public key is never written.
   `public-key` prints the value to commit under `crates/updater/keys/`. `--key-file` and
   `--test-key` are for lab and dev releases: a key readable from a file is not a production
   key. The tool is tested against SoftHSM with a throwaway token (`tools/test-pkcs11.sh`,
   run by CI); it has not been run against a real PIV token or HSM. Who holds the token and
   who approves a release are the owner's decisions (ADR-0027), not the tool's.

   Key generation, custody and rotation are decided in ADR-0027; until the real keys exist
   the tool signs with the public test keys or with a token.

   **Key rotation (ADR-0027).** A rotation names a new `release` and/or `content` key and the
   key each replaces, and is signed by the offline `recovery` key and nothing else:

   ```
   release-tool rotation --release-version 9 --reason "scheduled" \
       --new-release-key <hex> --retire-release-key <hex> --out rotation.json
   release-tool sign --kind rotation --pkcs11 <module> --pkcs11-token recovery --pkcs11-key recovery \
       rotation.json --out rotation-signed.json
   ```

   On an endpoint, `agent apply-key-rotation` (from the control plane, or `--file`) verifies it
   against the embedded `recovery` key and the keys in force, and records it in
   `<state_dir>/key-rotations.json`; from then on the release and content commands and the
   integrity check use the rotated keys. A rotation takes its number from the release counter
   (it must be above the installed release and any earlier rotation, and the next release above
   it) and is applicable for at most 30 days after it is issued. A record that exists and does
   not verify makes those commands refuse, on purpose: see ADR-0027, "How an install holds the
   rotated keys", for what absent, older and corrupt records do.

   **Publishing a rotation.** The control plane never signs one and never checks the signature
   (agents do, against the `recovery` key they embed). It serves the file an operator places at
   `storage/key-rotations/<ring>.json` (`canary_0`, `canary_1`, `canary_2`, `prod`), byte for
   byte: one pending rotation per ring, so a rotation can reach a canary ring before `prod`, and
   removing the file withdraws it (404). A file that is not valid JSON or not shaped like a
   rotation (unknown field, a key that is not 64 lowercase hex characters, half a pair, a window
   beyond 30 days) is answered with 502 and an entry in the server log, never handed to an agent.
   A rotation names the key it retires, so it applies to hosts on that key state only: with one
   file per ring the server serves one state at a time, and an agent on another state refuses it
   without effect. There is no publish endpoint yet: the file is placed on the server by hand.

   **Which key a build trusts (ADR-0027).** An agent embeds a trust set of `release`,
   `content` and `recovery` public keys from `crates/updater/keys/*.pub`. Those files say
   `unprovisioned` until the real keys are committed, so a build without the `test-key`
   cargo feature verifies nothing: `apply-release` and `apply-content-manifest` refuse with
   "no production signing key". The default (development and lab) build has the feature,
   which embeds the public test key; it then refuses both commands unless you pass
   `--allow-test-key`, because anyone who can serve the routes can sign for it. Packaged
   builds (`packaging/linux`, and the Windows MSI of `packaging/windows`, whose `build.ps1`
   scans the binaries) turn the feature off (`--no-default-features`), and CI's
   `tools/check-no-test-key.sh` fails if the test key reaches them; the Windows and macOS
   static-agent jobs also scan the agent they build. There is no macOS package script yet,
   so a macOS package will have to be built the same way when it lands. A lab that applies a
   release or content with a package therefore needs its own build with the feature.
3. Put the manifest and the files at the paths above.
4. `POST /api/release` (session-authenticated) with
   `{ "ring", "releaseVersion", "manifestUrl", "manifestSha256" }`. The server refuses
   the release (422) unless the manifest hashes to `manifestSha256`, matches the
   schema, carries `releaseVersion`, and every entry's file exists and hashes to its
   signed value. `releaseVersion` must exceed the ring's latest (409 otherwise).
5. Agents in that ring get it on their next `agent apply-release`.

## What agents can reach

All three routes authenticate like `/api/ingest/*` (nginx proxy secret + verified client
certificate, enrolled agent) and are public to the session middleware for that reason.

- `GET /api/release/manifest`: the latest **active** release of the agent's own ring.
  An agent cannot name a ring or a tenant. 404 when there is none.
- `GET /api/release/artifact?release_version=N&path=P[&sha256=H]`: a file of an active
  release of the agent's ring, only if the manifest lists `P`, and only if the stored
  file still hashes to the signed value (502 otherwise).
- `GET /api/release/key-rotation`: the key rotation pending for the agent's own ring
  (ADR-0027), which `agent apply-key-rotation` fetches. 404 when nothing is pending.

Setting `status` to `halted` on a row stops it being offered (there is no endpoint for
that yet; ring-health auto-halt is a later slice).

## Control plane on a private CA

An agent trusts the built-in public roots by default, so a control plane whose
certificate comes from a private CA (a self-hosted install, a lab, the dev CA from
`server/scripts/generate-dev-certs.sh`) fails with `UnknownIssuer`, and installing the
CA in the system store does not help: the agent does not read it. Tell the agent which
CA to trust, once, in `agent.toml`:

```toml
[server]
ca_cert = "/etc/synthaea/certs/ca.pem"   # absolute path, PEM bundle
```

That applies to `agent run --server`, `apply-release`, `apply-content-manifest` and
`check-content-manifest`. Each of the four also takes `--ca-cert <PEM>`, which wins over
the file for that run:

```sh
agent apply-release --server https://cp.internal --ca-cert /etc/synthaea/certs/ca.pem \
  --cert /etc/synthaea/certs/client.crt --key /etc/synthaea/certs/client.key
```

The bundle **replaces** the public roots rather than adding to them, so the server is
pinned to that CA. An unreadable file or a bundle with no certificate stops the command
before it connects (`agent run` stops at start-up). A CA is a trust anchor, not a
credential, so it also applies to a server named by hand; the client certificate does
not (see `--cert`/`--key`).

`agent run` uses the same two settings, and it also presents the client certificate: by
default it uploads to `server.control_plane_url` with `server.mtls_cert` and
`server.mtls_key`, and trusts only `server.ca_cert` when that is set. `--server` names
another control plane (it never receives the configured client certificate; pass
`--cert`/`--key` for one that needs it), and `--standalone` uploads nothing. An unreadable
client certificate or key, a passphrase-protected key (the transport cannot use an encrypted
key yet: `server.mtls_passphrase` is not wired) or a missing CA bundle is a failure to set
the upload up, and what happens next follows `server.offline_fallback`:

- **`true` (the default):** `run` starts and detects locally without uploading. It says so
  in the journal (`UPLOAD DISABLED: not uploading to <url>: <cause>`) and writes an
  `UPLOAD-DISABLED` line to the alert log. Nothing is uploaded until the next start with
  the certificates in place.
- **`false`:** `run` stops at start-up with the cause.

The default is deliberate. Stopping would leave a host without certificates with no
detection at all (a first install, or any host the certificates have not reached yet), and
the watchdog, which only sees that the agent never shows progress, would roll back and ban a
release that is otherwise healthy (ADR-0015 probation). Set `offline_fallback = false` where
an agent that cannot report should not run.
