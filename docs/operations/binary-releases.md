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
   hex characters and must not be readable by group or others. `--test-key` signs with
   the public checked-in test key, for lab releases only. Content manifests
   (`--kind content`) are signed the same way; they are written by hand or by a
   script, `release-tool` only signs them.

   Key generation, custody and rotation are not decided here (ADR-0015, Deferred): the
   tool takes whatever key file it is given.
3. Put the manifest and the files at the paths above.
4. `POST /api/release` (session-authenticated) with
   `{ "ring", "releaseVersion", "manifestUrl", "manifestSha256" }`. The server refuses
   the release (422) unless the manifest hashes to `manifestSha256`, matches the
   schema, carries `releaseVersion`, and every entry's file exists and hashes to its
   signed value. `releaseVersion` must exceed the ring's latest (409 otherwise).
5. Agents in that ring get it on their next `agent apply-release`.

## What agents can reach

Both routes authenticate like `/api/ingest/*` (nginx proxy secret + verified client
certificate, enrolled agent) and are public to the session middleware for that reason.

- `GET /api/release/manifest`: the latest **active** release of the agent's own ring.
  An agent cannot name a ring or a tenant. 404 when there is none.
- `GET /api/release/artifact?release_version=N&path=P[&sha256=H]`: a file of an active
  release of the agent's ring, only if the manifest lists `P`, and only if the stored
  file still hashes to the signed value (502 otherwise).

Setting `status` to `halted` on a row stops it being offered (there is no endpoint for
that yet; ring-health auto-halt is a later slice).

## Control plane on a private CA

An agent trusts the built-in public roots by default, so a control plane whose
certificate comes from a private CA (a self-hosted install, a lab, the dev CA from
`server/scripts/generate-dev-certs.sh`) fails with `UnknownIssuer`, and installing the
CA in the system store does not help: the agent does not read it. Point the command at
the CA instead:

```sh
agent apply-release --server https://cp.internal --ca-cert /etc/synthaea/certs/ca.pem \
  --cert /etc/synthaea/certs/client.crt --key /etc/synthaea/certs/client.key
```

`--ca-cert` takes a PEM bundle and is accepted by `apply-release`,
`apply-content-manifest` and `check-content-manifest`. It **replaces** the public
roots rather than adding to them, so the server is pinned to that CA. An unreadable
file or a bundle with no certificate stops the command before it connects.

Not covered yet: the `agent run` upload and heartbeat path, and `agent.toml` has no
`server.ca_cert` field (#658).
