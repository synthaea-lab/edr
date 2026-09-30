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

1. Build the release files (`agent`, `watchdog`, `cli`, ...) and hash them.
2. Create the manifest `{"schema_version":1,"release_version":N,"entries":{"agent":"<sha256>",...},"signature":""}`
   and sign it **offline** with the updater key (`ReleaseManifest::sign`). The server
   never holds the private key, and does not verify the signature: every agent does,
   before staging. The manifest carries no ring and no per-entry size.
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
