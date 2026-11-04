import { S3Client } from "@aws-sdk/client-s3";
import { FsLakeStore, lakeEnabled, type EventArchive, type LakeReader, type LakeStore } from "@/lib/lake-store";
import { S3LakeReader, S3LakeStore } from "@/lib/lake-s3-store";

type Env = Record<string, string | undefined>;

/** The S3 settings, from the environment. Documented in `server/datalake/README.md`. */
export function s3Settings(env: Env, creds: { id: string; secret: string } = { id: "LAKE_S3_ACCESS_KEY_ID", secret: "LAKE_S3_SECRET_ACCESS_KEY" }) {
  const bucket = env.LAKE_S3_BUCKET ?? "";
  const endpoint = env.LAKE_S3_ENDPOINT || undefined;
  const forcePath = env.LAKE_S3_FORCE_PATH_STYLE;
  if (forcePath !== undefined && forcePath !== "" && forcePath !== "true" && forcePath !== "false") {
    throw new Error(`LAKE_S3_FORCE_PATH_STYLE must be "true" or "false", got "${forcePath}"`);
  }
  const accessKeyId = env[creds.id] || undefined;
  const secretAccessKey = env[creds.secret] || undefined;
  // One without the other is a misconfiguration, not a request for the default credential chain.
  if ((accessKeyId === undefined) !== (secretAccessKey === undefined)) {
    throw new Error(`${creds.id} and ${creds.secret} must be set together`);
  }
  return {
    bucket,
    endpoint,
    region: env.LAKE_S3_REGION || "us-east-1",
    prefix: env.LAKE_S3_PREFIX ?? "",
    // MinIO and most self-hosted stores need path-style addressing; a custom endpoint defaults to it.
    forcePathStyle: forcePath === "true" || (forcePath !== "false" && endpoint !== undefined),
    accessKeyId,
    secretAccessKey,
  };
}

function s3Client(s: ReturnType<typeof s3Settings>): S3Client {
  return new S3Client({
    region: s.region,
    endpoint: s.endpoint,
    forcePathStyle: s.forcePathStyle,
    credentials: s.accessKeyId && s.secretAccessKey ? { accessKeyId: s.accessKeyId, secretAccessKey: s.secretAccessKey } : undefined,
    // Newer SDKs add checksum headers by default; some S3-compatible stores reject them.
    requestChecksumCalculation: "WHEN_REQUIRED",
    responseChecksumValidation: "WHEN_REQUIRED",
  });
}

let cached: { key: string; store: LakeStore } | null = null;

/**
 * The store the environment asks for, or null when the lake is off. `LAKE_DIR` selects a directory,
 * `LAKE_S3_BUCKET` an S3-compatible bucket; both set is refused rather than guessed, since writing
 * to one while retention reads the other would silently split the lake.
 *
 * An S3 store is built once per distinct configuration and reused: the client keeps connections.
 */
export function lakeStoreFromEnv(env: Env = process.env): LakeStore | null {
  if (!lakeEnabled(env)) return null;
  const dir = env.LAKE_DIR ?? "";
  const bucket = env.LAKE_S3_BUCKET ?? "";
  if (dir !== "" && bucket !== "") {
    throw new Error("Set LAKE_DIR or LAKE_S3_BUCKET, not both");
  }
  if (dir !== "") return new FsLakeStore(dir);

  const s = s3Settings(env);
  const key = JSON.stringify(s);
  if (cached?.key === key) return cached.store;
  const store = new S3LakeStore({ bucket: s.bucket, prefix: s.prefix, client: s3Client(s) });
  cached = { key, store };
  return store;
}

const READER_CREDS = { id: "LAKE_S3_READER_ACCESS_KEY_ID", secret: "LAKE_S3_READER_SECRET_ACCESS_KEY" };
let cachedReader: { key: string; reader: LakeReader } | null = null;

/**
 * The reader the query side uses, or null when the lake is off. A directory is read in place; an S3
 * bucket is read through `S3LakeReader` on its own client and its own credentials
 * (`LAKE_S3_READER_ACCESS_KEY_ID` / `LAKE_S3_READER_SECRET_ACCESS_KEY`, both or neither), never the
 * writer's `LAKE_S3_ACCESS_KEY_ID` pair (ADR-0041, decision 4): with neither set the SDK's default
 * credential chain applies. Same refusals as `lakeStoreFromEnv` (both stores set, bad settings).
 *
 * With no reader pair, the reader resolves the default chain (an instance role, IRSA), which can
 * have write and delete rights, and that holds whether or not the writer has an explicit pair of its
 * own (its variables say nothing about the reader's role): decision 4 is then met only if that role is
 * read-only, which this cannot see. So the warning is logged whenever the reader pair is unset and S3
 * is in use, once per process and configuration, on the first call (the archive search, not startup),
 * rather than refusing to start. Set the reader pair, or give the reader a read-only role, to meet it.
 */
export function lakeReaderFromEnv(env: Env = process.env): LakeReader | null {
  if (!lakeEnabled(env)) return null;
  const dir = env.LAKE_DIR ?? "";
  const bucket = env.LAKE_S3_BUCKET ?? "";
  if (dir !== "" && bucket !== "") throw new Error("Set LAKE_DIR or LAKE_S3_BUCKET, not both");
  if (dir !== "") return new FsLakeStore(dir);

  const s = s3Settings(env, READER_CREDS);
  const key = JSON.stringify(s);
  if (cachedReader?.key === key) return cachedReader.reader;
  if (s.accessKeyId === undefined) {
    console.warn(
      "Lake reader: LAKE_S3_READER_ACCESS_KEY_ID/LAKE_S3_READER_SECRET_ACCESS_KEY are not set, so the reader uses the SDK's default credential chain (an instance or IRSA role), which can have write and delete rights on the bucket, whether or not the writer has its own LAKE_S3_ACCESS_KEY_ID pair: the query side may run with more than read access (ADR-0041, decision 4). Set the reader pair, or give the reader its own read-only role."
    );
  }
  const reader = new S3LakeReader({ bucket: s.bucket, prefix: s.prefix, client: s3Client(s) });
  cachedReader = { key, reader };
  return reader;
}

/**
 * What the archive search can read from, as the environment says (#1105): a reader exists, or the
 * lake is off. `no_reader` stays in the type for a store that has no read side; no configurable
 * store is in that case now, so the `no_reader` branch below is unreachable today (`lakeEnabled`
 * implies a reader) and kept only so a future store without one is a 501 and not a silent `off`.
 */
export function eventArchiveFromEnv(env: Env = process.env): EventArchive {
  const reader = lakeReaderFromEnv(env);
  if (reader !== null) return { state: "ready", reader };
  return lakeEnabled(env) ? { state: "no_reader" } : { state: "off" };
}
