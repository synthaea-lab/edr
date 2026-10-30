import { S3Client } from "@aws-sdk/client-s3";
import { FsLakeStore, lakeEnabled, type LakeStore } from "@/lib/lake-store";
import { S3LakeStore } from "@/lib/lake-s3-store";

type Env = Record<string, string | undefined>;

/** The S3 settings, from the environment. Documented in `server/datalake/README.md`. */
function s3Settings(env: Env) {
  const bucket = env.LAKE_S3_BUCKET ?? "";
  const endpoint = env.LAKE_S3_ENDPOINT || undefined;
  const forcePath = env.LAKE_S3_FORCE_PATH_STYLE;
  if (forcePath !== undefined && forcePath !== "" && forcePath !== "true" && forcePath !== "false") {
    throw new Error(`LAKE_S3_FORCE_PATH_STYLE must be "true" or "false", got "${forcePath}"`);
  }
  const accessKeyId = env.LAKE_S3_ACCESS_KEY_ID || undefined;
  const secretAccessKey = env.LAKE_S3_SECRET_ACCESS_KEY || undefined;
  // One without the other is a misconfiguration, not a request for the default credential chain.
  if ((accessKeyId === undefined) !== (secretAccessKey === undefined)) {
    throw new Error("LAKE_S3_ACCESS_KEY_ID and LAKE_S3_SECRET_ACCESS_KEY must be set together");
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
  const client = new S3Client({
    region: s.region,
    endpoint: s.endpoint,
    forcePathStyle: s.forcePathStyle,
    credentials: s.accessKeyId && s.secretAccessKey ? { accessKeyId: s.accessKeyId, secretAccessKey: s.secretAccessKey } : undefined,
    // Newer SDKs add checksum headers by default; some S3-compatible stores reject them.
    requestChecksumCalculation: "WHEN_REQUIRED",
    responseChecksumValidation: "WHEN_REQUIRED",
  });
  const store = new S3LakeStore({ bucket: s.bucket, prefix: s.prefix, client });
  cached = { key, store };
  return store;
}
