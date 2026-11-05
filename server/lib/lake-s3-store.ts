import {
  DeleteObjectsCommand,
  GetBucketVersioningCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import { assertSafeKey, LakeNotDeletableError, type DeleteResult, type LakeReader, type LakeStore } from "@/lib/lake-store";

/**
 * The lake on an S3-compatible object store (issue #77, ADR-0041): AWS S3, or MinIO in the
 * self-hosted compose. Same three methods as the directory store, so the writer and the retention
 * job do not know which one they have.
 *
 * Versioning must be off on the bucket: on a versioned bucket a delete leaves a delete marker and
 * the bytes stay, and `lake_deletions` would say "verified empty" about a prefix whose objects still
 * exist. `assertDeletable` checks it once per retention run and fails closed (ADR-0041, section 5):
 * `Enabled`, `Suspended` (earlier versions are kept) and a status that cannot be read all refuse.
 * It needs `s3:GetBucketVersioning` on the credentials the retention job uses.
 */

/** S3's per-request cap on `DeleteObjects`. */
const DELETE_BATCH = 1000;

export type S3LakeConfig = {
  bucket: string;
  /** A key prefix inside the bucket, without leading or trailing slash; "" for the bucket root. */
  prefix?: string;
  client: Pick<S3Client, "send">;
};

/** Maps lake keys to object keys under the optional prefix; shared by the writer's store and the reader. */
class S3Keys {
  readonly prefix: string;
  constructor(prefix: string | undefined) {
    const p = (prefix ?? "").replace(/^\/+|\/+$/g, "");
    if (p !== "") assertSafeKey(p);
    this.prefix = p;
  }
  full(key: string): string {
    return this.prefix === "" ? key : `${this.prefix}/${key}`;
  }
  /** The `Prefix` of a listing for a lake prefix, or undefined for the whole bucket. */
  listPrefix(prefix: string): string | undefined {
    const wanted = this.full(prefix);
    return wanted === "" ? undefined : this.prefix !== "" && prefix === "" ? `${this.prefix}/` : wanted;
  }
  strip(objectKey: string): string {
    return objectKey.slice(this.prefix === "" ? 0 : this.prefix.length + 1);
  }
}

/**
 * The query side of the lake on S3 (issue #1105, ADR-0041, decision 4). It is its own class, built on
 * its own client, and can only issue `ListObjectsV2` and `GetObject`: it has no write method to
 * misuse, and the credentials it is given should be read-only (`s3:ListBucket`, `s3:GetObject`),
 * ideally scoped to a tenant prefix, never the writer's.
 */
export class S3LakeReader implements LakeReader {
  private readonly bucket: string;
  private readonly keys: S3Keys;
  private readonly client: Pick<S3Client, "send">;

  constructor(config: S3LakeConfig) {
    if (!config.bucket) throw new Error("S3LakeReader needs a bucket");
    this.bucket = config.bucket;
    this.keys = new S3Keys(config.prefix);
    this.client = config.client;
  }

  async list(prefix: string, opts: { limit?: number; signal?: AbortSignal } = {}): Promise<{ key: string; size: number }[]> {
    if (prefix !== "") assertSafeKey(prefix.replace(/\/$/, ""));
    const { limit, signal } = opts;
    if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) throw new RangeError("list limit must be a positive integer");
    const objectPrefix = this.keys.listPrefix(prefix);
    const out: { key: string; size: number }[] = [];
    let token: string | undefined;
    do {
      signal?.throwIfAborted();
      // S3 lists in key order, so with a limit the first `limit` keys are the answer: ask for no more than are still wanted.
      // `abortSignal` abandons the request in flight, so a slow store cannot hold the caller past its deadline.
      let page;
      try {
        page = await this.client.send(
          new ListObjectsV2Command({
            Bucket: this.bucket,
            Prefix: objectPrefix,
            ContinuationToken: token,
            MaxKeys: limit === undefined ? undefined : limit - out.length,
          }),
          { abortSignal: signal }
        );
      } catch (e) {
        // The SDK rejects with an AbortError whose `cause` is the reason; the contract is the reason itself.
        if (signal?.aborted) throw signal.reason;
        throw e;
      }
      for (const object of page.Contents ?? []) {
        if (object.Key === undefined) continue;
        out.push({ key: this.keys.strip(object.Key), size: Number(object.Size ?? 0) });
      }
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token !== undefined && (limit === undefined || out.length < limit));
    return out.sort((a, b) => (a.key < b.key ? -1 : 1)).slice(0, limit);
  }

  async get(key: string, opts: { signal?: AbortSignal } = {}): Promise<Uint8Array> {
    assertSafeKey(key);
    const { signal } = opts;
    signal?.throwIfAborted();
    try {
      const res = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: this.keys.full(key) }), { abortSignal: signal });
      if (res.Body === undefined) throw new Error(`Lake object ${key} has no body`);
      const bytes = await res.Body.transformToByteArray();
      // Whether the SDK stops a body read on abort is not guaranteed: say so here.
      signal?.throwIfAborted();
      return bytes;
    } catch (e) {
      if (signal?.aborted) throw signal.reason;
      throw e;
    }
  }
}

export class S3LakeStore implements LakeStore {
  private readonly bucket: string;
  private readonly keys: S3Keys;
  private readonly client: Pick<S3Client, "send">;

  constructor(config: S3LakeConfig) {
    if (!config.bucket) throw new Error("S3LakeStore needs a bucket");
    this.bucket = config.bucket;
    this.keys = new S3Keys(config.prefix);
    this.client = config.client;
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    assertSafeKey(key);
    // An S3 PUT is atomic: a reader sees the whole object or none, so no temporary name is needed.
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: this.keys.full(key),
        Body: body,
        ContentLength: body.byteLength,
        ContentType: "application/vnd.apache.parquet",
      })
    );
  }

  async list(prefix: string): Promise<{ key: string; size: number }[]> {
    if (prefix !== "") assertSafeKey(prefix.replace(/\/$/, ""));
    // With no lake prefix and no wanted prefix, list the whole bucket.
    const objectPrefix = this.keys.listPrefix(prefix);
    const out: { key: string; size: number }[] = [];
    let token: string | undefined;
    do {
      const page = await this.client.send(
        new ListObjectsV2Command({ Bucket: this.bucket, Prefix: objectPrefix, ContinuationToken: token })
      );
      for (const object of page.Contents ?? []) {
        if (object.Key === undefined) continue;
        out.push({ key: this.keys.strip(object.Key), size: Number(object.Size ?? 0) });
      }
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token !== undefined);
    return out.sort((a, b) => (a.key < b.key ? -1 : 1));
  }

  async assertDeletable(): Promise<void> {
    let status: string | undefined;
    try {
      status = (await this.client.send(new GetBucketVersioningCommand({ Bucket: this.bucket }))).Status;
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      throw new LakeNotDeletableError(
        `Cannot read the versioning status of bucket ${this.bucket} (${error}); the retention job needs s3:GetBucketVersioning and deletes nothing without it`
      );
    }
    if (status !== undefined && status !== "") {
      throw new LakeNotDeletableError(
        `Bucket ${this.bucket} has versioning ${status}: a delete leaves the bytes behind a marker, so the deletion could not be proven. Nothing was deleted; turn versioning off or move the lake to an unversioned bucket`
      );
    }
  }

  async delete(keys: string[]): Promise<DeleteResult> {
    for (const key of keys) assertSafeKey(key);
    const result: DeleteResult = { deleted: [], failed: [] };
    for (let i = 0; i < keys.length; i += DELETE_BATCH) {
      const batch = keys.slice(i, i + DELETE_BATCH);
      let res;
      try {
        res = await this.client.send(
          new DeleteObjectsCommand({
            Bucket: this.bucket,
            Delete: { Objects: batch.map((key) => ({ Key: this.keys.full(key) })), Quiet: true },
          })
        );
      } catch (e) {
        // The request itself failed (network, credentials, a 5xx): nothing is known about this batch, and the
        // ones after it are not tried. Earlier batches are already gone and stay in `deleted`.
        const error = e instanceof Error ? e.message : String(e);
        for (const key of keys.slice(i)) result.failed.push({ key, error: key === batch[0] || batch.includes(key) ? error : `not attempted: ${error}` });
        return result;
      }
      // DeleteObjects answers 200 with a per-key error list: a missing key is not an error in S3, anything else is.
      const errors = new Map((res.Errors ?? []).map((e) => [e.Key, `${e.Code}${e.Message ? `: ${e.Message}` : ""}`] as const));
      for (const key of batch) {
        const error = errors.get(this.keys.full(key));
        if (error === undefined) result.deleted.push(key);
        else result.failed.push({ key, error });
      }
    }
    return result;
  }
}
