import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { CreateBucketCommand, DeleteBucketCommand, DeleteObjectsCommand, ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { parquetReadObjects } from "hyparquet";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { lakeStoreFromEnv } from "@/lib/lake-env";
import type { LakeStore } from "@/lib/lake-store";
import { drainLakeQueue, enqueueLakeBatch } from "@/lib/lake-writer";
import { pruneLake } from "@/lib/lake-retention";

/**
 * Against a real S3-compatible server. Skipped unless LAKE_S3_TEST_ENDPOINT is set (for example
 * `http://127.0.0.1:8333` for a local SeaweedFS or RustFS): CI has no object store, so these do not
 * run there. LAKE_S3_TEST_ACCESS_KEY / LAKE_S3_TEST_SECRET_KEY default to a dummy pair, for servers
 * that do not check credentials.
 */
const ENDPOINT = process.env.LAKE_S3_TEST_ENDPOINT;
const ACCESS = process.env.LAKE_S3_TEST_ACCESS_KEY ?? "lake-test";
const SECRET = process.env.LAKE_S3_TEST_SECRET_KEY ?? "lake-test-secret";

const DAY = 86_400_000;
const NOW = new Date(Date.UTC(2026, 9, 29, 12, 0, 0));
const BUCKET = `lake-it-${randomUUID().slice(0, 8)}`;
const admin = ENDPOINT
  ? new S3Client({ region: "us-east-1", endpoint: ENDPOINT, forcePathStyle: true, credentials: { accessKeyId: ACCESS, secretAccessKey: SECRET } })
  : null;

function storeFor(prefix = ""): LakeStore {
  const store = lakeStoreFromEnv({
    LAKE_S3_BUCKET: BUCKET,
    LAKE_S3_ENDPOINT: ENDPOINT,
    LAKE_S3_ACCESS_KEY_ID: ACCESS,
    LAKE_S3_SECRET_ACCESS_KEY: SECRET,
    LAKE_S3_PREFIX: prefix,
  });
  if (!store) throw new Error("lake is off");
  return store;
}

async function emptyBucket() {
  let token: string | undefined;
  do {
    const page = await admin!.send(new ListObjectsV2Command({ Bucket: BUCKET, ContinuationToken: token }));
    const keys = (page.Contents ?? []).map((o) => ({ Key: o.Key! }));
    if (keys.length) await admin!.send(new DeleteObjectsCommand({ Bucket: BUCKET, Delete: { Objects: keys, Quiet: true } }));
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
}

describe.skipIf(!ENDPOINT)("the lake on an S3-compatible server", () => {
  beforeAll(async () => {
    await admin!.send(new CreateBucketCommand({ Bucket: BUCKET }));
  });
  beforeEach(async () => {
    await emptyBucket();
    await cleanDatabase();
    await prisma.lakeDeletion.deleteMany();
  });
  afterAll(async () => {
    await emptyBucket();
    await admin!.send(new DeleteBucketCommand({ Bucket: BUCKET })).catch(() => {});
    await prisma.lakeDeletion.deleteMany();
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("round-trips put, list and delete, and a missing key deletes quietly", async () => {
    const store = storeFor();
    const key = "tenant=t1/date=2026-10-29/type=exec/f.parquet";
    await store.put(key, new Uint8Array([1, 2, 3, 4]));
    expect(await store.list("tenant=t1/")).toEqual([{ key, size: 4 }]);
    expect(await store.list("tenant=t2/")).toEqual([]);
    await store.delete([key, key, "tenant=t1/date=2026-10-29/type=exec/never.parquet"]);
    expect(await store.list("")).toEqual([]);
  });

  it("lists and deletes past one page of 1000", async () => {
    const store = storeFor();
    const keys = Array.from({ length: 1005 }, (_, i) => `tenant=t1/date=2026-10-29/type=exec/f${String(i).padStart(4, "0")}.parquet`);
    for (let i = 0; i < keys.length; i += 50) await Promise.all(keys.slice(i, i + 50).map((k) => store.put(k, new Uint8Array(1))));
    expect((await store.list("tenant=t1/")).map((f) => f.key)).toEqual(keys);
    await store.delete(keys);
    expect(await store.list("")).toEqual([]);
  });

  it("keeps a prefix's objects apart from the rest of the bucket", async () => {
    const a = storeFor("prod");
    const b = storeFor("staging");
    const key = "tenant=t1/date=2026-10-29/type=exec/f.parquet";
    await a.put(key, new Uint8Array(1));
    await b.put(key, new Uint8Array(2));
    expect(await a.list("")).toEqual([{ key, size: 1 }]);
    expect(await b.list("")).toEqual([{ key, size: 2 }]);
    await a.delete([key]);
    expect(await a.list("")).toEqual([]);
    expect(await b.list("")).toEqual([{ key, size: 2 }]);
  });

  it("carries the writer and the retention job end to end: Parquet written, read back, then deleted with its record", async () => {
    const store = storeFor("lake");
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 30 } });
    const old = new Date(NOW.getTime() - 60 * DAY);
    const fresh = new Date(NOW.getTime() - 1 * DAY);
    const ev = (at: Date, image: string) => ({ type: "exec", meta: { comm: "bash", timestamp_ns: at.getTime() * 1_000_000 }, image_path: image });
    await enqueueLakeBatch(prisma, { tenantId: tenant.id, agentId: agent.id, events: [ev(old, "/old/a"), ev(fresh, "/fresh/a"), ev(fresh, "/fresh/b")], receivedAt: NOW });
    expect(await drainLakeQueue(prisma, store)).toMatchObject({ events: 3, files: 2, remaining: 0 });

    const listed = await store.list(`tenant=${tenant.id}/`);
    expect(listed).toHaveLength(2);
    const freshFile = listed.find((f) => f.key.includes("date=2026-10-28"))!;
    const got = await admin!.send(new (await import("@aws-sdk/client-s3")).GetObjectCommand({ Bucket: BUCKET, Key: `lake/${freshFile.key}` }));
    const bytes = await got.Body!.transformToByteArray();
    expect(bytes.byteLength).toBe(freshFile.size);
    const rows = (await parquetReadObjects({ file: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer })) as Record<string, unknown>[];
    expect(rows.map((r) => r.image_path).sort()).toEqual(["/fresh/a", "/fresh/b"]);

    const result = await pruneLake(prisma, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 1, filesDeleted: 1, notEmpty: 0 });
    expect((await store.list(`tenant=${tenant.id}/`)).map((f) => f.key)).toEqual([freshFile.key]);
    const record = await prisma.lakeDeletion.findFirstOrThrow();
    expect(record).toMatchObject({ tenantId: tenant.id, date: "2026-08-30", objectCount: 1, verifiedEmpty: true });
  });
});
