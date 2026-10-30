import { describe, expect, it } from "vitest";
import { DeleteObjectsCommand, GetBucketVersioningCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { FsLakeStore, LakeNotDeletableError, lakeEnabled } from "@/lib/lake-store";
import { S3LakeStore } from "@/lib/lake-s3-store";
import { lakeStoreFromEnv } from "@/lib/lake-env";

/** An in-memory bucket behind the one method the store uses, with pages of two and injectable delete errors (per key, or a whole request failing on its nth call). */
function fakeBucket(
  opts: { deleteErrors?: { Key: string; Code: string }[]; failDeleteCall?: number; versioning?: string | "denied" } = {}
) {
  let deleteCalls = 0;
  const objects = new Map<string, Uint8Array>();
  const sent: { name: string; input: Record<string, unknown> }[] = [];
  const client = {
    async send(command: unknown) {
      const c = command as { constructor: { name: string }; input: Record<string, any> };
      sent.push({ name: c.constructor.name, input: c.input });
      if (command instanceof PutObjectCommand) {
        objects.set(c.input.Key, c.input.Body);
        return {};
      }
      if (command instanceof ListObjectsV2Command) {
        const keys = Array.from(objects.keys()).filter((k) => k.startsWith(c.input.Prefix ?? "")).sort();
        const start = c.input.ContinuationToken ? Number(c.input.ContinuationToken) : 0;
        const page = keys.slice(start, start + 2);
        const more = start + 2 < keys.length;
        return {
          Contents: page.map((Key) => ({ Key, Size: objects.get(Key)!.byteLength })),
          IsTruncated: more,
          NextContinuationToken: more ? String(start + 2) : undefined,
        };
      }
      if (command instanceof DeleteObjectsCommand) {
        deleteCalls += 1;
        if (opts.failDeleteCall === deleteCalls) throw new Error("connection reset");
        const failing = new Set((opts.deleteErrors ?? []).map((e) => e.Key));
        for (const o of c.input.Delete.Objects) if (!failing.has(o.Key)) objects.delete(o.Key);
        return { Errors: opts.deleteErrors };
      }
      if (command instanceof GetBucketVersioningCommand) {
        if (opts.versioning === "denied") throw new Error("AccessDenied");
        return opts.versioning === undefined ? {} : { Status: opts.versioning };
      }
      throw new Error(`unexpected command ${c.constructor.name}`);
    },
  } as unknown as Pick<S3Client, "send">;
  return { client, objects, sent };
}

const KEY = (t: string, d = "2026-10-29", name = "f") => `tenant=${t}/date=${d}/type=exec/${name}.parquet`;

describe("S3LakeStore", () => {
  it("puts the bytes under the bucket, with the Parquet content type and the exact length", async () => {
    const { client, objects, sent } = fakeBucket();
    await new S3LakeStore({ bucket: "lake", client }).put(KEY("t1"), new Uint8Array([1, 2, 3]));
    expect(Array.from(objects.get(KEY("t1"))!)).toEqual([1, 2, 3]);
    expect(sent[0].input).toMatchObject({ Bucket: "lake", Key: KEY("t1"), ContentLength: 3, ContentType: "application/vnd.apache.parquet" });
  });

  it("keeps everything under the configured prefix, and hides the prefix from callers", async () => {
    const { client, objects } = fakeBucket();
    const store = new S3LakeStore({ bucket: "lake", prefix: "/prod/telemetry/", client });
    await store.put(KEY("t1"), new Uint8Array(4));
    expect(Array.from(objects.keys())).toEqual([`prod/telemetry/${KEY("t1")}`]);
    expect(await store.list("")).toEqual([{ key: KEY("t1"), size: 4 }]);
    expect(await store.list("tenant=t1/")).toEqual([{ key: KEY("t1"), size: 4 }]);
    expect(await store.delete([KEY("t1")])).toEqual({ deleted: [KEY("t1")], failed: [] });
    expect(objects.size).toBe(0);
  });

  it("does not list another prefix's objects in the same bucket", async () => {
    const { client, objects } = fakeBucket();
    objects.set("other/tenant=t9/date=2020-01-01/type=exec/x.parquet", new Uint8Array(1));
    const store = new S3LakeStore({ bucket: "lake", prefix: "prod", client });
    await store.put(KEY("t1"), new Uint8Array(1));
    expect((await store.list("")).map((f) => f.key)).toEqual([KEY("t1")]);
  });

  it("follows pagination and sorts, with sizes", async () => {
    const { client } = fakeBucket();
    const store = new S3LakeStore({ bucket: "lake", client });
    for (const n of ["e", "b", "d", "a", "c"]) await store.put(KEY("t1", "2026-10-29", n), new Uint8Array(n.charCodeAt(0) - 96));
    const listed = await store.list("tenant=t1/");
    expect(listed.map((f) => f.key.slice(-9, -8))).toEqual(["a", "b", "c", "d", "e"]);
    expect(listed.map((f) => f.size)).toEqual([1, 2, 3, 4, 5]);
  });

  it("does not let a prefix match half a segment", async () => {
    const { client } = fakeBucket();
    const store = new S3LakeStore({ bucket: "lake", client });
    await store.put(KEY("t1"), new Uint8Array(1));
    await store.put(KEY("t10"), new Uint8Array(1));
    expect((await store.list("tenant=t1/")).map((f) => f.key)).toEqual([KEY("t1")]);
  });

  it("deletes in batches of at most 1000", async () => {
    const { client, sent } = fakeBucket();
    const store = new S3LakeStore({ bucket: "lake", client });
    const keys = Array.from({ length: 2500 }, (_, i) => KEY("t1", "2026-10-29", `f${i}`));
    await store.delete(keys);
    const sizes = sent.filter((s) => s.name === "DeleteObjectsCommand").map((s) => (s.input.Delete as { Objects: unknown[] }).Objects.length);
    expect(sizes).toEqual([1000, 1000, 500]);
    expect(sent[0].input.Delete).toMatchObject({ Quiet: true });
  });

  it("reports a per-key delete error, which a 200 answer would otherwise hide, and the keys that did go", async () => {
    const { client, objects } = fakeBucket({ deleteErrors: [{ Key: KEY("t1", "2026-10-29", "b"), Code: "AccessDenied" }] });
    const store = new S3LakeStore({ bucket: "lake", client });
    for (const n of ["a", "b", "c"]) await store.put(KEY("t1", "2026-10-29", n), new Uint8Array(1));
    const result = await store.delete(["a", "b", "c"].map((n) => KEY("t1", "2026-10-29", n)));
    expect(result.deleted).toEqual([KEY("t1", "2026-10-29", "a"), KEY("t1", "2026-10-29", "c")]);
    expect(result.failed).toEqual([{ key: KEY("t1", "2026-10-29", "b"), error: "AccessDenied" }]);
    expect(Array.from(objects.keys())).toEqual([KEY("t1", "2026-10-29", "b")]);
  });

  it("when a later batch fails outright, keeps the earlier batches as deleted and does not try the rest", async () => {
    const { client, objects, sent } = fakeBucket({ failDeleteCall: 2 });
    const store = new S3LakeStore({ bucket: "lake", client });
    const keys = Array.from({ length: 2500 }, (_, i) => KEY("t1", "2026-10-29", `f${i}`));
    for (const k of keys.slice(0, 5)) objects.set(k, new Uint8Array(1));
    const result = await store.delete(keys);
    expect(result.deleted).toHaveLength(1000);
    expect(result.failed).toHaveLength(1500);
    expect(result.failed[0]).toEqual({ key: keys[1000], error: "connection reset" });
    expect(result.failed[1000].error).toBe("not attempted: connection reset");
    expect(sent.filter((s) => s.name === "DeleteObjectsCommand")).toHaveLength(2);
  });

  it("refuses a key that could escape, before sending anything", async () => {
    const { client, sent } = fakeBucket();
    const store = new S3LakeStore({ bucket: "lake", client });
    for (const bad of ["../x", "/abs", "a//b", "a b", ""]) {
      await expect(store.put(bad, new Uint8Array(1))).rejects.toThrow(/Unsafe lake key/);
      await expect(store.delete([bad])).rejects.toThrow(/Unsafe lake key/);
    }
    await expect(store.list("../")).rejects.toThrow(/Unsafe lake key/);
    expect(sent).toHaveLength(0);
  });

  it("needs a bucket, and a safe prefix", () => {
    const { client } = fakeBucket();
    expect(() => new S3LakeStore({ bucket: "", client })).toThrow(/bucket/);
    expect(() => new S3LakeStore({ bucket: "b", prefix: "../x", client })).toThrow(/Unsafe lake key/);
  });
});

describe("S3LakeStore.assertDeletable", () => {
  const store = (opts: Parameters<typeof fakeBucket>[0]) => {
    const bucket = fakeBucket(opts);
    return { bucket, store: new S3LakeStore({ bucket: "lake", client: bucket.client }) };
  };

  it("passes on a bucket that never had versioning, and asks once for the bucket's status", async () => {
    const { bucket, store: s } = store({});
    await expect(s.assertDeletable()).resolves.toBeUndefined();
    expect(bucket.sent.map((c) => [c.name, c.input.Bucket])).toEqual([["GetBucketVersioningCommand", "lake"]]);
  });

  it.each(["Enabled", "Suspended"])("refuses a bucket whose versioning is %s", async (status) => {
    const { store: s } = store({ versioning: status });
    await expect(s.assertDeletable()).rejects.toBeInstanceOf(LakeNotDeletableError);
    await expect(s.assertDeletable()).rejects.toThrow(new RegExp(status));
  });

  it("refuses when the status cannot be read, instead of assuming it is off", async () => {
    const { store: s } = store({ versioning: "denied" });
    await expect(s.assertDeletable()).rejects.toThrow(/s3:GetBucketVersioning/);
  });
});

describe("lakeEnabled and lakeStoreFromEnv", () => {
  it("is off unless a directory or a bucket is configured", () => {
    expect(lakeEnabled({})).toBe(false);
    expect(lakeEnabled({ LAKE_DIR: "", LAKE_S3_BUCKET: "" })).toBe(false);
    expect(lakeEnabled({ LAKE_DIR: "/d" })).toBe(true);
    expect(lakeEnabled({ LAKE_S3_BUCKET: "b" })).toBe(true);
    expect(lakeStoreFromEnv({})).toBeNull();
  });

  it("picks the directory or the bucket, and refuses both", () => {
    expect(lakeStoreFromEnv({ LAKE_DIR: "/d" })).toBeInstanceOf(FsLakeStore);
    expect(lakeStoreFromEnv({ LAKE_S3_BUCKET: "b", LAKE_S3_ACCESS_KEY_ID: "k", LAKE_S3_SECRET_ACCESS_KEY: "s" })).toBeInstanceOf(S3LakeStore);
    expect(() => lakeStoreFromEnv({ LAKE_DIR: "/d", LAKE_S3_BUCKET: "b" })).toThrow(/not both/);
  });

  it("refuses half a credential pair and a wrong path-style value", () => {
    expect(() => lakeStoreFromEnv({ LAKE_S3_BUCKET: "b", LAKE_S3_ACCESS_KEY_ID: "k" })).toThrow(/set together/);
    expect(() => lakeStoreFromEnv({ LAKE_S3_BUCKET: "b", LAKE_S3_SECRET_ACCESS_KEY: "s" })).toThrow(/set together/);
    expect(() => lakeStoreFromEnv({ LAKE_S3_BUCKET: "b", LAKE_S3_FORCE_PATH_STYLE: "yes" })).toThrow(/"true" or "false"/);
  });

  it("reuses the S3 store for the same configuration and builds another for a different one", () => {
    const env = { LAKE_S3_BUCKET: "b", LAKE_S3_ACCESS_KEY_ID: "k", LAKE_S3_SECRET_ACCESS_KEY: "s" };
    expect(lakeStoreFromEnv(env)).toBe(lakeStoreFromEnv({ ...env }));
    expect(lakeStoreFromEnv({ ...env, LAKE_S3_BUCKET: "other" })).not.toBe(lakeStoreFromEnv(env));
  });
});
