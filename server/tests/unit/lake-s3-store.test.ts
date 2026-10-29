import { describe, expect, it } from "vitest";
import { DeleteObjectsCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { FsLakeStore, lakeEnabled } from "@/lib/lake-store";
import { S3LakeStore } from "@/lib/lake-s3-store";
import { lakeStoreFromEnv } from "@/lib/lake-env";

/** An in-memory bucket behind the one method the store uses, with pages of two and injectable delete errors. */
function fakeBucket(opts: { deleteErrors?: { Key: string; Code: string }[] } = {}) {
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
        for (const o of c.input.Delete.Objects) objects.delete(o.Key);
        return { Errors: opts.deleteErrors };
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
    await store.delete([KEY("t1")]);
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

  it("fails when S3 reports a per-key delete error, which a 200 would otherwise hide", async () => {
    const { client } = fakeBucket({ deleteErrors: [{ Key: KEY("t1"), Code: "AccessDenied" }] });
    await expect(new S3LakeStore({ bucket: "lake", client }).delete([KEY("t1")])).rejects.toThrow(/1 of 1 keys.*AccessDenied/);
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
