import { afterEach, describe, expect, it, vi } from "vitest";
import { DeleteObjectsCommand, GetBucketVersioningCommand, GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { FsLakeStore, LakeNotDeletableError, lakeEnabled } from "@/lib/lake-store";
import { S3LakeReader, S3LakeStore } from "@/lib/lake-s3-store";
import { lakeReaderFromEnv, lakeStoreFromEnv, s3Settings } from "@/lib/lake-env";
import { queryLake } from "@/lib/lake-query";
import { searchFailure } from "@/lib/hunt-search";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

/** An in-memory bucket behind the one method the store uses, with pages of two and injectable delete errors (per key, or a whole request failing on its nth call). */
function fakeBucket(
  opts: { deleteErrors?: { Key: string; Code: string }[]; failDeleteCall?: number; versioning?: string | "denied"; delayMs?: number } = {}
) {
  let deleteCalls = 0;
  const objects = new Map<string, Uint8Array>();
  const sent: { name: string; input: Record<string, unknown> }[] = [];
  const client = {
    async send(command: unknown, options?: { abortSignal?: AbortSignal }) {
      const c = command as { constructor: { name: string }; input: Record<string, any> };
      sent.push({ name: c.constructor.name, input: c.input });
      // A slow store: the call takes `delayMs`, and is abandoned when `abortSignal` fires. Like the real SDK it rejects with an
      // AbortError whose `cause` is the signal's reason, not with the reason itself.
      if (opts.delayMs !== undefined) {
        const signal = options?.abortSignal;
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(resolve, opts.delayMs);
          const abort = () => (clearTimeout(timer), reject(Object.assign(new Error("Request aborted"), { name: "AbortError", cause: signal?.reason })));
          if (signal?.aborted) abort();
          else signal?.addEventListener("abort", abort, { once: true });
        });
      }
      if (command instanceof PutObjectCommand) {
        objects.set(c.input.Key, c.input.Body);
        return {};
      }
      if (command instanceof ListObjectsV2Command) {
        const keys = Array.from(objects.keys()).filter((k) => k.startsWith(c.input.Prefix ?? "")).sort();
        const start = c.input.ContinuationToken ? Number(c.input.ContinuationToken) : 0;
        const size = Math.min(2, c.input.MaxKeys ?? 2);
        const page = keys.slice(start, start + size);
        const more = start + size < keys.length;
        return {
          Contents: page.map((Key) => ({ Key, Size: objects.get(Key)!.byteLength })),
          IsTruncated: more,
          NextContinuationToken: more ? String(start + size) : undefined,
        };
      }
      if (command instanceof GetObjectCommand) {
        const body = objects.get(c.input.Key);
        if (body === undefined) throw new Error("NoSuchKey");
        return { Body: { transformToByteArray: async () => body } };
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

describe("S3LakeReader", () => {
  const filled = async (prefix?: string) => {
    const b = fakeBucket();
    const writer = new S3LakeStore({ bucket: "lake", prefix, client: b.client });
    for (const n of ["a", "b", "c", "d", "e"]) await writer.put(KEY("t1", "2026-10-29", n), new Uint8Array([n.charCodeAt(0)]));
    await writer.put(KEY("t2"), new Uint8Array([9]));
    return { ...b, reader: new S3LakeReader({ bucket: "lake", prefix, client: b.client }) };
  };

  it("lists a prefix across pages, in key order, with sizes", async () => {
    const { reader } = await filled();
    const files = await reader.list("tenant=t1/");
    expect(files.map((f) => f.key)).toEqual(["a", "b", "c", "d", "e"].map((n) => KEY("t1", "2026-10-29", n)));
    expect(files.every((f) => f.size === 1)).toBe(true);
  });

  it("with a limit asks for MaxKeys and stops at the first files", async () => {
    const { reader, sent } = await filled();
    sent.length = 0;
    const files = await reader.list("tenant=t1/", { limit: 3 });
    expect(files.map((f) => f.key)).toEqual(["a", "b", "c"].map((n) => KEY("t1", "2026-10-29", n)));
    const lists = sent.filter((s) => s.name === "ListObjectsV2Command");
    expect(lists.map((l) => l.input.MaxKeys)).toEqual([3, 1]);
    expect(lists).toHaveLength(2);
  });

  it("rejects a limit that is not a positive integer", async () => {
    const { reader } = await filled();
    await expect(reader.list("", { limit: 0 })).rejects.toThrow(RangeError);
    await expect(reader.list("", { limit: 1.5 })).rejects.toThrow(RangeError);
  });

  it("reads the bytes at a key, under the lake prefix, and refuses an unsafe key", async () => {
    const { reader, sent } = await filled("lake1");
    expect(Array.from(await reader.get(KEY("t1", "2026-10-29", "b")))).toEqual([98]);
    expect(sent.at(-1)!.input.Key).toBe(`lake1/${KEY("t1", "2026-10-29", "b")}`);
    await expect(reader.get("../x")).rejects.toThrow(/Unsafe lake key/);
    await expect(reader.get(KEY("t1", "2026-10-29", "zz"))).rejects.toThrow(/NoSuchKey/);
  });

  it("hides the lake prefix from listings and never lists outside it", async () => {
    const { reader } = await filled("lake1");
    expect((await reader.list("")).map((f) => f.key)).toHaveLength(6);
    expect((await reader.list("tenant=t2/")).map((f) => f.key)).toEqual([KEY("t2")]);
  });

  it("sends nothing but list and get", async () => {
    const { reader, sent } = await filled();
    sent.length = 0;
    await reader.list("");
    await reader.get(KEY("t2"));
    expect(new Set(sent.map((s) => s.name))).toEqual(new Set(["ListObjectsV2Command", "GetObjectCommand"]));
  });
});

describe("the search deadline over a slow S3 store", () => {
  // A store that never answers within the test: only the signal ends the call.
  const SLOW = 60_000;

  it("a reader abandons a listing and a read in flight and rejects with the signal's reason, a 504", async () => {
    const b = fakeBucket({ delayMs: SLOW });
    const reader = new S3LakeReader({ bucket: "lake", client: b.client });
    for (const run of [
      (signal: AbortSignal) => reader.list("tenant=t1/", { signal }),
      (signal: AbortSignal) => reader.get(KEY("t1"), { signal }),
    ]) {
      const signal = AbortSignal.timeout(20);
      const error = await run(signal).then(() => null, (e: unknown) => e);
      expect(error).toBe(signal.reason);
      expect((error as Error).name).toBe("TimeoutError");
      expect(searchFailure(error).status).toBe(504);
    }
    expect(b.sent.map((s) => s.name)).toEqual(["ListObjectsV2Command", "GetObjectCommand"]);
  });

  it("without the fix the SDK's AbortError would be a 500: the fake rejects like the SDK", async () => {
    const b = fakeBucket({ delayMs: SLOW });
    const signal = AbortSignal.timeout(20);
    const raw = await b.client.send(new ListObjectsV2Command({ Bucket: "lake" }), { abortSignal: signal }).then(() => null, (e: unknown) => e);
    expect((raw as Error).name).toBe("AbortError");
    expect((raw as Error & { cause: unknown }).cause).toBe(signal.reason);
    expect(searchFailure(raw).status).toBe(500);
  });

  it("a directory read rejects with the signal's reason too", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "lake-abort-"));
    try {
      const store = new FsLakeStore(dir);
      await store.put(KEY("t1"), new Uint8Array([1]));
      const controller = new AbortController();
      const read = store.get(KEY("t1"), { signal: controller.signal });
      controller.abort(new DOMException("deadline", "TimeoutError"));
      const error = await read.then(() => null, (e: unknown) => e);
      // The read may have finished before the abort was seen; if it failed, it failed with the reason.
      if (error !== null) {
        expect(error).toBe(controller.signal.reason);
        expect(searchFailure(error).status).toBe(504);
      }
      const late = await store.get(KEY("t1"), { signal: controller.signal }).then(() => null, (e: unknown) => e);
      expect(late).toBe(controller.signal.reason);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses to start a request once the signal is already aborted", async () => {
    const b = fakeBucket();
    const reader = new S3LakeReader({ bucket: "lake", client: b.client });
    const controller = new AbortController();
    controller.abort(new Error("deadline"));
    await expect(reader.list("", { signal: controller.signal })).rejects.toThrow("deadline");
    await expect(reader.get(KEY("t1"), { signal: controller.signal })).rejects.toThrow("deadline");
    expect(b.sent).toHaveLength(0);
  });

  it("a search over 90 days and many types stops at its deadline with a 504, after one listing", async () => {
    const b = fakeBucket({ delayMs: SLOW });
    const reader = new S3LakeReader({ bucket: "lake", client: b.client });
    const error = await queryLake(reader, {
      tenantId: "t1",
      from: "2026-08-01",
      to: "2026-10-29",
      types: ["exec", "connect", "dns"],
      signal: AbortSignal.timeout(20),
    }).then(() => null, (e: unknown) => e);
    expect((error as Error).name).toBe("TimeoutError");
    expect(searchFailure(error).status).toBe(504);
    // Unbounded, there would be one listing per day and type: 270.
    expect(b.sent.filter((s) => s.name === "ListObjectsV2Command")).toHaveLength(1);
  });
});

describe("lakeReaderFromEnv", () => {
  it("is null when the lake is off, a directory reader for LAKE_DIR, an S3 reader for a bucket", () => {
    expect(lakeReaderFromEnv({})).toBeNull();
    expect(lakeReaderFromEnv({ LAKE_DIR: "/d" })).toBeInstanceOf(FsLakeStore);
    expect(lakeReaderFromEnv({ LAKE_S3_BUCKET: "b" })).toBeInstanceOf(S3LakeReader);
    expect(() => lakeReaderFromEnv({ LAKE_DIR: "/d", LAKE_S3_BUCKET: "b" })).toThrow(/not both/);
  });

  it("takes its own credential pair, both or neither, never the writer's", () => {
    expect(() => lakeReaderFromEnv({ LAKE_S3_BUCKET: "b", LAKE_S3_READER_ACCESS_KEY_ID: "k" })).toThrow(/LAKE_S3_READER_ACCESS_KEY_ID and LAKE_S3_READER_SECRET_ACCESS_KEY must be set together/);
    // The writer's pair alone is not a reader configuration: it is neither used nor an error.
    expect(lakeReaderFromEnv({ LAKE_S3_BUCKET: "b", LAKE_S3_ACCESS_KEY_ID: "w", LAKE_S3_SECRET_ACCESS_KEY: "w" })).toBeInstanceOf(S3LakeReader);
  });

  it("pins the credentials the reader is built with: its own pair, and the writer's never", () => {
    const writer = { LAKE_S3_BUCKET: "b", LAKE_S3_ACCESS_KEY_ID: "w-id", LAKE_S3_SECRET_ACCESS_KEY: "w-secret" };
    const READER = { id: "LAKE_S3_READER_ACCESS_KEY_ID", secret: "LAKE_S3_READER_SECRET_ACCESS_KEY" };
    // The writer's pair alone: the reader gets no explicit credentials (the default chain), not the writer's.
    const alone = s3Settings(writer, READER);
    expect(alone.accessKeyId).toBeUndefined();
    expect(alone.secretAccessKey).toBeUndefined();
    // Both pairs: the reader's wins, the writer's does not leak in.
    const both = s3Settings({ ...writer, LAKE_S3_READER_ACCESS_KEY_ID: "r-id", LAKE_S3_READER_SECRET_ACCESS_KEY: "r-secret" }, READER);
    expect(both.accessKeyId).toBe("r-id");
    expect(both.secretAccessKey).toBe("r-secret");
    // And the writer's own settings still read the writer's pair.
    expect(s3Settings(writer).accessKeyId).toBe("w-id");
  });

  describe("the default credential chain", () => {
    afterEach(() => vi.restoreAllMocks());

    it("warns once that the default chain can have write rights when no pair is set at all", () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const env = { LAKE_S3_BUCKET: "warn-default-chain" };
      lakeReaderFromEnv(env);
      lakeReaderFromEnv({ ...env });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toMatch(/default credential chain.*write and delete rights/);
    });

    it("warns when the writer has an explicit pair and the reader has none, naming variables and never values", () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      lakeReaderFromEnv({ LAKE_S3_BUCKET: "warn-writer-pair", LAKE_S3_ACCESS_KEY_ID: "w-id-value", LAKE_S3_SECRET_ACCESS_KEY: "w-secret-value" });
      expect(warn).toHaveBeenCalledTimes(1);
      const text = String(warn.mock.calls[0][0]);
      expect(text).toContain("LAKE_S3_READER_ACCESS_KEY_ID");
      expect(text).not.toMatch(/w-id-value|w-secret-value/);
    });

    it("does not warn when the reader has its own pair, or for a directory", () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      lakeReaderFromEnv({ LAKE_S3_BUCKET: "warn-reader-pair", LAKE_S3_READER_ACCESS_KEY_ID: "r", LAKE_S3_READER_SECRET_ACCESS_KEY: "s" });
      lakeReaderFromEnv({ LAKE_DIR: "/d" });
      expect(warn).not.toHaveBeenCalled();
    });
  });

  it("builds a different reader when the reader credentials change", () => {
    const env = { LAKE_S3_BUCKET: "b", LAKE_S3_READER_ACCESS_KEY_ID: "r", LAKE_S3_READER_SECRET_ACCESS_KEY: "s" };
    expect(lakeReaderFromEnv(env)).toBe(lakeReaderFromEnv({ ...env }));
    expect(lakeReaderFromEnv({ ...env, LAKE_S3_READER_ACCESS_KEY_ID: "r2" })).not.toBe(lakeReaderFromEnv(env));
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
