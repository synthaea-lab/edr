import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { S3Client } from "@aws-sdk/client-s3";
import { S3LakeReader } from "@/lib/lake-s3-store";
import { searchFailure } from "@/lib/hunt-search";

/**
 * The search deadline against the real AWS SDK, not a fake client (PR #1113 review): a local server
 * accepts the connection and never answers, so only the AbortSignal can end the request. The SDK
 * rejects with its own `AbortError` (cause = the signal's reason); the reader must turn that into
 * the signal's reason, which `searchFailure` maps to a 504 and not a 500.
 */
describe("S3LakeReader with the real SDK against a server that never answers", () => {
  let server: Server;
  let endpoint: string;
  const sockets = new Set<Socket>();
  let requests = 0;

  beforeAll(async () => {
    server = createServer(() => {
      requests += 1; // never respond
    });
    server.on("connection", (s) => {
      sockets.add(s);
      s.on("close", () => sockets.delete(s));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    sockets.forEach((s) => s.destroy());
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function reader(): S3LakeReader {
    const client = new S3Client({
      region: "us-east-1",
      endpoint,
      forcePathStyle: true,
      credentials: { accessKeyId: "test", secretAccessKey: "test" },
      maxAttempts: 1,
    });
    return new S3LakeReader({ bucket: "lake", client });
  }

  it("a listing that hits the deadline rejects with the signal's reason, a 504", async () => {
    const signal = AbortSignal.timeout(300);
    const error = await reader().list("tenant=t1/", { signal }).then(() => null, (e: unknown) => e);
    expect(error).toBe(signal.reason);
    expect((error as Error).name).toBe("TimeoutError");
    expect(searchFailure(error).status).toBe(504);
  });

  it("a read that hits the deadline rejects with the signal's reason, a 504", async () => {
    const signal = AbortSignal.timeout(300);
    const error = await reader()
      .get("tenant=t1/date=2026-11-01/type=process/part-0.parquet", { signal })
      .then(() => null, (e: unknown) => e);
    expect(error).toBe(signal.reason);
    expect(searchFailure(error).status).toBe(504);
  });

  it("the request did reach the server: the call was cut by the signal, not refused up front", async () => {
    const before = requests;
    const signal = AbortSignal.timeout(300);
    await reader().list("tenant=t1/", { signal }).then(() => null, () => null);
    expect(requests).toBeGreaterThan(before);
  });
});
