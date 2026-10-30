import { mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

/**
 * Where the telemetry lake's files go (issue #77, ADR-0041). The ADR makes the S3 API the
 * interface; this slice ships the directory store only, so a lake can run on a mounted volume
 * and the writer can be tested without a service. An S3 store is the next slice and implements
 * the same one method.
 */
export interface LakeStore {
  /** Writes `body` at `key`, replacing a file already there: the writer's keys are deterministic, so a retry rewrites the same bytes. */
  put(key: string, body: Uint8Array): Promise<void>;
}

/** A key the writer built is `tenant=…/date=…/type=…/<id>.parquet`; anything that could leave the root is refused. */
const SAFE_KEY = /^[A-Za-z0-9=_.-]+(\/[A-Za-z0-9=_.-]+)*$/;

export function assertSafeKey(key: string): void {
  if (!SAFE_KEY.test(key) || key.split("/").some((part) => part === "." || part === "..")) {
    throw new Error(`Unsafe lake key: ${JSON.stringify(key)}`);
  }
}

/** Files under one directory. The write goes to a temporary name and is renamed, so a reader never lists half a file. */
export class FsLakeStore implements LakeStore {
  constructor(private readonly root: string) {
    if (!root) throw new Error("FsLakeStore needs a root directory");
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    assertSafeKey(key);
    const target = path.join(this.root, key);
    await mkdir(path.dirname(target), { recursive: true });
    const tmp = `${target}.tmp-${process.pid}`;
    await writeFile(tmp, body);
    await rename(tmp, target);
  }
}

/**
 * The store the environment asks for, or null when the lake is off. `LAKE_DIR` is the only switch:
 * unset (the default) means ingest queues nothing and the writer has nothing to do, so a
 * deployment that has no lake does not grow a queue nobody drains.
 */
export function lakeStoreFromEnv(env: Record<string, string | undefined> = process.env): LakeStore | null {
  const dir = env.LAKE_DIR;
  if (dir === undefined || dir === "") return null;
  return new FsLakeStore(dir);
}
