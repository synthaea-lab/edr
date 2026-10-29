import { mkdir, readdir, rename, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

/**
 * Where the telemetry lake's files go (issue #77, ADR-0041). The ADR makes the S3 API the
 * interface; the directory store is the only one built, so a lake can run on a mounted volume and
 * the writer and the retention job can be tested without a service. An S3 store implements the
 * same three methods.
 */
export interface LakeStore {
  /** Writes `body` at `key`, replacing a file already there: the writer's keys are deterministic, so a retry rewrites the same bytes. */
  put(key: string, body: Uint8Array): Promise<void>;
  /** Every file whose key starts with `prefix` (a whole path segment boundary, or ""), with its size in bytes. */
  list(prefix: string): Promise<{ key: string; size: number }[]>;
  /** Removes the files at `keys`. A key that is already gone is not an error: a retried deletion must finish. */
  delete(keys: string[]): Promise<void>;
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

  async list(prefix: string): Promise<{ key: string; size: number }[]> {
    if (prefix !== "") assertSafeKey(prefix.replace(/\/$/, ""));
    const out: { key: string; size: number }[] = [];
    const walk = async (rel: string): Promise<void> => {
      let entries;
      try {
        entries = await readdir(path.join(this.root, rel), { withFileTypes: true });
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
        throw e;
      }
      for (const entry of entries) {
        const key = rel === "" ? entry.name : `${rel}/${entry.name}`;
        if (entry.isDirectory()) {
          await walk(key);
        } else if (entry.isFile() && !entry.name.includes(".tmp-")) {
          if (key.startsWith(prefix)) out.push({ key, size: (await stat(path.join(this.root, key))).size });
        }
      }
    };
    // Start at the deepest whole directory of the prefix, so a tenant's listing does not walk the others.
    const start = prefix.includes("/") ? prefix.slice(0, prefix.lastIndexOf("/")) : "";
    await walk(start);
    return out.sort((a, b) => (a.key < b.key ? -1 : 1));
  }

  async delete(keys: string[]): Promise<void> {
    for (const key of keys) {
      assertSafeKey(key);
      try {
        await unlink(path.join(this.root, key));
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      }
      // Empty directories left behind go too, up to the root: an empty `date=` prefix must read as empty.
      let dir = path.dirname(path.join(this.root, key));
      while (dir !== path.resolve(this.root) && dir.startsWith(path.resolve(this.root))) {
        try {
          await rmdir(dir);
        } catch {
          break;
        }
        dir = path.dirname(dir);
      }
    }
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
