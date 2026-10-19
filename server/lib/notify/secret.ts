import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * A channel's signing secret is used (to sign), so it cannot be a hash: it is stored with
 * AES-256-GCM under a server key, the channel id as associated data, and the key id kept next
 * to the ciphertext so the key can rotate (ADR-0036 point 5).
 *
 * `NOTIFY_SECRET_KEY` is `<keyId>:<64 hex>`; `NOTIFY_SECRET_KEY_PREVIOUS` may hold older keys,
 * comma-separated in the same form, for decryption only. An unset key disables channel
 * creation: `currentKey()` returns null and the caller refuses, it never stores in clear.
 */
export interface SealedSecret {
  keyId: string;
  /** base64 of `iv(12) || tag(16) || ciphertext`. */
  sealed: string;
}

interface Key {
  id: string;
  bytes: Buffer;
}

function parseKey(entry: string): Key | null {
  const m = /^([A-Za-z0-9_-]{1,16}):([0-9a-fA-F]{64})$/.exec(entry.trim());
  return m ? { id: m[1], bytes: Buffer.from(m[2], "hex") } : null;
}

export function currentKey(env: NodeJS.ProcessEnv = process.env): Key | null {
  return env.NOTIFY_SECRET_KEY ? parseKey(env.NOTIFY_SECRET_KEY) : null;
}

function keyById(id: string, env: NodeJS.ProcessEnv): Key | null {
  const all = [env.NOTIFY_SECRET_KEY, ...(env.NOTIFY_SECRET_KEY_PREVIOUS ?? "").split(",")];
  for (const entry of all) {
    const k = entry ? parseKey(entry) : null;
    if (k?.id === id) return k;
  }
  return null;
}

export function sealSecret(
  secret: string,
  channelId: string,
  env: NodeJS.ProcessEnv = process.env
): SealedSecret | null {
  const key = currentKey(env);
  if (!key) return null;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key.bytes, iv);
  cipher.setAAD(Buffer.from(channelId));
  const ct = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return { keyId: key.id, sealed: Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64") };
}

/** Returns null when the key is gone or the ciphertext does not authenticate for this channel. */
export function openSecret(
  value: SealedSecret,
  channelId: string,
  env: NodeJS.ProcessEnv = process.env
): string | null {
  const key = keyById(value.keyId, env);
  if (!key) return null;
  try {
    const raw = Buffer.from(value.sealed, "base64");
    if (raw.length < 28) return null;
    const decipher = createDecipheriv("aes-256-gcm", key.bytes, raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(channelId));
    decipher.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}
