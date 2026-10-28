/**
 * Key-rotation manifest (ADR-0027): the document the offline `recovery` key signs to replace the
 * `release` and/or `content` key an agent trusts. This is the wire shape of
 * `crates/updater::KeyRotationManifest`. The server never signs one and never verifies the
 * signature (every agent does, against the `recovery` key it embeds); it serves the bytes of a
 * file an operator placed, after checking that the file is shaped like one.
 *
 * Where it is read from: `storage/key-rotations/<ring>.json`, one pending rotation per ring, so a
 * rotation can reach `canary_0` before `prod` the way a release does. A rotation names the key it
 * retires, so it applies to hosts on that key state only; with one file per ring the server
 * serves one state at a time, and an agent on another state refuses it harmlessly.
 */

import { readFile } from "fs/promises";
import path from "path";
import { z } from "zod";

const KEY_HEX = /^[a-f0-9]{64}$/;
/** Same ceiling as the agent's `MAX_VALIDITY_SECS` (30 days). */
const MAX_VALIDITY_SECS = 30 * 24 * 60 * 60;
const MAX_REASON_BYTES = 256;

const OptionalKey = z.string().regex(KEY_HEX).nullable();

export const KeyRotationManifest = z
  .object({
    expires_at: z.number().int().min(0),
    issued_at: z.number().int().min(0),
    new_content_key: OptionalKey,
    new_release_key: OptionalKey,
    reason: z.string(),
    release_version: z.number().int().min(1),
    retired_content_key: OptionalKey,
    retired_release_key: OptionalKey,
    schema_version: z.literal(1),
    /** Lowercase hex, checked by the agents, not here. */
    signature: z.string(),
  })
  // Unknown fields would sit outside the signed canonical form.
  .strict()
  .superRefine((m, ctx) => {
    const issue = (message: string) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, message });
    if ((m.new_release_key === null) !== (m.retired_release_key === null)) {
      issue("release key needs both a retired and a new key, or neither");
    }
    if ((m.new_content_key === null) !== (m.retired_content_key === null)) {
      issue("content key needs both a retired and a new key, or neither");
    }
    if (m.new_release_key === null && m.new_content_key === null) {
      issue("rotation changes no key");
    }
    if (m.reason.trim() === "" || Buffer.byteLength(m.reason) > MAX_REASON_BYTES) {
      issue("reason is empty or too long");
    }
    if (m.expires_at <= m.issued_at || m.expires_at - m.issued_at > MAX_VALIDITY_SECS) {
      issue("validity window is empty or longer than 30 days");
    }
  });

export type KeyRotationManifest = z.infer<typeof KeyRotationManifest>;

const RINGS = new Set(["canary_0", "canary_1", "canary_2", "prod"]);

/** Filesystem path of a ring's pending rotation, or `null` for a ring name that is not one. */
export function keyRotationFile(ring: string): string | null {
  if (!RINGS.has(ring)) return null;
  return path.join(process.cwd(), "storage", "key-rotations", `${ring}.json`);
}

export type LoadedRotation =
  | { ok: true; bytes: Buffer }
  | { ok: false; status: 404 | 502; error: string };

/**
 * Reads the pending rotation of `ring`. No file is 404 ("nothing to apply", not an error). A file
 * that is not valid JSON or not shaped like a rotation is a 502: a stored file that disagrees with
 * the contract is a server-side fault, never the agent's. The bytes are returned untouched.
 */
export async function loadKeyRotation(ring: string): Promise<LoadedRotation> {
  const file = keyRotationFile(ring);
  if (file === null) return { ok: false, status: 404, error: "No key rotation pending" };
  let bytes: Buffer;
  try {
    bytes = await readFile(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { ok: false, status: 404, error: "No key rotation pending" };
    }
    console.error("Key rotation read error:", error);
    return { ok: false, status: 502, error: "Key rotation unavailable" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf-8"));
  } catch {
    return { ok: false, status: 502, error: "Key rotation is not valid JSON" };
  }
  const validation = KeyRotationManifest.safeParse(parsed);
  if (!validation.success) {
    console.error("Key rotation shape validation error:", validation.error);
    return { ok: false, status: 502, error: "Key rotation does not match the expected schema" };
  }
  return { ok: true, bytes };
}
