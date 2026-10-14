/**
 * The common-set snapshot (ADR-0020, issue #76): the image hashes seen on at least K hosts of
 * one tenant, as a Bloom filter the agent checks locally. Layout, hashing and sizing are
 * specified in `docs/detection/common-set-snapshot-format.md`; the Rust reader and a Python
 * reference are held to the same bytes by `ml/tests/fixtures/common_set_snapshot_golden.json`.
 */

const MAGIC = Buffer.from("SYCS", "ascii");
export const SNAPSHOT_FORMAT_VERSION = 1;
export const SNAPSHOT_HEADER_BYTES = 32;
const MIN_BITS = 64;
const MAX_HASH_COUNT = 16;
const SHA256 = /^[0-9a-f]{64}$/;
const ONE = BigInt(1);
const MASK64 = (ONE << BigInt(64)) - ONE;

/** The snapshot would exceed the caller's byte cap. Never silently truncated: a filter that
 * lost members would read common binaries as rare. Raise K or lower the target rate. */
export class SnapshotTooLargeError extends Error {
  constructor(
    readonly bytes: number,
    readonly maxBytes: number
  ) {
    super(`common-set snapshot would be ${bytes} bytes, over the cap of ${maxBytes}`);
    this.name = "SnapshotTooLargeError";
  }
}

/** The bytes are not a snapshot this reader understands. */
export class SnapshotFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SnapshotFormatError";
  }
}

export type SnapshotHeader = {
  formatVersion: number;
  hashCount: number;
  minHosts: number;
  hostsCovered: number;
  entryCount: number;
  bitCount: number;
  builtAt: number;
};

export type BuildInput = {
  /** Hashes already known to be on at least `minHosts` hosts. Normalized, deduplicated and
   * sorted here; anything that is not a SHA-256 is dropped. */
  hashes: Iterable<string>;
  minHosts: number;
  hostsCovered: number;
  /** Unix seconds. */
  builtAt: number;
  /** Target false-positive rate, strictly between 0 and 1. */
  falsePositiveRate: number;
  /** Refuse to build a snapshot larger than this, header included. */
  maxBytes?: number;
};

function normalize(value: string): string | null {
  const key = value.trim().toLowerCase();
  return SHA256.test(key) ? key : null;
}

function u32(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError(`${name} must be an integer in 0..2^32-1, got ${value}`);
  }
}

function sizing(entryCount: number, rate: number): { bitCount: number; hashCount: number } {
  if (entryCount === 0) return { bitCount: MIN_BITS, hashCount: 1 };
  const ideal = Math.ceil((entryCount * Math.log(1 / rate)) / Math.LN2 ** 2);
  const bitCount = Math.max(MIN_BITS, Math.ceil(ideal / 8) * 8);
  const hashCount = Math.min(
    MAX_HASH_COUNT,
    Math.max(1, Math.floor((bitCount / entryCount) * Math.LN2 + 0.5))
  );
  return { bitCount, hashCount };
}

/** The bit positions of one hash: double hashing over the digest, which is already uniform. */
function positions(sha256: string, bitCount: number, hashCount: number): number[] {
  const raw = Buffer.from(sha256, "hex");
  const h1 = raw.readBigUInt64LE(0);
  const h2 = raw.readBigUInt64LE(8) | ONE;
  const bits = BigInt(bitCount);
  const out: number[] = [];
  for (let i = 0; i < hashCount; i++) {
    out.push(Number(((h1 + BigInt(i) * h2) & MASK64) % bits));
  }
  return out;
}

/**
 * Builds the snapshot for one tenant's common hashes. Pure and deterministic: the same set
 * gives the same bytes whatever its order or duplicates.
 *
 * @throws RangeError for a parameter out of range
 * @throws SnapshotTooLargeError when the result would pass `maxBytes`
 */
export function buildCommonSetSnapshot(input: BuildInput): Uint8Array {
  const { minHosts, hostsCovered, builtAt, falsePositiveRate, maxBytes } = input;
  if (!(falsePositiveRate > 0 && falsePositiveRate < 1)) {
    throw new RangeError(`falsePositiveRate must be in (0, 1), got ${falsePositiveRate}`);
  }
  if (!Number.isInteger(minHosts) || minHosts < 1) {
    throw new RangeError(`minHosts must be an integer >= 1, got ${minHosts}`);
  }
  u32("hostsCovered", hostsCovered);
  if (!Number.isInteger(builtAt) || builtAt < 0) {
    throw new RangeError(`builtAt must be a non-negative integer, got ${builtAt}`);
  }

  const normalized: string[] = [];
  for (const h of Array.from(input.hashes)) {
    const key = normalize(h);
    if (key !== null) normalized.push(key);
  }
  const unique = Array.from(new Set(normalized)).sort();
  u32("entry count", unique.length);
  const { bitCount, hashCount } = sizing(unique.length, falsePositiveRate);
  u32("bit count", bitCount);

  const total = SNAPSHOT_HEADER_BYTES + bitCount / 8;
  if (maxBytes !== undefined && total > maxBytes) throw new SnapshotTooLargeError(total, maxBytes);

  const out = Buffer.alloc(total);
  MAGIC.copy(out, 0);
  out.writeUInt16LE(SNAPSHOT_FORMAT_VERSION, 4);
  out.writeUInt16LE(hashCount, 6);
  out.writeUInt32LE(minHosts, 8);
  out.writeUInt32LE(hostsCovered, 12);
  out.writeUInt32LE(unique.length, 16);
  out.writeUInt32LE(bitCount, 20);
  out.writeBigUInt64LE(BigInt(builtAt), 24);
  for (const hash of unique) {
    for (const p of positions(hash, bitCount, hashCount)) {
      out[SNAPSHOT_HEADER_BYTES + (p >> 3)] |= 1 << (p & 7);
    }
  }
  return out;
}

export type ParsedSnapshot = {
  header: SnapshotHeader;
  /** Whether a normalized SHA-256 reads as a member. A non-member may read as one. */
  contains: (sha256: string) => boolean;
};

/**
 * Reads a snapshot. Strict: an unknown magic or version, an out-of-range size or a length that
 * is not exactly header plus body is an error, never a guess.
 *
 * @throws SnapshotFormatError
 */
export function parseCommonSetSnapshot(bytes: Uint8Array): ParsedSnapshot {
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (buf.length < SNAPSHOT_HEADER_BYTES) throw new SnapshotFormatError("shorter than the header");
  if (!buf.subarray(0, 4).equals(MAGIC)) throw new SnapshotFormatError("bad magic");
  const formatVersion = buf.readUInt16LE(4);
  if (formatVersion !== SNAPSHOT_FORMAT_VERSION) {
    throw new SnapshotFormatError(`unknown format version ${formatVersion}`);
  }
  const header: SnapshotHeader = {
    formatVersion,
    hashCount: buf.readUInt16LE(6),
    minHosts: buf.readUInt32LE(8),
    hostsCovered: buf.readUInt32LE(12),
    entryCount: buf.readUInt32LE(16),
    bitCount: buf.readUInt32LE(20),
    builtAt: Number(buf.readBigUInt64LE(24)),
  };
  if (header.hashCount < 1 || header.hashCount > MAX_HASH_COUNT) {
    throw new SnapshotFormatError(`hash count ${header.hashCount} out of range`);
  }
  if (header.bitCount < MIN_BITS || header.bitCount % 8 !== 0) {
    throw new SnapshotFormatError(`bit count ${header.bitCount} out of range`);
  }
  if (buf.length !== SNAPSHOT_HEADER_BYTES + header.bitCount / 8) {
    throw new SnapshotFormatError("length does not match the header");
  }
  return {
    header,
    contains: (sha256) => {
      const key = normalize(sha256);
      if (key === null) return false;
      return positions(key, header.bitCount, header.hashCount).every(
        (p) => (buf[SNAPSHOT_HEADER_BYTES + (p >> 3)] >> (p & 7)) & 1
      );
    },
  };
}
