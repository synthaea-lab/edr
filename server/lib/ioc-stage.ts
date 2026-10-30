/**
 * Turns one threat-intelligence source into the artifacts of an `ioc` content release
 * (issue #60, ADR-0038): `ioc/<feed>.txt` and, optionally, `ioc/VERSION`, each with the manifest
 * entry that lists it.
 *
 * This is the step between a source (plain `kind:value` text, CSV, a STIX bundle or a MISP export) and the unsigned content
 * manifest the operator signs offline (docs/operations/content.md). It builds the feed with the
 * same builder the device's rules come from, drops the lines the device would skip, and refuses
 * what would do harm if published:
 *
 * - an **empty** result. A source whose columns were mapped wrong, or a download that came back as
 *   an error page, leaves no indicator; a release that lists an empty feed unloads the set on every
 *   agent of the ring. Publishing that has to be asked for (`allowEmpty`).
 * - anything {@link iocEntryError} would refuse at publish, so a staged feed never fails there.
 *
 * Pure: no I/O; the clock is read only for a STIX source's lifetimes, and `now` replaces it. The caller writes the artifacts to the store.
 */

import { createHash } from "crypto";
import { buildFeed, versionFile, type FeedResult, type IocKind } from "@/lib/ioc-feed";
import { buildFeedFromCsv } from "@/lib/ioc-csv";
import { buildFeedFromStix } from "@/lib/ioc-stix";
import { buildFeedFromMisp } from "@/lib/ioc-misp";
import { iocEntryError } from "@/lib/content-publish";
import { isPublicSuffix as realIsPublicSuffix } from "@/lib/public-suffix";

/**
 * The largest request body `POST /api/content/ioc-feed` reads, in bytes. `nginx.conf` sets
 * `client_max_body_size` for that route to the same figure, so the proxy and the handler agree: a
 * body between nginx's default (1 MiB) and this is a feed, not an error. It sits under the builder's
 * own cap on the source text (`MAX_FEED_TEXT_BYTES`, 64 MiB) because a JSON body wraps the source in
 * quotes and escapes.
 */
export const MAX_STAGE_BODY_BYTES = 32 * 1024 * 1024;

export type StageSource =
  | { format: "plain"; text: string; defaultKind?: IocKind }
  | { format: "stix"; json: string }
  | { format: "misp"; json: string }
  | {
      format: "csv";
      csv: string;
      valueColumn: string | number;
      typeColumn?: string | number;
      defaultKind?: IocKind;
      hasHeader?: boolean;
    };

export interface StageInput {
  /** Feed name: becomes `ioc/<feed>.txt` and is printed in every finding the feed raises. */
  feed: string;
  /** Written to `ioc/VERSION`: names the release the feeds came from. Absent: no version file. */
  version?: string;
  source: StageSource;
  /** Publish a feed with no indicator in it, which unloads the set (default: refused). */
  allowEmpty?: boolean;
  /** Test seam; the instant a STIX source's lifetimes are judged against (the clock by default). */
  now?: Date;
  /** Test seam; the Public Suffix List by default. */
  isPublicSuffix?: (name: string) => boolean;
}

/** A manifest entry for an artifact, as the content manifest lists it. */
export interface StagedEntry {
  path: string;
  type: "ioc";
  sha256: string;
  size: number;
}

export interface StagedArtifact {
  entry: StagedEntry;
  bytes: Buffer;
}

export type StageReport = Pick<FeedResult, "read" | "counts" | "duplicates" | "rejected" | "rejectedTotal">;

export type StageResult =
  | { ok: true; artifacts: StagedArtifact[]; report: StageReport }
  | { ok: false; error: string };

function artifact(path: string, text: string): StagedArtifact {
  const bytes = Buffer.from(text, "utf8");
  return {
    entry: { path, type: "ioc", sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length },
    bytes,
  };
}

export function buildIocStage(input: StageInput): StageResult {
  const isPublicSuffix = input.isPublicSuffix ?? realIsPublicSuffix;
  let built: FeedResult;
  try {
    switch (input.source.format) {
      case "csv":
        built = buildFeedFromCsv({ ...input.source, feed: input.feed, isPublicSuffix });
        break;
      case "stix":
        built = buildFeedFromStix({ feed: input.feed, json: input.source.json, now: input.now ?? new Date(), isPublicSuffix });
        break;
      case "misp":
        built = buildFeedFromMisp({ feed: input.feed, json: input.source.json, isPublicSuffix });
        break;
      case "plain":
        built = buildFeed({ feed: input.feed, text: input.source.text, defaultKind: input.source.defaultKind, isPublicSuffix });
        break;
    }
  } catch (error) {
    // A bad feed name, a source over the size cap, a CSV column that is not there: the caller's
    // mistake, said plainly.
    if (error instanceof RangeError) return { ok: false, error: error.message };
    throw error;
  }

  if (built.counts.total === 0 && !input.allowEmpty) {
    return {
      ok: false,
      error:
        `No indicator survived (${built.read} read, ${built.rejectedTotal} rejected). Publishing an empty ` +
        `feed would unload the set on every agent of the ring, so it is refused; if that is the intent, ` +
        `ask for it with allowEmpty.`,
    };
  }

  const artifacts = [artifact(`ioc/${input.feed}.txt`, built.text)];
  if (input.version !== undefined) {
    try {
      artifacts.push(artifact("ioc/VERSION", versionFile(input.version)));
    } catch (error) {
      if (error instanceof RangeError) return { ok: false, error: error.message };
      throw error;
    }
  }

  // The builder's output is what the publish check accepts; this is the proof, not a second rule.
  for (const { entry, bytes } of artifacts) {
    const refused = iocEntryError(entry, bytes);
    if (refused !== null) return { ok: false, error: refused };
  }

  const { read, counts, duplicates, rejected, rejectedTotal } = built;
  return { ok: true, artifacts, report: { read, counts, duplicates, rejected, rejectedTotal } };
}
