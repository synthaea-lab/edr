/**
 * Public-suffix check for the IOC feed builder (issue #60, ADR-0038).
 *
 * A listed domain covers every name beneath it, so one that is itself a public suffix (`co.uk`,
 * or a private one such as `blogspot.com`) would flag a whole registry or a hosting platform. This
 * is the `isPublicSuffix` callback `buildFeed` takes, backed by the Public Suffix List that ships
 * with `tldts`, private domains included.
 */

import { parse } from "tldts";

/**
 * Whether `name` (normalised, lowercase, no trailing dot) is exactly a public suffix. A name under
 * one (`evil.co.uk`), and a name whose last label the list does not know, are not.
 */
export function isPublicSuffix(name: string): boolean {
  const result = parse(name, { allowPrivateDomains: true, extractHostname: false });
  return result.domain === null && result.publicSuffix === name;
}
