/**
 * What a content rollback does and does not do (ADR-0032, issue #665).
 *
 * A rollback reactivates an earlier release so that agents that have *not* yet applied the
 * rolled-back one get the earlier content. It cannot reach an agent that already applied it:
 * agents never go to a lower release number (anti-replay, ADR-0016), so such an agent keeps
 * the rolled-back content and reports "the server offers an older release". Withdrawing the
 * content from those agents takes a corrective release, numbered above every release of the
 * ring, that carries the earlier content again. The server never holds the signing key, so
 * the corrective release is built and signed offline (`release-tool roll-forward`, then
 * `release-tool sign --kind content`) and published through POST /api/content/release.
 */
export interface CorrectiveReleaseAdvice {
  /**
   * The number the corrective release must carry: the next one the control plane will assign
   * (`POST /api/content/release` numbers a release highest + 1, and the manifest route refuses a
   * manifest whose own `release_version` differs from its row's), which is above every release
   * of the ring, rolled back ones included.
   */
  releaseVersion: number;
  /** The release whose content the corrective release should carry. */
  restoreVersion: number;
  /** What the operator has to do, for the response and the audit trail. */
  note: string;
}

/**
 * @param highestVersion the highest `releaseVersion` of the ring, rolled back or not
 * @param restoreVersion the release the rollback reactivated
 */
export function correctiveReleaseAdvice(
  highestVersion: number,
  restoreVersion: number,
): CorrectiveReleaseAdvice {
  const releaseVersion = highestVersion + 1;
  return {
    releaseVersion,
    restoreVersion,
    note:
      `Agents that already applied a later release keep it: an agent never goes to a lower ` +
      `release number. To withdraw that content from them, sign and publish a corrective ` +
      `release numbered exactly ${releaseVersion} (the next number the control plane assigns) that carries release ${restoreVersion}'s ` +
      `content (release-tool roll-forward --from <release ${restoreVersion} manifest> ` +
      `--release-version ${releaseVersion}).`,
  };
}
