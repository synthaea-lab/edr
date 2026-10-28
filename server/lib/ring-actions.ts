import type { Ring, RolloutState } from "@/lib/rings";

/**
 * What an operator may do to a content ring from the console (#898, #863 item 4), and what the
 * confirmation says. The actions call the existing admin routes (`POST /api/content/halt` and
 * `/rollback`), which check the role, write the `AuditLog` row and do the change: the console adds
 * no authority of its own. A one-click release is not here: who may publish is undecided.
 */
export type RingAction = "halt" | "rollback";

/**
 * Which actions make sense for a ring in this state. A halt needs a serving release. A rollback
 * needs a serving or halted ring *and* an earlier release to go back to (`hasEarlierRelease`):
 * the route answers 404 without one, so the button is not offered. Nothing is offered when
 * nothing was released or the latest release was already rolled back.
 */
export function availableActions(rollout: RolloutState, hasEarlierRelease: boolean): RingAction[] {
  switch (rollout) {
    case "serving":
      return hasEarlierRelease ? ["halt", "rollback"] : ["halt"];
    case "halted":
      return hasEarlierRelease ? ["rollback"] : [];
    default:
      return [];
  }
}

/** What the operator reads before confirming. */
export function confirmation(action: RingAction, ring: Ring, servedVersion: number | null): {
  title: string;
  body: string;
  /** Typing the ring's name is required when the action cannot be undone from the console. */
  mustType: string | null;
  confirmLabel: string;
} {
  if (action === "halt") {
    return {
      title: `Halt ${ring}`,
      body:
        `Agents of ${ring} stop being offered content${servedVersion === null ? "" : ` (now v${servedVersion})`} ` +
        `until a new release is published or the ring is rolled back. What an agent has already applied stays ` +
        `applied. This is recorded in the audit log under your name.`,
      mustType: null,
      confirmLabel: `Halt ${ring}`,
    };
  }
  return {
    title: `Roll back ${ring}`,
    body:
      `The earlier release becomes the one agents of ${ring} are offered, and the latest one is marked rolled back. ` +
      `This does not reach an agent that has already applied the rolled-back release: it never goes to a lower ` +
      `release number and stays on it. Withdrawing the content from those agents takes a corrective release, ` +
      `signed offline, which this page does not make; the answer names the number it must carry. ` +
      `This is recorded in the audit log under your name.`,
    mustType: ring,
    confirmLabel: `Roll back ${ring}`,
  };
}

/** True when what was typed is the ring's name (case and surrounding spaces ignored). */
export function confirmationMatches(typed: string, mustType: string | null): boolean {
  return mustType === null || typed.trim().toLowerCase() === mustType.toLowerCase();
}

/** What a member who is not an owner or an admin is told in place of the buttons. */
export const NON_ADMIN_NOTE = "Only an organization owner or admin can halt or roll back a ring.";
