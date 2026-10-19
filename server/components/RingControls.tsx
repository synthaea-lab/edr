"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { endedSession } from "@/lib/session-redirect";
import { availableActions, confirmation, confirmationMatches, type RingAction } from "@/lib/ring-actions";
import type { Ring, RolloutState } from "@/lib/rings";

type Props = { ring: Ring; rollout: RolloutState; servedVersion: number | null };

/**
 * Halt and roll back for one ring, for an owner or admin (the page does not render this for
 * anyone else; the routes refuse them anyway). Nothing happens on the first click: it opens the
 * confirmation, which says what the action does and does not do. A rollback also asks for the
 * ring's name. The page only calls `POST /api/content/halt` and `/rollback`.
 */
export default function RingControls({ ring, rollout, servedVersion }: Props) {
  const router = useRouter();
  const [open, setOpen] = useState<RingAction | null>(null);
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [advice, setAdvice] = useState<string | null>(null);

  const actions = availableActions(rollout);
  if (actions.length === 0) return null;

  const close = () => {
    setOpen(null);
    setReason("");
    setTyped("");
  };

  async function run(action: RingAction) {
    setBusy(true);
    setMessage(null);
    setAdvice(null);
    try {
      const res = await fetch(`/api/content/${action}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ring, ...(reason.trim() ? { reason: reason.trim() } : {}) }),
      });
      if (endedSession(res)) {
        setMessage("Your session has ended: sign in again, then retry.");
        return;
      }
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        setMessage(json.error ?? `Failed (${res.status})`);
        return;
      }
      setMessage(action === "halt" ? `${ring} halted.` : `${ring} rolled back.`);
      if (action === "rollback" && json.correctiveRelease?.note) setAdvice(json.correctiveRelease.note);
      close();
      router.refresh();
    } finally {
      setBusy(false);
    }
  }

  const plan = open ? confirmation(open, ring, servedVersion) : null;
  const btn = "rounded border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50";
  return (
    <div className="mt-3 space-y-2">
      {open === null && (
        <div className="flex gap-2">
          {actions.includes("halt") && (
            <button className={btn} onClick={() => setOpen("halt")}>
              Halt…
            </button>
          )}
          {actions.includes("rollback") && (
            <button className={`${btn} text-red-700`} onClick={() => setOpen("rollback")}>
              Roll back…
            </button>
          )}
        </div>
      )}
      {open !== null && plan && (
        <div role="alertdialog" aria-label={plan.title} className="space-y-2 rounded border border-orange-300 bg-orange-50 p-3 text-xs text-gray-800">
          <p className="font-semibold">{plan.title}</p>
          <p>{plan.body}</p>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason (kept in the audit log, optional)"
            maxLength={300}
            className="w-full rounded border border-gray-300 px-2 py-1"
          />
          {plan.mustType !== null && (
            <input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={`Type ${plan.mustType} to confirm`}
              aria-label={`Type ${plan.mustType} to confirm`}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono"
            />
          )}
          <div className="flex gap-2">
            <button
              className="rounded bg-red-700 px-2 py-1 text-white disabled:opacity-50"
              disabled={busy || !confirmationMatches(typed, plan.mustType)}
              onClick={() => run(open)}
            >
              {plan.confirmLabel}
            </button>
            <button className={btn} disabled={busy} onClick={close}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {message && <p className="text-xs text-gray-700">{message}</p>}
      {advice && <p className="rounded border border-yellow-300 bg-yellow-50 p-2 text-xs text-yellow-900">{advice}</p>}
    </div>
  );
}
