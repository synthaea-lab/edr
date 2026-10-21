"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  deleteConfirmation,
  deleteResponseMessage,
  isSignInRedirect,
  SESSION_EXPIRED_MESSAGE,
} from "@/lib/hunt-view";

/** Deletes a saved hunt and its run history after a confirmation (#61), then refreshes the list. */
export function DeleteHuntButton({ huntId, name }: { huntId: string; name: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  async function handleClick() {
    if (!window.confirm(deleteConfirmation(name))) return;
    setPending(true);
    setProblem(null);
    try {
      const res = await fetch(`/api/hunts/${huntId}`, { method: "DELETE" });
      if (isSignInRedirect(res)) {
        setProblem(SESSION_EXPIRED_MESSAGE);
        return;
      }
      const message = deleteResponseMessage(res.status, await res.json().catch(() => null));
      if (message) setProblem(message);
      else router.refresh();
    } catch {
      setProblem("The request did not reach the server");
    } finally {
      setPending(false);
    }
  }

  return (
    <span>
      <button
        onClick={handleClick}
        disabled={pending}
        aria-label={`Delete ${name}`}
        className="text-sm text-red-700 hover:underline disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {pending ? "Deleting…" : "Delete"}
      </button>
      {problem && <span className="ml-2 text-xs text-red-600">{problem}</span>}
    </span>
  );
}
