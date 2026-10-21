"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { isSignInRedirect, runResponseMessage, runSummary, SESSION_EXPIRED_MESSAGE } from "@/lib/hunt-view";

export function RunHuntButton({ huntId }: { huntId: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null);

  async function handleClick() {
    setPending(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/hunts/${huntId}/run`, { method: "POST" });
      if (isSignInRedirect(res)) {
        setMessage({ text: SESSION_EXPIRED_MESSAGE, ok: false });
        return;
      }
      const body = await res.json().catch(() => ({}));
      const problem = runResponseMessage(res.status, body);
      setMessage(problem ? { text: problem, ok: false } : { text: runSummary(body), ok: true });
      router.refresh();
    } catch {
      setMessage({ text: "The request did not reach the server", ok: false });
    } finally {
      setPending(false);
    }
  }

  return (
    <div>
      <button
        onClick={handleClick}
        disabled={pending}
        className="px-3 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {pending ? "Running…" : "Run now"}
      </button>
      {message && (
        <p className={`mt-2 text-sm ${message.ok ? "text-green-700" : "text-red-600"}`}>{message.text}</p>
      )}
    </div>
  );
}
