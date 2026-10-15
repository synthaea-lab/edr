"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { runResponseMessage } from "@/lib/hunt-view";

export function RunHuntButton({ huntId }: { huntId: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function handleClick() {
    setPending(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/hunts/${huntId}/run`, { method: "POST" });
      const body = await res.json().catch(() => ({}));
      setMessage(runResponseMessage(res.status, body));
      router.refresh();
    } catch {
      setMessage("The request did not reach the server");
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
      {message && <p className="mt-2 text-sm text-red-600">{message}</p>}
    </div>
  );
}
