"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

interface Props {
  caseId: string;
  label: string;
}

export function GenerateNarrativeButton({ caseId, label }: Props) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    setPending(true);
    setError(null);
    try {
      const res = await fetch(`/api/cases/${caseId}/narrative/regenerate`, {
        method: "POST",
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `Request failed with status ${res.status}`);
      }
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Narrative generation failed");
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
        {pending ? "Generating…" : label}
      </button>
      {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
    </div>
  );
}
