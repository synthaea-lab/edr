"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { SEVERITIES } from "@/lib/hunt";
import {
  EMPTY_HUNT_FORM,
  huntFormToBody,
  saveResponseMessage,
  type HuntFormValues,
} from "@/lib/hunt-form";

const INPUT = "mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-900";
const LABEL = "block text-sm font-medium text-gray-700";
const HINT = "mt-1 text-xs text-gray-500";

/** Creates a hunt (`huntId` absent) or changes one (`huntId` set). */
export function HuntForm({ huntId, initial }: { huntId?: string; initial?: HuntFormValues }) {
  const router = useRouter();
  const [values, setValues] = useState<HuntFormValues>(initial ?? EMPTY_HUNT_FORM);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function set<K extends keyof HuntFormValues>(key: K, value: HuntFormValues[K]) {
    setValues((current) => ({ ...current, [key]: value }));
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    const result = huntFormToBody(values);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setPending(true);
    try {
      const res = await fetch(huntId ? `/api/hunts/${huntId}` : "/api/hunts", {
        method: huntId ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(result.body),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(saveResponseMessage(res.status, body));
        return;
      }
      const saved = (body as { hunt?: { id?: string } }).hunt?.id ?? huntId;
      router.push(saved ? `/console/hunts/${saved}` : "/console/hunts");
      router.refresh();
    } catch {
      setError("The request did not reach the server");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-2xl space-y-5">
      <div>
        <label className={LABEL} htmlFor="hunt-name">Name</label>
        <input id="hunt-name" className={INPUT} value={values.name} maxLength={120} required
          onChange={(e) => set("name", e.target.value)} />
      </div>
      <div>
        <label className={LABEL} htmlFor="hunt-description">Description (optional)</label>
        <textarea id="hunt-description" className={INPUT} rows={2} value={values.description} maxLength={2000}
          onChange={(e) => set("description", e.target.value)} />
      </div>

      <fieldset className="space-y-4 rounded-lg border border-gray-200 p-4">
        <legend className="px-1 text-sm font-semibold text-gray-900">Query</legend>
        <div>
          <label className={LABEL} htmlFor="hunt-hours">Look back (hours)</label>
          <input id="hunt-hours" className={INPUT} inputMode="numeric" value={values.lastHours}
            onChange={(e) => set("lastHours", e.target.value)} />
          <p className={HINT}>From the start of each run, so a scheduled hunt keeps meaning “recently”. 1 to 2160 (90 days).</p>
        </div>
        <div>
          <label className={LABEL} htmlFor="hunt-techniques">ATT&amp;CK techniques</label>
          <input id="hunt-techniques" className={INPUT} placeholder="T1059, T1003.001" value={values.techniques}
            onChange={(e) => set("techniques", e.target.value)} />
          <p className={HINT}>T1059 also matches its sub-techniques; T1059.001 only itself. Empty: any.</p>
        </div>
        <div>
          <span className={LABEL}>Severities</span>
          <div className="mt-1 flex gap-4">
            {SEVERITIES.map((severity) => (
              <label key={severity} className="flex items-center gap-1.5 text-sm text-gray-700">
                <input type="checkbox" checked={values.severities.includes(severity)}
                  onChange={(e) =>
                    set("severities", e.target.checked
                      ? SEVERITIES.filter((s) => s === severity || values.severities.includes(s))
                      : values.severities.filter((s) => s !== severity))
                  } />
                {severity}
              </label>
            ))}
          </div>
          <p className={HINT}>None ticked: any severity.</p>
        </div>
        <div>
          <label className={LABEL} htmlFor="hunt-agents">Hosts (agent ids)</label>
          <textarea id="hunt-agents" className={`${INPUT} font-mono`} rows={2} value={values.agentIds}
            onChange={(e) => set("agentIds", e.target.value)} />
          <p className={HINT}>One per line or separated by commas. Empty: every host.</p>
        </div>
        <div>
          <label className={LABEL} htmlFor="hunt-text">Text</label>
          <input id="hunt-text" className={INPUT} value={values.text} maxLength={256}
            onChange={(e) => set("text", e.target.value)} />
          <p className={HINT}>A literal, case-insensitive substring of the detection’s event, 3 to 256 characters. Empty: no text filter.</p>
        </div>
      </fieldset>

      <div>
        <label className={LABEL} htmlFor="hunt-schedule">Run every (minutes)</label>
        <input id="hunt-schedule" className={INPUT} inputMode="numeric" value={values.scheduleMinutes}
          onChange={(e) => set("scheduleMinutes", e.target.value)} />
        <p className={HINT}>5 to 10080 (a week). Empty: manual only.</p>
      </div>
      <label className="flex items-center gap-2 text-sm text-gray-700">
        <input type="checkbox" checked={values.active} onChange={(e) => set("active", e.target.checked)} />
        Active (a paused hunt keeps its history and is not run on its schedule)
      </label>

      {huntId && (
        <p className="text-xs text-gray-500">
          Changing the query starts a new query version; past runs keep the query they ran.
        </p>
      )}
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      <div className="flex items-center gap-3">
        <button type="submit" disabled={pending}
          className="px-3 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed">
          {pending ? "Saving…" : huntId ? "Save changes" : "Create hunt"}
        </button>
        <a href={huntId ? `/console/hunts/${huntId}` : "/console/hunts"} className="text-sm text-gray-600 hover:underline">
          Cancel
        </a>
      </div>
    </form>
  );
}
