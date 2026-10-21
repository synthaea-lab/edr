"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { isSignInRedirect } from "@/lib/notify/sign-in-redirect";

type Props = {
  mode: "create" | "row";
  channelId?: string;
  status?: string;
  failedRows?: number;
  hunts?: { id: string; name: string }[];
};

const EVENT_LABELS: Record<string, string> = {
  "host.degraded": "Host degraded",
  "host.silent": "Host silent",
  "host.recovered": "Host recovered",
  "hunt.new_matches": "Hunt has new matches",
};

/** Admin controls of the notifications page. The API enforces the role: this only hides what would be refused. */
export default function NotificationChannelActions({ mode, channelId, status, failedRows = 0, hunts = [] }: Props) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<string[]>(["host.degraded", "host.silent", "host.recovered"]);
  const [huntIds, setHuntIds] = useState<string[]>([]);

  async function call(path: string, method: string, body?: unknown) {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fetch(path, {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (isSignInRedirect(res)) {
        setMessage("Your session has ended: sign in again, then retry.");
        return { ok: false, json: {} };
      }
      const json = await res.json().catch(() => ({}));
      if (!res.ok) setMessage(json.error ?? `Failed (${res.status})`);
      return { ok: res.ok, json };
    } finally {
      setBusy(false);
    }
  }

  if (mode === "create") {
    const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
    return (
      <form
        className="space-y-3 rounded-lg border border-gray-200 bg-white p-4"
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await call("/api/notify/channels", "POST", { url, events, huntIds });
          if (r.ok) {
            setSecret(r.json.secret);
            setUrl("");
            router.refresh();
          }
        }}
      >
        <h3 className="text-sm font-semibold text-gray-900">Add a webhook</h3>
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://receiver.example.com/hook"
          className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
        />
        <fieldset className="flex flex-wrap gap-4 text-sm text-gray-700">
          {Object.entries(EVENT_LABELS).map(([ev, label]) => (
            <label key={ev} className="flex items-center gap-1">
              <input type="checkbox" checked={events.includes(ev)} onChange={() => setEvents(toggle(events, ev))} />
              {label}
            </label>
          ))}
        </fieldset>
        {events.includes("hunt.new_matches") && (
          <div className="text-sm text-gray-700">
            <p className="mb-1">Hunts this webhook receives:</p>
            {hunts.length === 0 ? (
              <p className="text-gray-500">No saved hunt yet.</p>
            ) : (
              hunts.map((h) => (
                <label key={h.id} className="mr-4 inline-flex items-center gap-1">
                  <input type="checkbox" checked={huntIds.includes(h.id)} onChange={() => setHuntIds(toggle(huntIds, h.id))} />
                  {h.name}
                </label>
              ))
            )}
          </div>
        )}
        <button disabled={busy} className="rounded bg-gray-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50">
          Add webhook
        </button>
        {message && <p className="text-sm text-red-700">{message}</p>}
        {secret && <SecretNotice secret={secret} />}
      </form>
    );
  }

  const path = `/api/notify/channels/${channelId}`;
  const act = async (action: string) => {
    const r = await call(path, "PATCH", { action });
    if (r.ok) {
      if (r.json.secret) setSecret(r.json.secret);
      router.refresh();
    }
  };
  const btn = "rounded border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50";
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        <button
          className={btn}
          disabled={busy}
          onClick={async () => {
            const r = await call(`${path}/test`, "POST");
            if (r.ok) setMessage(r.json.ok ? `Test sent (HTTP ${r.json.statusCode})` : `Test failed: ${r.json.errorClass}${r.json.statusCode ? ` (HTTP ${r.json.statusCode})` : ""}`);
          }}
        >
          Send test
        </button>
        {status === "active" ? (
          <button className={btn} disabled={busy} onClick={() => act("disable")}>Disable</button>
        ) : (
          <button className={btn} disabled={busy} onClick={() => act("enable")}>Re-enable</button>
        )}
        {failedRows > 0 && (
          <button className={btn} disabled={busy} onClick={() => act("resend_failed")}>
            Send {failedRows} failed again
          </button>
        )}
        <button className={btn} disabled={busy} onClick={() => act("rotate_secret")}>Rotate secret</button>
        <button
          className={`${btn} text-red-700`}
          disabled={busy}
          onClick={async () => {
            if (!confirm("Delete this webhook and its queued notifications?")) return;
            const r = await call(path, "DELETE");
            if (r.ok) router.refresh();
          }}
        >
          Delete
        </button>
      </div>
      {message && <p className="text-xs text-gray-700">{message}</p>}
      {secret && <SecretNotice secret={secret} />}
    </div>
  );
}

function SecretNotice({ secret }: { secret: string }) {
  return (
    <div className="rounded border border-yellow-300 bg-yellow-50 p-2 text-xs text-yellow-900">
      Signing secret, shown once: <code className="break-all font-mono">{secret}</code>
    </div>
  );
}
