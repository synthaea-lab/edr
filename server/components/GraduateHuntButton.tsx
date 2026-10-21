"use client";

import { useState } from "react";
import {
  draftDownloadName,
  graduationBody,
  graduationResult,
  isSignInRedirect,
  SESSION_EXPIRED_MESSAGE,
  type GraduationForm,
  type GraduationResult,
} from "@/lib/hunt-view";

const PLATFORMS: GraduationForm["platform"][] = ["linux", "windows", "macos"];

/**
 * "Draft Sigma rule" on a hunt (#618, #61's graduation box): asks for the assisted draft of the
 * hunt's newest finished run and shows its files and what a person still has to do. It writes
 * nothing: the files are copied or downloaded and go through the normal PR and CI path.
 */
export function GraduateHuntButton({ huntId }: { huntId: string }) {
  const [form, setForm] = useState<GraduationForm>({
    platform: "linux",
    negativeImage: "",
    negativeCmdline: "",
    negativeNote: "",
  });
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<GraduationResult | null>(null);
  const set = (patch: Partial<GraduationForm>) => setForm((f) => ({ ...f, ...patch }));

  async function handleClick() {
    setResult(null);
    const request = graduationBody(form);
    if (!request.ok) {
      setResult({ ok: false, message: request.message, problems: [] });
      return;
    }
    setPending(true);
    try {
      const res = await fetch(`/api/hunts/${huntId}/graduate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request.body),
      });
      if (isSignInRedirect(res)) {
        setResult({ ok: false, message: SESSION_EXPIRED_MESSAGE, problems: [] });
        return;
      }
      setResult(graduationResult(res.status, await res.json().catch(() => null)));
    } catch {
      setResult({ ok: false, message: "The request did not reach the server", problems: [] });
    } finally {
      setPending(false);
    }
  }

  function download(file: { path: string; content: string }) {
    const url = URL.createObjectURL(new Blob([file.content], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = draftDownloadName(file.path);
    link.click();
    URL.revokeObjectURL(url);
  }

  const input = "mt-1 w-full rounded-md border border-gray-300 px-2 py-1 text-sm";
  return (
    <section className="mb-6 rounded-lg border border-gray-200 bg-white p-4" aria-label="Draft a rule">
      <h3 className="text-lg font-semibold text-gray-900">Graduate to content</h3>
      <p className="mt-1 text-sm text-gray-600">
        A draft Sigma rule and its samples from this hunt&apos;s newest finished run. Nothing is
        saved or shipped: review the files and open a pull request.
      </p>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="text-sm text-gray-700">
          Platform
          <select
            className={`${input} block`}
            value={form.platform}
            onChange={(e) => set({ platform: e.target.value as GraduationForm["platform"] })}
          >
            {PLATFORMS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <button
          onClick={handleClick}
          disabled={pending}
          className="px-3 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {pending ? "Drafting…" : "Draft Sigma rule"}
        </button>
      </div>
      <details className="mt-3 text-sm text-gray-700">
        <summary className="cursor-pointer">A benign lookalike that must not fire (optional)</summary>
        <p className="mt-1 text-xs text-gray-500">
          Needed when the hunt has no text to derive one from. Give both fields or neither.
        </p>
        <label className="mt-2 block">
          Image
          <input className={input} value={form.negativeImage} onChange={(e) => set({ negativeImage: e.target.value })} />
        </label>
        <label className="mt-2 block">
          Command line
          <input className={input} value={form.negativeCmdline} onChange={(e) => set({ negativeCmdline: e.target.value })} />
        </label>
        <label className="mt-2 block">
          Note
          <input className={input} value={form.negativeNote} onChange={(e) => set({ negativeNote: e.target.value })} />
        </label>
      </details>
      {result && !result.ok && (
        <div className="mt-3 text-sm text-red-600" role="alert">
          <p>{result.message}</p>
          {result.problems.length > 0 && (
            <ul className="mt-1 list-disc pl-5">
              {result.problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      {result?.ok && (
        <div className="mt-3">
          {result.files.map((file) => (
            <div key={file.path} className="mb-3">
              <div className="flex items-center justify-between gap-3">
                <code className="text-xs text-gray-800">{file.path}</code>
                <span className="flex gap-3 text-xs">
                  <button className="text-indigo-700 hover:underline" onClick={() => navigator.clipboard?.writeText(file.content)}>
                    Copy
                  </button>
                  <button className="text-indigo-700 hover:underline" onClick={() => download(file)}>
                    Download
                  </button>
                </span>
              </div>
              <pre className="mt-1 overflow-x-auto rounded bg-gray-50 p-2 text-xs text-gray-700">{file.content}</pre>
            </div>
          ))}
          {result.todo.length > 0 && (
            <>
              <p className="text-sm font-medium text-gray-900">Still to do by a person</p>
              <ul className="mt-1 list-disc pl-5 text-sm text-gray-700">
                {result.todo.map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </section>
  );
}
