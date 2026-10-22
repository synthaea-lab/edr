import { formatTime } from "@/lib/hunt-view";
import type { CaseRow, DetectionRow, SearchPage } from "@/lib/hunt-search";

/**
 * The rows of one page of a search (#61). Plain server markup: every string is rendered as text,
 * so what an analyst or an attacker put in a case title or a rule title cannot become markup.
 */
function DetectionTable({ rows }: { rows: DetectionRow[] }) {
  return (
    <table className="min-w-full text-sm">
      <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
        <tr>
          <th className="px-4 py-2">Time</th>
          <th className="px-4 py-2">Technique</th>
          <th className="px-4 py-2">Severity</th>
          <th className="px-4 py-2">Detection</th>
          <th className="px-4 py-2">Host</th>
          <th className="px-4 py-2">Case</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-100">
        {rows.map((row) => (
          <tr key={row.id}>
            <td className="px-4 py-2 text-gray-600">{formatTime(new Date(row.timestamp))}</td>
            <td className="px-4 py-2 font-mono text-xs text-gray-900">{row.technique}</td>
            <td className="px-4 py-2 text-gray-900">{row.severity}</td>
            <td className="px-4 py-2 text-gray-700">{row.title ?? "–"}</td>
            <td className="px-4 py-2 font-mono text-xs text-gray-600" title={row.agentId}>{row.agentId.slice(0, 8)}</td>
            <td className="px-4 py-2">
              {row.caseId ? (
                <a href={`/console/cases/${row.caseId}`} className="text-indigo-700 hover:underline">
                  {row.caseTitle ?? "case"}
                </a>
              ) : (
                <span className="text-gray-500">not grouped</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CaseTable({ rows }: { rows: CaseRow[] }) {
  return (
    <table className="min-w-full text-sm">
      <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
        <tr>
          <th className="px-4 py-2">Opened</th>
          <th className="px-4 py-2">Case</th>
          <th className="px-4 py-2">Severity</th>
          <th className="px-4 py-2">Status</th>
          <th className="px-4 py-2 text-right">Detections</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-100">
        {rows.map((row) => (
          <tr key={row.id}>
            <td className="px-4 py-2 text-gray-600">{formatTime(new Date(row.createdAt))}</td>
            <td className="px-4 py-2">
              <a href={`/console/cases/${row.id}`} className="text-indigo-700 hover:underline">{row.title}</a>
            </td>
            <td className="px-4 py-2 text-gray-900">{row.severity}</td>
            <td className="px-4 py-2 text-gray-900">{row.status}</td>
            <td className="px-4 py-2 text-right text-gray-900">{row.detectionCount}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function SearchResults({ page, olderHref }: { page: SearchPage; olderHref: string | null }) {
  const noun = page.source === "cases" ? "case" : "detection";
  return (
    <div>
      {page.total !== null && (
        <p className="mb-2 text-sm text-gray-600">
          {page.total} {noun}
          {page.total === 1 ? "" : "s"} match
          {page.total === 1 ? "es" : ""}.
        </p>
      )}
      {page.rows.length === 0 ? (
        <div className="rounded-lg bg-gray-50 p-6 text-center text-sm text-gray-600">Nothing matches.</div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          {page.source === "cases" ? <CaseTable rows={page.rows} /> : <DetectionTable rows={page.rows} />}
        </div>
      )}
      {olderHref && (
        <p className="mt-3 text-sm">
          <a href={olderHref} className="text-indigo-700 hover:underline">Older →</a>
        </p>
      )}
    </div>
  );
}
