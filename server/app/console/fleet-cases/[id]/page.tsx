import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { FLEET_CASE_DETECTIONS_LIMIT, loadFleetCase } from "@/lib/fleet-case-load";
import { describeEntity, formatWhen, severityStyle, STATUS_LABEL } from "@/lib/fleet-case-view";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function FleetCasePage({ params }: { params: { id: string } }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const tenantId = session.session.activeOrganizationId;
  if (!tenantId) {
    return (
      <div className="rounded-lg bg-yellow-50 p-4">
        <p className="text-sm text-yellow-800">
          No organization selected. Please contact your administrator.
        </p>
      </div>
    );
  }

  // Scoped to the session's tenant: another tenant's fleet case is a 404, never its contents.
  const fleetCase = await loadFleetCase(prisma, tenantId, params.id);
  if (!fleetCase) notFound();
  const hostname = new Map(fleetCase.agents.map((a) => [a.id, a.hostname]));

  return (
    <div>
      <a href="/console/fleet-cases" className="text-sm text-indigo-700 hover:underline">
        ← Fleet cases
      </a>
      <div className="mt-2 mb-6 flex items-center gap-3">
        <h2 className="text-2xl font-bold text-gray-900">Fleet case {fleetCase.id.slice(0, 8)}</h2>
        <span className={`rounded border px-2 py-0.5 text-xs ${severityStyle(fleetCase.severity)}`}>{fleetCase.severity}</span>
        <span className="text-sm text-gray-600">{STATUS_LABEL[fleetCase.status] ?? fleetCase.status}</span>
      </div>

      <dl className="mb-6 grid grid-cols-1 gap-4 rounded-lg border border-gray-200 bg-white p-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs uppercase text-gray-500">Joined on</dt>
          {fleetCase.entities.map((e) => {
            const d = describeEntity(e);
            return (
              <dd key={`${e.kind}:${e.key}`} className="mt-1 text-gray-900">
                <span className="text-gray-600">{e.kind === "sha256" ? "file hash" : e.kind === "identity" ? "account" : e.kind}</span>{" "}
                <code className="break-all text-xs" title={d.title}>{e.key}</code>
              </dd>
            );
          })}
        </div>
        <div>
          <dt className="text-xs uppercase text-gray-500">Hosts ({fleetCase.agentCount})</dt>
          {fleetCase.agents.map((a) => (
            <dd key={a.id} className="mt-1 text-gray-900">{a.hostname ?? a.id}</dd>
          ))}
          <dt className="mt-3 text-xs uppercase text-gray-500">Between</dt>
          <dd className="mt-1 text-gray-900">
            {formatWhen(fleetCase.firstAt)} and {formatWhen(fleetCase.lastAt)}
          </dd>
        </div>
      </dl>

      <h3 className="mb-2 text-lg font-semibold text-gray-900">Detections</h3>
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-2">Time</th>
              <th className="px-4 py-2">Host</th>
              <th className="px-4 py-2">Technique</th>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">Host case</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {fleetCase.detections.map((d) => (
              <tr key={d.id}>
                <td className="px-4 py-2 text-gray-700">{formatWhen(d.timestamp)}</td>
                <td className="px-4 py-2 text-gray-900">{hostname.get(d.agentId) ?? d.agentId}</td>
                <td className="px-4 py-2 text-gray-900">{d.technique}</td>
                <td className="px-4 py-2">
                  <span className={`rounded border px-2 py-0.5 text-xs ${severityStyle(d.severity)}`}>{d.severity}</span>
                </td>
                <td className="px-4 py-2">
                  {d.caseId ? (
                    <a href={`/console/cases/${d.caseId}`} className="text-indigo-700 hover:underline">
                      open
                    </a>
                  ) : (
                    <span className="text-gray-500">none yet</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {fleetCase.detectionsTruncated && (
        <p className="mt-3 text-sm text-gray-600">Only the first {FLEET_CASE_DETECTIONS_LIMIT} detections are listed.</p>
      )}
    </div>
  );
}
