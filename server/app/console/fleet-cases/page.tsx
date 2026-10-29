import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { FLEET_CASE_LIST_LIMIT, listFleetCases } from "@/lib/fleet-case-load";
import { describeEntity, formatWhen, severityStyle, STATUS_LABEL } from "@/lib/fleet-case-view";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function FleetCasesPage() {
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

  const { cases, truncated } = await listFleetCases(prisma, tenantId);

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Fleet cases</h2>
        <p className="mt-1 text-sm text-gray-600">
          Detections of several hosts joined on something they share: a file hash or an account.
          A host&apos;s own detections are grouped in <a href="/console/cases" className="text-indigo-700 hover:underline">Cases</a>.
        </p>
      </div>

      {cases.length === 0 ? (
        <div className="rounded-lg bg-gray-50 p-8 text-center">
          <p className="text-gray-600">No fleet cases yet</p>
          <p className="mt-1 text-sm text-gray-500">
            One appears when detections of two hosts carry the same executed file or the same account.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">Fleet case</th>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Joined on</th>
                <th className="px-4 py-2 text-right">Hosts</th>
                <th className="px-4 py-2 text-right">Detections</th>
                <th className="px-4 py-2">First</th>
                <th className="px-4 py-2">Last</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {cases.map((c) => (
                <tr key={c.id}>
                  <td className="px-4 py-2 font-mono text-xs">
                    <a href={`/console/fleet-cases/${c.id}`} className="text-indigo-700 hover:underline">
                      {c.id.slice(0, 8)}
                    </a>
                  </td>
                  <td className="px-4 py-2">
                    <span className={`rounded border px-2 py-0.5 text-xs ${severityStyle(c.severity)}`}>{c.severity}</span>
                  </td>
                  <td className="px-4 py-2 text-gray-700">{STATUS_LABEL[c.status] ?? c.status}</td>
                  <td className="px-4 py-2 text-gray-700">
                    {c.entities.map((e) => {
                      const d = describeEntity(e);
                      return (
                        <span key={`${e.kind}:${e.key}`} title={d.title} className="mr-2 inline-block">
                          {d.label}
                        </span>
                      );
                    })}
                  </td>
                  <td className="px-4 py-2 text-right text-gray-900">{c.agentCount}</td>
                  <td className="px-4 py-2 text-right text-gray-900">{c.detectionCount}</td>
                  <td className="px-4 py-2 text-gray-700">{formatWhen(c.firstAt)}</td>
                  <td className="px-4 py-2 text-gray-700">{formatWhen(c.lastAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {truncated && (
        <p className="mt-3 text-sm text-gray-600">Only the {FLEET_CASE_LIST_LIMIT} most recent fleet cases are listed.</p>
      )}
    </div>
  );
}
