import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { HUNT_RUNS_KEPT } from "@/lib/hunt";
import {
  describeQuery,
  describeSchedule,
  formatDuration,
  formatTime,
  ownerLabel,
  runState,
  STATE_LABEL,
  STATE_STYLE,
} from "@/lib/hunt-view";
import { RunHuntButton } from "@/components/RunHuntButton";
import { GraduateHuntButton } from "@/components/GraduateHuntButton";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function HuntPage({ params }: { params: { id: string } }) {
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

  // Scoped to the session's tenant: another tenant's hunt is a 404, never its contents.
  const hunt = await prisma.hunt.findFirst({ where: { id: params.id, tenantId } });
  if (!hunt) notFound();
  const runs = await prisma.huntRun.findMany({
    where: { huntId: hunt.id, tenantId },
    orderBy: { startedAt: "desc" },
    take: HUNT_RUNS_KEPT,
  });
  const now = new Date();

  return (
    <div>
      <a href="/console/hunts" className="text-sm text-indigo-700 hover:underline">
        ← Hunts
      </a>
      <div className="mt-2 mb-6 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">{hunt.name}</h2>
          {hunt.description && <p className="mt-1 text-sm text-gray-600">{hunt.description}</p>}
        </div>
        <div className="flex shrink-0 items-start gap-3">
          <a
            href={`/console/hunts/${hunt.id}/edit`}
            className="px-3 py-1.5 text-sm font-medium rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50"
          >
            Edit
          </a>
          <RunHuntButton huntId={hunt.id} />
        </div>
      </div>

      <dl className="mb-6 grid grid-cols-1 gap-4 rounded-lg border border-gray-200 bg-white p-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs uppercase text-gray-500">Query (version {hunt.version})</dt>
          <dd className="mt-1 text-gray-900">{describeQuery(hunt.query)}</dd>
          <dd className="mt-1">
            <pre className="overflow-x-auto rounded bg-gray-50 p-2 text-xs text-gray-700">
              {JSON.stringify(hunt.query, null, 2)}
            </pre>
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase text-gray-500">Schedule</dt>
          <dd className="mt-1 text-gray-900">{describeSchedule(hunt.scheduleMinutes, hunt.active)}</dd>
          <dt className="mt-3 text-xs uppercase text-gray-500">Created</dt>
          <dd className="mt-1 text-gray-900">
            {formatTime(hunt.createdAt)} by <span title={hunt.ownerId}>{ownerLabel(hunt.ownerId, session.user?.id)}</span>
          </dd>
        </div>
      </dl>

      <GraduateHuntButton huntId={hunt.id} />

      <h3 className="mb-2 text-lg font-semibold text-gray-900">History</h3>
      {runs.length === 0 ? (
        <p className="text-sm text-gray-600">This hunt has not run yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">Started</th>
                <th className="px-4 py-2">Result</th>
                <th className="px-4 py-2">Trigger</th>
                <th className="px-4 py-2">Query</th>
                <th className="px-4 py-2">Took</th>
                <th className="px-4 py-2 text-right">Matches</th>
                <th className="px-4 py-2 text-right">New</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {runs.map((run) => {
                const state = runState(run, now);
                return (
                  <tr key={run.id}>
                    <td className="px-4 py-2 text-gray-700">{formatTime(run.startedAt)}</td>
                    <td className="px-4 py-2">
                      <span className={`rounded border px-2 py-0.5 text-xs ${STATE_STYLE[state]}`}>
                        {STATE_LABEL[state]}
                      </span>
                      {run.error && <span className="ml-2 text-red-700">{run.error}</span>}
                    </td>
                    <td className="px-4 py-2 text-gray-700">{run.trigger}</td>
                    <td className="px-4 py-2 text-gray-700">v{run.queryVersion}</td>
                    <td className="px-4 py-2 text-gray-700">{formatDuration(run) ?? "–"}</td>
                    <td className="px-4 py-2 text-right text-gray-900">{state === "ok" ? run.matchCount : "–"}</td>
                    <td className="px-4 py-2 text-right text-gray-900">{state === "ok" ? run.newMatchCount : "–"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-3 text-xs text-gray-500">
        The newest {HUNT_RUNS_KEPT} runs are kept. A run that never finished (the server stopped
        while it ran) stays in the list as "Did not finish".
      </p>
    </div>
  );
}
