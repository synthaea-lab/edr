import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { describeQuery, describeSchedule, formatTime, runState, type RunState } from "@/lib/hunt-view";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

/** A tenant may have 200 hunts (ADR-0025); one more row says the list was cut. */
const LIST_LIMIT = 200;

const STATE_STYLE: Record<RunState, string> = {
  running: "bg-blue-100 text-blue-800 border-blue-200",
  ok: "bg-green-100 text-green-800 border-green-200",
  failed: "bg-red-100 text-red-800 border-red-200",
  interrupted: "bg-orange-100 text-orange-800 border-orange-200",
};

const STATE_LABEL: Record<RunState, string> = {
  running: "Running",
  ok: "Done",
  failed: "Failed",
  interrupted: "Did not finish",
};

export default async function HuntsPage() {
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

  // The newest two runs of each hunt: the newest says what is happening, and when it has not
  // produced a result yet (running, never finished) the one before it still has numbers to show.
  const found = await prisma.hunt.findMany({
    where: { tenantId },
    orderBy: { createdAt: "desc" },
    take: LIST_LIMIT + 1,
    include: { runs: { orderBy: { startedAt: "desc" }, take: 2 } },
  });
  const truncated = found.length > LIST_LIMIT;
  const hunts = found.slice(0, LIST_LIMIT);
  const now = new Date();

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Hunts</h2>
        <p className="mt-1 text-sm text-gray-600">
          Saved searches over the detection store, run by hand or on a schedule. A run counts the
          detections that match in its window, and how many of them arrived since the previous run.
        </p>
      </div>

      {hunts.length === 0 ? (
        <div className="rounded-lg bg-gray-50 p-8 text-center">
          <p className="text-gray-600">No hunts yet</p>
          <p className="mt-1 text-sm text-gray-500">
            Hunts are created through the API (<code>POST /api/hunts</code>) for now.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">Hunt</th>
                <th className="px-4 py-2">Query</th>
                <th className="px-4 py-2">Schedule</th>
                <th className="px-4 py-2">Last run</th>
                <th className="px-4 py-2 text-right">Matches</th>
                <th className="px-4 py-2 text-right">New</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {hunts.map((hunt) => {
                const latest = hunt.runs[0];
                const state = latest ? runState(latest, now) : null;
                // The numbers come from the newest run that produced a result.
                const withResult = hunt.runs.find((run) => run.finishedAt && !run.error);
                return (
                  <tr key={hunt.id}>
                    <td className="px-4 py-2 font-medium text-gray-900">
                      <a href={`/console/hunts/${hunt.id}`} className="text-indigo-700 hover:underline">
                        {hunt.name}
                      </a>
                    </td>
                    <td className="px-4 py-2 text-gray-700">{describeQuery(hunt.query)}</td>
                    <td className="px-4 py-2 text-gray-700">{describeSchedule(hunt.scheduleMinutes, hunt.active)}</td>
                    <td className="px-4 py-2">
                      {latest && state ? (
                        <span className="flex items-center gap-2">
                          <span className={`rounded border px-2 py-0.5 text-xs ${STATE_STYLE[state]}`}>
                            {STATE_LABEL[state]}
                          </span>
                          <span className="text-gray-600">{formatTime(latest.startedAt)}</span>
                        </span>
                      ) : (
                        <span className="text-gray-500">Never run</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right text-gray-900">{withResult ? withResult.matchCount : "–"}</td>
                    <td className="px-4 py-2 text-right text-gray-900">{withResult ? withResult.newMatchCount : "–"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {truncated && (
        <p className="mt-3 text-sm text-gray-600">Only the newest {LIST_LIMIT} hunts are listed.</p>
      )}
    </div>
  );
}
