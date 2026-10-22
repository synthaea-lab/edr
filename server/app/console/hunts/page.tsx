import { DeleteHuntButton } from "@/components/DeleteHuntButton";
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { describeQuery, describeSchedule, formatTime, runState, STATE_LABEL, STATE_STYLE } from "@/lib/hunt-view";
import { newestRunsByHunt } from "@/lib/hunt-runs";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

/** A tenant may have 200 hunts (ADR-0025); one more row says the list was cut. */
const LIST_LIMIT = 200;

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

  const found = await prisma.hunt.findMany({
    where: { tenantId },
    orderBy: { createdAt: "desc" },
    take: LIST_LIMIT + 1,
  });
  const truncated = found.length > LIST_LIMIT;
  const hunts = found.slice(0, LIST_LIMIT);
  // The newest run of each hunt says what is happening; the newest one with a result has the
  // numbers (they may be older than the newest run, which is then running or failed).
  const runs = await newestRunsByHunt(
    prisma,
    tenantId,
    hunts.map((hunt) => hunt.id)
  );
  const now = new Date();

  return (
    <div>
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Hunts</h2>
          <p className="mt-1 text-sm text-gray-600">
            Saved searches over the detection store, run by hand or on a schedule. A run counts the
            detections that match in its window, and how many of them arrived since the previous run.
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <a
            href="/console/hunts/search"
            className="px-3 py-1.5 text-sm font-medium rounded-md border border-gray-300 text-gray-800 hover:bg-gray-50"
          >
            Search
          </a>
          <a
            href="/console/hunts/new"
            className="px-3 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700"
          >
            New hunt
          </a>
        </div>
      </div>

      {hunts.length === 0 ? (
        <div className="rounded-lg bg-gray-50 p-8 text-center">
          <p className="text-gray-600">No hunts yet</p>
          <p className="mt-1 text-sm text-gray-500">Use “New hunt” to save your first search.</p>
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
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {hunts.map((hunt) => {
                const latest = runs.get(hunt.id)?.latest ?? null;
                const state = latest ? runState(latest, now) : null;
                const withResult = runs.get(hunt.id)?.result ?? null;
                // The numbers of an older run than the newest one say where they come from.
                const stale = withResult && latest && withResult.startedAt.getTime() !== latest.startedAt.getTime();
                const from = stale && withResult ? (
                  <span className="block text-xs text-gray-500">from {formatTime(withResult.startedAt)}</span>
                ) : null;
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
                    <td className="px-4 py-2 text-right text-gray-900">
                      {withResult ? withResult.matchCount : "–"}
                      {from}
                    </td>
                    <td className="px-4 py-2 text-right text-gray-900">{withResult ? withResult.newMatchCount : "–"}</td>
                    <td className="px-4 py-2 text-right">
                      <DeleteHuntButton huntId={hunt.id} name={hunt.name} />
                    </td>
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
