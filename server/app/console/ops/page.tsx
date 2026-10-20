import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { loadFleet, type FleetAgent } from "@/lib/fleet";
import { loadRings, type RingStatus, type RolloutState } from "@/lib/rings";
import type { FleetStatus } from "@/lib/fleet-health";
import { loadIngestHealth, type AgentIngestHealth } from "@/lib/ingest-stats";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import RingControls from "@/components/RingControls";
import { NON_ADMIN_NOTE } from "@/lib/ring-actions";
import { isAdminRole } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

const STATUS_STYLE: Record<FleetStatus, string> = {
  silent: "bg-red-100 text-red-800 border-red-200",
  degraded: "bg-orange-100 text-orange-800 border-orange-200",
  no_beacon: "bg-gray-100 text-gray-700 border-gray-200",
  healthy: "bg-green-100 text-green-800 border-green-200",
};

const STATUS_LABEL: Record<FleetStatus, string> = {
  silent: "Silent",
  degraded: "Degraded",
  no_beacon: "No health data",
  healthy: "Healthy",
};

export default async function FleetHealthPage() {
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

  const agents = await loadFleet(prisma, tenantId);
  const { rings, truncated } = await loadRings(prisma, tenantId);
  // Halt and roll back are admin actions (#803): only an owner or admin sees the buttons; the
  // routes check the role again.
  const member = await prisma.member.findFirst({
    where: { organizationId: tenantId, userId: session.user.id },
    select: { role: true },
  });
  const isAdmin = isAdminRole(member?.role);
  const ingest = await loadIngestHealth(prisma, tenantId, new Date());

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Fleet health</h2>
        <p className="mt-1 text-sm text-gray-600">
          Latest health beacon per agent. Sensors that stopped reporting, and telemetry the agent
          had to drop, show here before they show as missing detections.
        </p>
      </div>
      <RingPanel rings={rings} truncated={truncated} isAdmin={isAdmin} />
      {agents.length === 0 ? (
        <p className="text-sm text-gray-600">No agents enrolled yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">Host</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Ring</th>
                <th className="px-4 py-2">Last heartbeat</th>
                <th className="px-4 py-2">Silent sensors</th>
                <th className="px-4 py-2">Telemetry loss</th>
                <th className="px-4 py-2 text-right">Spool dropped</th>
                <th className="px-4 py-2 text-right">Enrich dropped</th>
                <th className="px-4 py-2 text-right">Spool backlog</th>
                <th className="px-4 py-2">Rarity evidence</th>
                <th className="px-4 py-2 text-right">Watchdog restarts</th>
                <th className="px-4 py-2 text-right">Tamper events</th>
                <th className="px-4 py-2">Parent images evicted</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {agents.map((a) => (
                <AgentRow key={a.id} agent={a} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <IngestPanel agents={agents} ingest={ingest} />
    </div>
  );
}

function AgentRow({ agent }: { agent: FleetAgent }) {
  const silentSensors = agent.health?.sensors.filter((s) => s.silent).map((s) => s.name) ?? [];
  return (
    <tr>
      <td className="px-4 py-2 font-medium text-gray-900">{agent.hostname ?? agent.id}</td>
      <td className="px-4 py-2">
        <span className={`rounded border px-2 py-0.5 text-xs font-medium ${STATUS_STYLE[agent.status]}`}>
          {STATUS_LABEL[agent.status]}
        </span>
      </td>
      <td className="px-4 py-2 text-gray-700">{agent.ring}</td>
      <td className="px-4 py-2 text-gray-700">{new Date(agent.lastSeen).toLocaleString()}</td>
      <td className="px-4 py-2 text-gray-700">
        {agent.status === "silent" || !agent.health ? "—" : silentSensors.join(", ") || "none"}
      </td>
      <td className="px-4 py-2 text-gray-700">
        {agent.status === "silent" || !agent.health
          ? "—"
          : agent.health.recentLoss
            ? "Lost telemetry in the last 10 min"
            : "none recent"}
      </td>
      <td className="px-4 py-2 text-right tabular-nums">{agent.health?.spoolDropped ?? "—"}</td>
      <td className="px-4 py-2 text-right tabular-nums">{agent.health?.enrichDropped ?? "—"}</td>
      <td className="px-4 py-2 text-right tabular-nums">
        {agent.health ? `${agent.health.spoolBytes} B` : "—"}
      </td>
      <td className="px-4 py-2 text-gray-700">
        {agent.health
          ? `${agent.health.rarityApplied} applied, ${agent.health.rarityWithheld} withheld, ${agent.health.rarityUnapplied} lost`
          : "—"}
      </td>
      <td className="px-4 py-2 text-right tabular-nums">{agent.health?.watchdogRestarts ?? "—"}</td>
      <td className="px-4 py-2 text-right tabular-nums">{agent.health?.tamperEvents ?? "—"}</td>
      <td className="px-4 py-2 text-gray-700">
        {agent.health
          ? `${agent.health.parentImageEvictedLive} live, ${agent.health.parentImageEvictedDead} exited`
          : "—"}
      </td>
    </tr>
  );
}

const ROLLOUT_STYLE: Record<RolloutState, string> = {
  serving: "bg-green-100 text-green-800 border-green-200",
  halted: "bg-red-100 text-red-800 border-red-200",
  rolled_back: "bg-orange-100 text-orange-800 border-orange-200",
  no_release: "bg-gray-100 text-gray-700 border-gray-200",
};

const ROLLOUT_LABEL: Record<RolloutState, string> = {
  serving: "Serving",
  halted: "Halted",
  rolled_back: "Rolled back",
  no_release: "No release",
};

/** Content rollout per ring next to the health of the agents in it. */
function RingPanel({ rings, truncated, isAdmin }: { rings: RingStatus[]; truncated: boolean; isAdmin: boolean }) {
  return (
    <section className="mb-8" aria-label="Content rings">
      <h3 className="mb-2 text-lg font-semibold text-gray-900">Content rings</h3>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {rings.map((r) => (
          <div key={r.ring} className="rounded-lg border border-gray-200 bg-white p-4">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm font-medium text-gray-900">{r.ring}</span>
              <span className={`rounded border px-2 py-0.5 text-xs font-medium ${ROLLOUT_STYLE[r.rollout]}`}>
                {ROLLOUT_LABEL[r.rollout]}
              </span>
            </div>
            <p className="mt-2 text-xs text-gray-600">
              {r.latestVersion === null
                ? "No content released"
                : r.rollout === "halted" || r.rollout === "rolled_back"
                  ? `v${r.latestVersion} ${r.rollout === "halted" ? "halted" : "rolled back"}; agents are offered ${
                      r.servedVersion === null ? "nothing" : `v${r.servedVersion}`
                    }`
                  : `v${r.latestVersion}, released ${new Date(r.latestReleasedAt ?? "").toLocaleString()}`}
            </p>
            <p className="mt-2 text-xs text-gray-700">
              {r.agents} agent{r.agents === 1 ? "" : "s"}
              {r.byStatus.silent > 0 && `, ${r.byStatus.silent} silent`}
              {r.byStatus.degraded > 0 && `, ${r.byStatus.degraded} degraded`}
            </p>
            {isAdmin && <RingControls ring={r.ring} rollout={r.rollout} servedVersion={r.servedVersion} hasEarlierRelease={r.hasEarlierRelease} />}
          </div>
        ))}
      </div>
      {!isAdmin && <p className="mt-2 text-xs text-gray-500">{NON_ADMIN_NOTE}</p>}
      {truncated && (
        <p className="mt-2 text-xs text-gray-500">
          Agent counts cover the {rings.reduce((n, r) => n + r.agents, 0)} most recently seen agents only.
        </p>
      )}
    </section>
  );
}

/**
 * Ingest health (#899), in its own table so that it stays apart from `fleetStatus`: a refusal rate
 * or a stale kind of data does not make a host degraded (that is an open question in the issue).
 */
function IngestPanel({
  agents,
  ingest,
}: {
  agents: FleetAgent[];
  ingest: Map<string, AgentIngestHealth>;
}) {
  if (agents.length === 0) return null;
  return (
    <section className="mt-8" aria-label="Ingest health">
      <h3 className="mb-1 text-lg font-semibold text-gray-900">Ingest health</h3>
      <p className="mb-2 text-xs text-gray-600">
        What the server took from each agent, by kind of data. Refused and late are counted over the
        current and previous hour. Shown, not alerted on, and it does not change a host's status.
      </p>
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-2">Host</th>
              <th className="px-4 py-2">Last events batch</th>
              <th className="px-4 py-2">Last detection</th>
              <th className="px-4 py-2">Last beacon</th>
              <th
                className="px-4 py-2"
                title="Requests refused after the agent was identified, and entries dropped as malformed. The 5xx count is best effort: it under-counts exactly when the database is down, because the count is written to the same database."
              >
                Refused / skipped (1 h)
              </th>
              <th
                className="px-4 py-2 text-right"
                title="Ingest time minus event time. A reconnecting agent uploads events it spooled while offline, so a high worst case right after a reconnection is expected, not a server fault."
              >
                Ingest lag (1 h)
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {agents.map((a) => {
              const h = ingest.get(a.id);
              return (
                <tr key={a.id}>
                  <td className="px-4 py-2 font-medium text-gray-900">{a.hostname ?? a.id}</td>
                  <td className="px-4 py-2 text-gray-700">{when(h?.lastAccepted.events)}</td>
                  <td className="px-4 py-2 text-gray-700">{when(h?.lastAccepted.detection)}</td>
                  <td className="px-4 py-2 text-gray-700">{when(h?.lastAccepted.beacon)}</td>
                  <td className="px-4 py-2 text-gray-700">
                    {h ? `${h.refused4xx} 4xx, ${h.refused5xx} 5xx, ${h.skipped} skipped` : "—"}
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums">
                    {h?.lagMaxMs == null || h.lagMeanMs == null
                      ? "—"
                      : `${seconds(h.lagMeanMs)} mean, ${seconds(h.lagMaxMs)} max`}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** "never" is a fact (no accepted request retained), "—" would read as unknown. */
function when(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "never";
}

function seconds(ms: number): string {
  return `${(ms / 1000).toFixed(1)} s`;
}
