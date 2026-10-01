import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { loadFleet, type FleetAgent } from "@/lib/fleet";
import type { FleetStatus } from "@/lib/fleet-health";
import { redirect } from "next/navigation";

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
  const session = await auth.api.getSession();
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

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Fleet health</h2>
        <p className="mt-1 text-sm text-gray-600">
          Latest health beacon per agent. Sensors that stopped reporting, and telemetry the agent
          had to drop, show here before they show as missing detections.
        </p>
      </div>
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
                <th className="px-4 py-2 text-right">Spool dropped</th>
                <th className="px-4 py-2 text-right">Enrich dropped</th>
                <th className="px-4 py-2 text-right">Spool backlog</th>
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
      <td className="px-4 py-2 text-right tabular-nums">{agent.health?.spoolDropped ?? "—"}</td>
      <td className="px-4 py-2 text-right tabular-nums">{agent.health?.enrichDropped ?? "—"}</td>
      <td className="px-4 py-2 text-right tabular-nums">
        {agent.health ? `${agent.health.spoolBytes} B` : "—"}
      </td>
    </tr>
  );
}
