import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { channelView } from "@/lib/notify/channels";
import { currentKey } from "@/lib/notify/secret";
import { CHANNELS_PER_TENANT, failedCounts } from "@/lib/notify/outbox";
import NotificationChannelActions from "@/components/NotificationChannelActions";

export const dynamic = "force-dynamic";

const STATUS_STYLE: Record<string, string> = {
  active: "bg-green-100 text-green-800 border-green-200",
  paused: "bg-orange-100 text-orange-800 border-orange-200",
  disabled: "bg-gray-100 text-gray-700 border-gray-200",
};

/** Rows that have waited this long without a first attempt mean the outbox is backed up. */
const BACKED_UP_AFTER_MS = 5 * 60 * 1000;

export default async function NotificationsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const tenantId = session.session.activeOrganizationId;
  if (!tenantId) {
    return (
      <div className="rounded-lg bg-yellow-50 p-4">
        <p className="text-sm text-yellow-800">No organization selected. Please contact your administrator.</p>
      </div>
    );
  }

  const member = await prisma.member.findFirst({
    where: { organizationId: tenantId, userId: session.user.id },
    select: { role: true },
  });
  const isAdmin = (member?.role.split(",").map((r) => r.trim()) ?? []).some((r) => r === "owner" || r === "admin");

  const now = Date.now();
  const [channels, failed, waiting, stuck, hunts] = await Promise.all([
    prisma.notificationChannel.findMany({ where: { tenantId }, orderBy: { createdAt: "asc" } }),
    failedCounts(prisma, tenantId),
    prisma.notification.count({ where: { tenantId, deliveredAt: null, failedAt: null } }),
    prisma.notification.count({
      where: { tenantId, deliveredAt: null, failedAt: null, attempts: 0, createdAt: { lt: new Date(now - BACKED_UP_AFTER_MS) } },
    }),
    isAdmin ? prisma.hunt.findMany({ where: { tenantId }, select: { id: true, name: true }, orderBy: { name: "asc" } }) : [],
  ]);
    const configured = currentKey() !== null;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Notifications</h2>
        <p className="mt-1 text-sm text-gray-600">
          Signed webhooks that tell a person when a host goes degraded or silent, recovers, or when a saved hunt has new
          matches. A message points to the console and carries no detection contents. Delivery is at least once: a
          receiver should check the signature and de-duplicate on the event id. A host or a hunt sends at most one
          message per webhook per cooldown (30 minutes by default): a hunt that finds new matches on every run is
          not announced again until the cooldown has passed, and what it found meanwhile is not sent later.
        </p>
        {waiting > 0 && (
          <p className={`mt-2 text-sm ${stuck > 0 ? "text-orange-800" : "text-gray-600"}`}>
            {waiting} notification{waiting === 1 ? "" : "s"} waiting to be sent
            {stuck > 0 ? `; ${stuck} not yet attempted for over 5 minutes, so the outbox is backed up.` : "."}
          </p>
        )}
      </div>

      {channels.length === 0 ? (
        <p className="text-sm text-gray-600">No webhook registered.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">Receiver</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Events</th>
                <th className="px-4 py-2">Last result</th>
                {isAdmin && <th className="px-4 py-2">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {channels.map((c) => {
                const v = channelView(c);
                const { resendable: failedRows, superseded } = failed.get(c.id) ?? { resendable: 0, superseded: 0 };
                return (
                  <tr key={c.id} className="align-top">
                    <td className="px-4 py-2 font-mono text-xs">{v.host}</td>
                    <td className="px-4 py-2">
                      <span className={`rounded border px-2 py-0.5 text-xs ${STATUS_STYLE[v.status] ?? STATUS_STYLE.disabled}`}>
                        {v.status}
                      </span>
                      {v.status === "paused" && (
                        <p className="mt-1 text-xs text-orange-800">
                          Paused after five failed deliveries. New messages are kept and sent, oldest first, when it is re-enabled.
                        </p>
                      )}
                      {failedRows > 0 && <p className="mt-1 text-xs text-gray-600">{failedRows} failed</p>}
                      {superseded > 0 && (
                        <p className="mt-1 text-xs text-gray-500">
                          {superseded} failed, superseded by a later message of the same host (not sent again)
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-700">{v.events.join(", ") || "none"}</td>
                    <td className="px-4 py-2 text-xs text-gray-700">
                      {v.lastError
                        ? `${v.lastError}${v.lastStatusCode ? ` (HTTP ${v.lastStatusCode})` : ""}`
                        : v.lastDeliveredAt
                          ? `delivered ${v.lastDeliveredAt.toISOString()}`
                          : "nothing sent yet"}
                    </td>
                    {isAdmin && (
                      <td className="px-4 py-2">
                        <NotificationChannelActions mode="row" channelId={c.id} status={v.status} failedRows={failedRows} />
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {isAdmin &&
        (!configured ? (
          <p className="text-sm text-gray-600">Webhooks are not configured on this server (NOTIFY_SECRET_KEY is unset).</p>
        ) : channels.length >= CHANNELS_PER_TENANT ? (
          <p className="text-sm text-gray-600">This organization has the maximum of {CHANNELS_PER_TENANT} webhooks.</p>
        ) : (
          <NotificationChannelActions mode="create" hunts={hunts} />
        ))}
      {!isAdmin && <p className="text-xs text-gray-500">Only an organization owner or admin can change webhooks.</p>}
    </div>
  );
}
