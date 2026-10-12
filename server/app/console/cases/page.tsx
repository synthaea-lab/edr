import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { CaseList } from "@/components/CaseList";
import { redirect } from "next/navigation";

// Read per request: the session needs a database, which does not exist at build time.
export const dynamic = "force-dynamic";

export default async function CasesPage() {
  const session = await auth.api.getSession();

  if (!session) {
    redirect("/login");
  }

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

  const cases = await prisma.case.findMany({
    where: { tenantId },
    orderBy: { createdAt: "desc" },
    take: 100,
  });

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Cases</h2>
        <p className="mt-1 text-sm text-gray-600">
          Security incidents requiring investigation
        </p>
      </div>

      {cases.length === 0 ? (
        <div className="rounded-lg bg-gray-50 p-8 text-center">
          <p className="text-gray-600">No cases yet</p>
          <p className="mt-1 text-sm text-gray-500">
            Cases will appear here when detections are triggered
          </p>
        </div>
      ) : (
        <CaseList cases={cases} />
      )}
    </div>
  );
}
