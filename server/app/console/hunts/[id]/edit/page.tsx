import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { huntQueryIsValid, huntToFormValues } from "@/lib/hunt-form";
import { HuntForm } from "@/components/HuntForm";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function EditHuntPage({ params }: { params: { id: string } }) {
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

  return (
    <div>
      <a href={`/console/hunts/${hunt.id}`} className="text-sm text-indigo-700 hover:underline">
        ← {hunt.name}
      </a>
      <h2 className="mt-2 mb-6 text-2xl font-bold text-gray-900">Edit hunt</h2>
      <HuntForm huntId={hunt.id} initial={huntToFormValues(hunt)} queryInvalid={!huntQueryIsValid(hunt.query)} />
    </div>
  );
}
