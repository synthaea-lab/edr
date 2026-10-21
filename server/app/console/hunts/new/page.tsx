import { auth } from "@/lib/auth";
import { HuntForm } from "@/components/HuntForm";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function NewHuntPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  if (!session.session.activeOrganizationId) {
    return (
      <div className="rounded-lg bg-yellow-50 p-4">
        <p className="text-sm text-yellow-800">
          No organization selected. Please contact your administrator.
        </p>
      </div>
    );
  }

  return (
    <div>
      <a href="/console/hunts" className="text-sm text-indigo-700 hover:underline">
        ← Hunts
      </a>
      <h2 className="mt-2 mb-6 text-2xl font-bold text-gray-900">New hunt</h2>
      <HuntForm />
    </div>
  );
}
