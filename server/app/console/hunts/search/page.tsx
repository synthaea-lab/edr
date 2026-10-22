import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { SEVERITIES } from "@/lib/hunt";
import { CASE_STATUSES, MAX_CONCURRENT_SEARCHES_PER_TENANT, searchFailure, searchWithinLimit, type SearchPage } from "@/lib/hunt-search";
import { searchFormFromParams, searchHref, searchRequestFromParams, type SearchParams } from "@/lib/hunt-search-form";
import { SearchResults } from "@/components/SearchResults";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

const INPUT = "mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-900";
const LABEL = "block text-sm font-medium text-gray-700";

/**
 * Ad-hoc search over detections and cases (#61): a GET form, so a search is a link that can be
 * shared and a page of results is another link. The same validation and limits as the API.
 */
export default async function HuntSearchPage({ searchParams }: { searchParams: SearchParams }) {
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

  const form = searchFormFromParams(searchParams);
  const asked = searchRequestFromParams(searchParams);
  let page: SearchPage | null = null;
  let problem: string | null = null;
  if (asked.kind === "invalid") {
    problem = asked.error;
  } else if (asked.kind === "request") {
    try {
      const outcome = await searchWithinLimit(prisma, tenantId, asked.request);
      if (outcome.status === "busy") {
        problem = `At most ${MAX_CONCURRENT_SEARCHES_PER_TENANT} searches at a time per tenant; try again shortly.`;
      } else {
        page = outcome.page;
      }
    } catch (error) {
      const failure = searchFailure(error);
      if (failure.status === 500) console.error("Hunt search page error:", error);
      problem = failure.status === 500 ? "The search failed (see the server log)." : failure.message;
    }
  }

  return (
    <div>
      <a href="/console/hunts" className="text-sm text-indigo-700 hover:underline">← Hunts</a>
      <h2 className="mt-2 text-2xl font-bold text-gray-900">Search</h2>
      <p className="mt-1 mb-4 text-sm text-gray-600">
        Look through the detections or the cases of your organization before you save a hunt. The raw event
        archive is not searchable yet.
      </p>

      <form method="get" className="mb-6 max-w-2xl space-y-4 rounded-lg border border-gray-200 bg-white p-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className={LABEL} htmlFor="search-source">Search in</label>
            <select id="search-source" name="source" defaultValue={form.source} className={INPUT}>
              <option value="detections">Detections</option>
              <option value="cases">Cases</option>
            </select>
          </div>
          <div>
            <label className={LABEL} htmlFor="search-hours">Look back (hours)</label>
            <input id="search-hours" name="hours" defaultValue={form.hours} inputMode="numeric" className={INPUT} />
          </div>
        </div>
        <div>
          <label className={LABEL} htmlFor="search-techniques">ATT&amp;CK techniques</label>
          <input id="search-techniques" name="techniques" defaultValue={form.techniques} placeholder="T1059, T1003.001" className={INPUT} />
        </div>
        <fieldset>
          <legend className={LABEL}>Severity</legend>
          <div className="mt-1 flex gap-4 text-sm text-gray-800">
            {SEVERITIES.map((s) => (
              <label key={s} className="flex items-center gap-1">
                <input type="checkbox" name="severity" value={s} defaultChecked={form.severities.includes(s)} /> {s}
              </label>
            ))}
          </div>
        </fieldset>
        <fieldset>
          <legend className={LABEL}>Case status (cases only)</legend>
          <div className="mt-1 flex flex-wrap gap-4 text-sm text-gray-800">
            {CASE_STATUSES.map((s) => (
              <label key={s} className="flex items-center gap-1">
                <input type="checkbox" name="status" value={s} defaultChecked={form.statuses.includes(s)} /> {s}
              </label>
            ))}
          </div>
        </fieldset>
        <div>
          <label className={LABEL} htmlFor="search-hosts">Host ids (detections only)</label>
          <textarea id="search-hosts" name="hosts" defaultValue={form.hosts} rows={2} className={INPUT} />
        </div>
        <div>
          <label className={LABEL} htmlFor="search-text">Text</label>
          <input id="search-text" name="text" defaultValue={form.text} className={INPUT} />
          <p className="mt-1 text-xs text-gray-500">
            A literal, case-insensitive substring: of the stored event for detections, of the title or description for cases.
            3 to 256 characters; a wide window with a rare text is the slow case.
          </p>
        </div>
        <button type="submit" className="px-3 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700">
          Search
        </button>
      </form>

      {problem && (
        <p className="mb-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700" role="alert">{problem}</p>
      )}
      {page && <SearchResults page={page} olderHref={page.nextCursor ? searchHref(searchParams, page.nextCursor) : null} />}
    </div>
  );
}
