import { HuntValidationError, parseHuntQuery } from "@/lib/hunt";
import { parseCaseQuery, type SearchRequest } from "@/lib/hunt-search";

/** What Next gives a page for its query string. */
export type SearchParams = Record<string, string | string[] | undefined>;

export type SearchForm = {
  source: "detections" | "cases";
  hours: string;
  techniques: string;
  severities: string[];
  statuses: string[];
  hosts: string;
  text: string;
};

export const DEFAULT_SEARCH_FORM: SearchForm = {
  source: "detections",
  hours: "24",
  techniques: "",
  severities: [],
  statuses: [],
  hosts: "",
  text: "",
};

function first(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

function all(value: string | string[] | undefined): string[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
}

const words = (text: string) => text.split(/[\s,]+/).filter(Boolean);

/** The form's fields as they were submitted, for refilling the form. */
export function searchFormFromParams(params: SearchParams): SearchForm {
  return {
    source: first(params.source) === "cases" ? "cases" : "detections",
    hours: first(params.hours) || DEFAULT_SEARCH_FORM.hours,
    techniques: first(params.techniques),
    severities: all(params.severity),
    statuses: all(params.status),
    hosts: first(params.hosts),
    text: first(params.text),
  };
}

export type SearchFromParams =
  | { kind: "none" }
  | { kind: "invalid"; error: string }
  | { kind: "request"; request: SearchRequest };

/**
 * The search a query string asks for: `none` when the form has not been submitted, `invalid`
 * with the validator's own message when its fields do not make a query, else the request.
 * Goes through the same `parseHuntQuery` / `parseCaseQuery` as the API.
 */
export function searchRequestFromParams(params: SearchParams): SearchFromParams {
  if (first(params.source) === "" && first(params.hours) === "") return { kind: "none" };
  const form = searchFormFromParams(params);
  const hours = form.hours.trim();
  const lastHours = hours === "" ? undefined : Number(hours);
  const cursor = first(params.cursor) || undefined;
  const optional = <T,>(key: string, value: T | undefined | T[]) =>
    value === undefined || (Array.isArray(value) && value.length === 0) || value === "" ? {} : { [key]: value };
  try {
    if (form.source === "cases") {
      const query = parseCaseQuery({
        kind: "cases",
        version: 1,
        lastHours,
        ...optional("severities", form.severities),
        ...optional("statuses", form.statuses),
        ...optional("techniques", words(form.techniques)),
        ...optional("text", form.text),
      });
      return { kind: "request", request: { source: "cases", query, cursor } };
    }
    const query = parseHuntQuery({
      version: 1,
      lastHours,
      ...optional("techniques", words(form.techniques)),
      ...optional("severities", form.severities),
      ...optional("agentIds", words(form.hosts)),
      ...optional("text", form.text),
    });
    return { kind: "request", request: { source: "detections", query, cursor } };
  } catch (error) {
    if (error instanceof HuntValidationError) return { kind: "invalid", error: error.message };
    throw error;
  }
}

/** The query string of the same search with another cursor (or none), for the "older" link. */
export function searchHref(params: SearchParams, cursor: string | null): string {
  const next = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (key === "cursor") continue;
    for (const v of all(value)) next.append(key, v);
  }
  if (cursor) next.set("cursor", cursor);
  return `?${next.toString()}`;
}
