// The agent's compiled-in path (`transport::DEFAULT_INGEST_ENDPOINT`) carries
// the `/api/v1` version prefix; the implementation lives at /api/ingest/events.
export { POST } from "@/app/api/ingest/events/route";
