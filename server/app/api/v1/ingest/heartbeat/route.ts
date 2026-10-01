// The agent's compiled-in path (`transport::DEFAULT_HEARTBEAT_ENDPOINT`) carries
// the `/api/v1` version prefix; the implementation lives at /api/ingest/heartbeat.
export { POST } from "@/app/api/ingest/heartbeat/route";
