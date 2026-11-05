# Issue #1105: the event archive search has no S3 reader

**Component:** `server/lib/lake-*`, `server/app/api/hunts/search`
**Status:** code done on `feat/1105-lake-s3-reader` (stacked on `feat/933-hunt-events`, PR #1087); not run against a real store

- [x] Distinct answer for "lake on, no reader" (501) vs "lake off" (503): PR #1106.
- [x] `S3LakeReader` (`get`, `list` with `MaxKeys`), own client, no write method.
- [x] Reader credentials separate from the writer's (`LAKE_S3_READER_*`, ADR-0041 decision 4).
- [x] `lakeReaderFromEnv` / `eventArchiveFromEnv` moved to `lib/lake-env.ts` and return an S3 reader for `LAKE_S3_BUCKET`.
- [ ] Run the reader against MinIO or S3 (the unit tests use an in-memory bucket); needs the compose lab, not done here.
- [ ] Per-tenant credentials scoped by bucket policy (ADR-0041 decision 4, second layer).
