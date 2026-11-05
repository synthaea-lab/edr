# Issue #1131: an event over the body limit got a 413 and was dropped

**Branch:** `fix/1131-event-uplink-413` · **Refs:** #1112, #1119, #1122, #1116 · **Status:** fix in code and unit-tested; not run against a live server

## Decision
Smallest fix, the #1122 approach for events: `transport::event_limit::fit_batches` runs in `EventUploader::upload_once` before the batches are built. An event over 1 MiB (the spool segment cap) is shortened (strings and arrays cut step by step, identifying keys kept until the last step, which cuts them to 4096 bytes; original size logged), never dropped; batches are also split by bytes under 4 MiB. `EventDrain`/spool/server unchanged, so the 413 handling is untouched (no split-and-retry on a 413).

## Facts checked
- The route limit is 4 MiB (`MAX_BODY_BYTES`, `server/app/api/ingest/events/route.ts`), nginx 8 MiB: the mirror uses the route's value, not nginx's.
- The spool rotates at 1 MiB, so an oversized event sits alone in its segment (issue correction): shortening that one event is enough.

## Not verified
Live server/nginx (no VM used). A shortened event deserializes back into `schema::Event` in the unit tests for `Exec` only. An event that cannot be shortened under 1 MiB (none known) is no longer acknowledged with its segment: `upload_once` returns `TransportError::Unsendable`, the segment is redelivered, and only `max_drain_attempts` skips it, with the count logged (review of #1144). The skip is still a loss, after the budget; a quarantine for such an event is not built. Tested with the event limit lowered to 10 bytes, not with a real unshortenable event (none known). Windows/macOS sensors not exercised. Bounding argv at capture (#1116) is separate.
