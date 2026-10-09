// `npm start` for the standalone build (`output: 'standalone'` in next.config.js, #743).
//
// `next start` does not serve that output. The standalone server leaves out the static assets
// and `public/`, which the Docker image copies beside it; this does the same for a local run,
// then starts the server Next generated. PORT and HOSTNAME are read by that server.
import { cpSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const standalone = join(root, ".next", "standalone");
const entry = join(standalone, "server.js");

if (!existsSync(entry)) {
  console.error("No standalone build found: run `npm run build` first.");
  process.exit(1);
}

cpSync(join(root, ".next", "static"), join(standalone, ".next", "static"), { recursive: true });
if (existsSync(join(root, "public"))) {
  cpSync(join(root, "public"), join(standalone, "public"), { recursive: true });
}

await import(pathToFileURL(entry).href);
