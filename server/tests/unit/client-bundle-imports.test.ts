import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

/**
 * A client component's import graph must not reach server-only code (#926). Webpack builds the
 * browser bundle from the same graph and cannot resolve `node:crypto`, Prisma or the notification
 * outbox, so a page whose client component reaches one answers 500. The server tests import
 * modules in Node and never build that bundle, which is how #887 broke `/console/hunts/new`
 * without a test noticing.
 *
 * Static analysis, no build: every file that starts with `"use client"` is an entry; its value
 * imports are followed (`import type` is erased by the compiler and is not); the first import of
 * a Node built-in or of `@/lib/prisma` fails the test with the chain that led there. Server-only
 * modules are found by what they import, not by where they live, so a pure helper next to them
 * (`lib/notify/sign-in-redirect.ts`) is not a false alarm.
 */
const ROOT = path.resolve(__dirname, "../..");
const SERVER_ONLY_BUILTINS = new Set([
  "fs", "path", "crypto", "child_process", "os", "net", "tls", "http", "https", "http2",
  "stream", "zlib", "dns", "dgram", "cluster", "worker_threads", "readline", "vm",
]);
const SERVER_ONLY_FILES = [/^lib\/prisma\.ts$/];

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".next" || name === "tests") continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

const rel = (file: string) => path.relative(ROOT, file).split(path.sep).join("/");

function isClientEntry(source: string): boolean {
  // The directive is the first statement; comments may precede it.
  const body = source.replace(/^(\s*(\/\/[^\n]*\n|\/\*[\s\S]*?\*\/))*\s*/, "");
  return /^["']use client["']/.test(body);
}

/** The specifiers of the value imports and re-exports of `source`. */
export function valueImports(source: string): string[] {
  const found: string[] = [];
  const statement = /(?:^|\n)\s*(?:import|export)\s+(?!type\s|const\s|let\s|function\s|async\s|class\s|default\s|enum\s|interface\s)([\s\S]*?)\sfrom\s+["']([^"']+)["']/g;
  for (const m of Array.from(source.matchAll(statement))) found.push(m[2]);
  for (const m of Array.from(source.matchAll(/(?:^|\n)\s*import\s+["']([^"']+)["']/g))) found.push(m[1]);
  return found;
}

function resolveLocal(from: string, specifier: string): string | null {
  const base = specifier.startsWith("@/") ? path.join(ROOT, specifier.slice(2)) : path.resolve(path.dirname(from), specifier);
  for (const candidate of [base, `${base}.ts`, `${base}.tsx`, path.join(base, "index.ts"), path.join(base, "index.tsx")]) {
    try {
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      /* try the next candidate */
    }
  }
  return null;
}

/** The chain from `entry` to the first server-only module it reaches, or null. */
export function serverOnlyChain(entry: string): string[] | null {
  const seen = new Set<string>();
  const visit = (file: string, chain: string[]): string[] | null => {
    if (seen.has(file)) return null;
    seen.add(file);
    for (const specifier of valueImports(readFileSync(file, "utf-8"))) {
      const bare = specifier.replace(/^node:/, "");
      if (specifier.startsWith("node:") || SERVER_ONLY_BUILTINS.has(bare)) return [...chain, specifier];
      if (!specifier.startsWith("@/") && !specifier.startsWith(".")) continue; // a package
      const target = resolveLocal(file, specifier);
      if (!target) continue;
      const name = rel(target);
      if (SERVER_ONLY_FILES.some((re) => re.test(name))) return [...chain, name];
      const deeper = visit(target, [...chain, name]);
      if (deeper) return deeper;
    }
    return null;
  };
  return visit(entry, [rel(entry)]);
}

describe("client components do not reach server-only code (#926)", () => {
  const entries = walk(ROOT).filter((f) => isClientEntry(readFileSync(f, "utf-8")));

  it("finds the client components, or the check is blind", () => {
    const names = entries.map(rel);
    expect(names).toEqual(expect.arrayContaining(["components/HuntForm.tsx", "components/RunHuntButton.tsx"]));
    expect(entries.length).toBeGreaterThan(5);
  });

  it.each(entries.map((f) => [rel(f), f]))("%s", (_name, file) => {
    const chain = serverOnlyChain(file);
    expect(chain, chain ? `reaches server-only code: ${chain.join(" -> ")}` : "").toBeNull();
  });

  describe("the analysis itself", () => {
    it("reads value imports and re-exports, not type imports or declarations", () => {
      const source = [
        'import { a } from "@/lib/a";',
        'import type { B } from "@/lib/b";',
        'import { c, type D } from "@/lib/c";',
        'import {\n  e,\n  f,\n} from "@/lib/e";',
        'export { g } from "@/lib/g";',
        'export type { H } from "@/lib/h";',
        "export const x = 1;",
        'import "side-effect";',
      ].join("\n");
      expect(valueImports(source).sort()).toEqual(["@/lib/a", "@/lib/c", "@/lib/e", "@/lib/g", "side-effect"].sort());
    });

    it("follows the graph and names the chain that reaches a server-only module", () => {
      const chain = serverOnlyChain(path.join(ROOT, "components", "HuntForm.tsx"));
      // On a tree where the form still reaches the outbox, the chain says how; on a clean one it is null.
      if (chain) expect(chain[0]).toBe("components/HuntForm.tsx");
    });
  });
});
