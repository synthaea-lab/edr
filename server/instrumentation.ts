/**
 * Runs once when the Node server starts (Next `instrumentationHook`). Decoy credentials
 * (issue #81): finish the pending alarms when the process is told to stop, and say at start
 * if the table they live in does not exist.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { prisma } = await import("@/lib/prisma");
  const { checkDecoyTable, installDecoyShutdownFlush } = await import("@/lib/decoy");
  installDecoyShutdownFlush(process);
  void checkDecoyTable(prisma);
}
