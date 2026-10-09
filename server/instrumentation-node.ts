import { prisma } from "@/lib/prisma";
import { checkDecoyTable, checkShutdownOwnership, installDecoyShutdownFlush } from "@/lib/decoy";

/**
 * Decoy credentials (issue #81), at server start: finish the pending alarms when the process is
 * told to stop, and say if the table they live in does not exist. Node runtime only.
 */
export function startDecoyWatch(): void {
  checkShutdownOwnership();
  installDecoyShutdownFlush(process);
  void checkDecoyTable(prisma);
}
