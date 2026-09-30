"use client";

import Link from "next/link";
import { Case } from "@prisma/client";
import { severityColor, statusColor } from "@/lib/case-display";

interface Props {
  cases: Case[];
}

export function CaseList({ cases }: Props) {
  return (
    <div className="space-y-3">
      {cases.map((case_) => (
        <Link
          key={case_.id}
          href={`/console/cases/${case_.id}`}
          className="block border border-gray-200 rounded-lg p-4 bg-white hover:shadow-md transition-shadow cursor-pointer"
        >
          <div className="flex justify-between items-start">
            <div className="flex-1">
              <h3 className="font-semibold text-gray-900">{case_.title}</h3>
              {case_.description && (
                <p className="mt-1 text-sm text-gray-600 line-clamp-2">
                  {case_.description}
                </p>
              )}
            </div>
            <div className="flex gap-2 ml-4 flex-shrink-0">
              <span
                className={`px-2 py-1 rounded text-xs font-medium border ${severityColor(
                  case_.severity
                )}`}
              >
                {case_.severity}
              </span>
              <span
                className={`px-2 py-1 rounded text-xs font-medium border ${statusColor(
                  case_.status
                )}`}
              >
                {case_.status}
              </span>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
            <span>Created {new Date(case_.createdAt).toLocaleString()}</span>
            <span>Updated {new Date(case_.updatedAt).toLocaleString()}</span>
          </div>
        </Link>
      ))}
    </div>
  );
}
