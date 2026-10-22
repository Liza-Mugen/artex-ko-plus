"use client";

import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import type { DefenseState } from "@/lib/purple-api";

export function DefenseStateBadge({ state }: { state: DefenseState }) {
  const t = useTranslations("purple");
  return (
    <Badge
      variant={state === "stale" ? "destructive" : "outline"}
      className={state === "current" ? "border-teal-600/30 bg-teal-500/10 text-teal-700 dark:text-teal-300" : undefined}
    >
      {t(`state.${state}`)}
    </Badge>
  );
}
