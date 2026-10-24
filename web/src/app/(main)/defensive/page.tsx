"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";

export default function DefensivePage() {
  const router = useRouter();
  const t = useTranslations("Aegis");

  React.useEffect(() => {
    router.replace("/defensive/hunting/");
  }, [router]);

  return (
    <main className="mx-auto max-w-3xl p-6 text-sm">
      <Link href="/defensive/hunting/" className="underline underline-offset-2">
        {t("overview.start.defend")}
      </Link>
    </main>
  );
}
