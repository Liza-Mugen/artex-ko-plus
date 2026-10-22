"use client";

import { useEffect } from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

export default function DiagnosticsRedirectPage() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/function/tasks/");
  }, [router]);

  return (
    <p className="p-6 text-muted-foreground text-sm">
      원본 작업 화면으로 이동합니다.{" "}
      <Link href="/function/tasks/" className="underline">
        직접 이동
      </Link>
    </p>
  );
}
