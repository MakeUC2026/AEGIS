"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { apiFetch } from "@/lib/api";

// Close a session from the session list (PRD §6.3 step 4); the recap then opens.
export function CloseButton({ sessionId }: { sessionId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  return (
    <button
      className="btn-alt"
      type="button"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          await apiFetch(`arena/sessions/${sessionId}/close`, { method: "POST" });
          router.refresh();
        } finally {
          setBusy(false);
        }
      }}
    >
      {busy ? "Closing…" : "Close"}
    </button>
  );
}
