"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ApiError, apiFetch } from "@/lib/api";

import styles from "./classroom.module.css";

type Phase = "idle" | "confirm" | "working";

// Two clicks on purpose: rotating changes the secret for every new session, and it is audited.
export function RotateSecret({ levelId, levelName }: { levelId: string; levelName: string }) {
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState<string | null>(null);

  async function rotate() {
    setPhase("working");
    setMessage(null);
    try {
      await apiFetch(`classroom/secrets/${encodeURIComponent(levelId)}/rotate`, { method: "POST" });
      setMessage(`Rotated. New sessions on ${levelName} get a fresh secret.`);
      router.refresh();
    } catch (err) {
      setMessage(err instanceof ApiError && err.status === 403 ? "You are not allowed to rotate secrets." : "Rotation failed. Try again.");
    } finally {
      setPhase("idle");
    }
  }

  return (
    <div className={styles.rotate}>
      {phase === "confirm" ? (
        <div className={styles.actions} role="group" aria-label={`Confirm rotating ${levelName}`}>
          <button type="button" className="button" onClick={rotate}>
            Confirm rotate
          </button>
          <button type="button" className="btn-alt" onClick={() => setPhase("idle")}>
            Cancel
          </button>
        </div>
      ) : (
        <button
          type="button"
          className="button"
          disabled={phase === "working"}
          aria-label={`Rotate secret for ${levelName}`}
          onClick={() => setPhase("confirm")}
        >
          {phase === "working" ? "Rotating..." : "Rotate secret"}
        </button>
      )}
      <p role="status" className="muted">
        {message}
      </p>
    </div>
  );
}
