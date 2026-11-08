import Link from "next/link";
import { redirect } from "next/navigation";

import { CloseButton } from "@/components/arena/CloseButton";
import type { ArenaSession } from "@/lib/arena";
import { getMe, serverGet } from "@/lib/server-api";

// My sessions (PRD §4.2: own sessions only; §6.3 step 4: close from the list).
export default async function MySessionsPage() {
  if (!(await getMe())) redirect("/");
  const sessions = await serverGet<ArenaSession[]>(["arena", "sessions"]);
  return (
    <main>
      <h1>My sessions</h1>
      {sessions.length === 0 ? <p className="muted">No sessions yet. Start one from the Arena.</p> : null}
      <table className="table">
        <thead>
          <tr><th>Level</th><th>Mode</th><th>Started</th><th>Outcome</th><th>Status</th><th /></tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.id}>
              <td><Link href={`/arena/${s.id}`}>{s.level_name}</Link></td>
              <td><span className="mode-chip" data-mode={s.mode}>{s.mode}</span></td>
              <td>{new Date(s.started_at).toLocaleString()}</td>
              <td>{s.won ? <span className="badge-won">Obtained</span> : <span className="muted">Not yet</span>}</td>
              <td>{s.status}</td>
              <td>{s.status === "active" ? <CloseButton sessionId={s.id} /> : <Link href={`/arena/${s.id}`}>Recap</Link>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
