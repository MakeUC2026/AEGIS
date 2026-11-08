import Link from "next/link";

import { AccessDenied, Pill, Unavailable } from "../_components/Common";
import { RotateSecret } from "../_components/RotateSecret";
import styles from "../_components/classroom.module.css";
import { toSecrets, type ApiSecretList } from "../_lib/adapt";
import { canView } from "../_lib/access";
import { formatTime } from "../_lib/format";
import { load } from "../_lib/load";
import { requireViewer } from "../_lib/viewer";

// Teachers and firewall admins (PRD §12.4, §18.2). Status only: no secret value ever reaches the browser.
export default async function Page() {
  const viewer = await requireViewer();
  if (!canView("secrets", viewer.roles)) {
    return <AccessDenied what="secret status" home="/classroom" />;
  }
  const loaded = await load<ApiSecretList>(["classroom", "secrets"]);
  const secrets = loaded.ok ? toSecrets(loaded.data) : [];
  return (
    <main>
      <div className="page-head">
        <div>
          <p className="eyebrow learn">Classroom</p>
          <h1>Secrets</h1>
          <p className="muted">Rotating gives new sessions a fresh secret. Running sessions keep theirs.</p>
        </div>
      </div>
      {!loaded.ok ? (
        loaded.reason === "forbidden" ? (
          <AccessDenied what="secret status" home="/classroom" />
        ) : (
          <Unavailable what="secret status" />
        )
      ) : secrets.length === 0 ? (
        <p className={styles.empty}>No levels have a secret yet.</p>
      ) : (
        <ul className={styles.log}>
          {secrets.map((s) => (
            <li key={s.levelId} className={styles.block}>
              <div className={styles.actions} style={{ justifyContent: "space-between" }}>
                <div>
                  <strong>{s.levelName}</strong> <span className="muted">secret version {s.version}</span>
                  <div>
                    {s.compromised ? <Pill tone="bad">Compromised</Pill> : <Pill tone="good">Safe</Pill>}{" "}
                    {s.compromised ? (
                      <span className="muted">
                        by {s.by ?? "unknown"} at {formatTime(s.at ?? "")}
                        {s.sessionId ? (
                          <>
                            {" "}
                            <Link href={`/classroom/sessions/${s.sessionId}`}>View session</Link>
                          </>
                        ) : null}
                      </span>
                    ) : null}
                  </div>
                </div>
                <RotateSecret levelId={s.levelId} levelName={s.levelName} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
