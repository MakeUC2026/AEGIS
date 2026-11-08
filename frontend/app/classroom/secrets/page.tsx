import { AccessDenied, MockBadge, Pill, ScreenNav } from "../_components/Common";
import styles from "../_components/classroom.module.css";
import { canView } from "../_lib/access";
import { formatTime } from "../_lib/format";
import { MOCK_SECRETS } from "../_lib/mock-class";
import { requireViewer } from "../_lib/viewer";

// Phase A shell: mock data. Teachers and firewall admins (PRD §12.4, §18.2). No secret value is
// ever shown, only status. Rotation is wired to the API in Phase B.
export default async function Page() {
  const viewer = await requireViewer();
  if (!canView("secrets", viewer.roles)) {
    return <AccessDenied what="secret status" home="/classroom" />;
  }
  return (
    <main>
      <div className={styles.head}>
        <h1>Secrets</h1>
        <MockBadge />
      </div>
      <p className={styles.lead}>
        Each level has one secret. Rotating it gives new sessions a fresh one; running sessions keep theirs. Every rotation is
        written to the audit log.
      </p>
      <ScreenNav kind={viewer.kind} current="secrets" />
      <ul className={styles.log}>
        {MOCK_SECRETS.map((s) => (
          <li key={s.levelId} className={styles.block}>
            <div className={styles.actions} style={{ justifyContent: "space-between" }}>
              <div>
                <strong>{s.levelName}</strong> <span className="muted">secret version {s.version}</span>
                <div>
                  {s.compromised ? (
                    <Pill tone="bad">Compromised</Pill>
                  ) : (
                    <Pill tone="good">Safe</Pill>
                  )}{" "}
                  {s.compromised ? (
                    <span className="muted">
                      by {s.by} at {formatTime(s.at ?? "")}
                    </span>
                  ) : null}
                </div>
              </div>
              <button className="button" type="button" disabled title="Wired up in Phase B" aria-label={`Rotate secret for ${s.levelName}`}>
                Rotate secret
              </button>
            </div>
          </li>
        ))}
      </ul>
    </main>
  );
}
