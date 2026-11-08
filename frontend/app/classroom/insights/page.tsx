import { AccessDenied, MockBadge, ScreenNav } from "../_components/Common";
import { InsightsView } from "../_components/InsightsView";
import styles from "../_components/classroom.module.css";
import { canView } from "../_lib/access";
import { requireViewer } from "../_lib/viewer";

// Phase A shell: mock data. Teachers only (PRD §12.3); the API repeats the check.
export default async function Page() {
  const viewer = await requireViewer();
  if (!canView("insights", viewer.roles)) {
    return <AccessDenied what="class insights (teachers only)" home="/classroom" />;
  }
  return (
    <main>
      <div className={styles.head}>
        <h1>Class insights</h1>
        <MockBadge />
      </div>
      <p className={styles.lead}>How the class is doing. In the real screen these numbers refresh about once a minute.</p>
      <ScreenNav kind={viewer.kind} current="insights" />
      <InsightsView />
    </main>
  );
}
