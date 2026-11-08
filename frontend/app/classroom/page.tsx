import { MockBadge, ScreenNav } from "./_components/Common";
import { FilterForm } from "./_components/FilterForm";
import { SessionsTable } from "./_components/SessionsTable";
import styles from "./_components/classroom.module.css";
import { applyFilters, parseFilters } from "./_lib/filters";
import { MOCK_SESSIONS } from "./_lib/mock";
import { requireViewer } from "./_lib/viewer";

// Phase A shell: mock data. Phase B reads GET /api/classroom/sessions instead (filters server-side).
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const viewer = await requireViewer();
  const filters = parseFilters(await searchParams);
  const rows = applyFilters(MOCK_SESSIONS, filters, { kind: viewer.kind, userId: viewer.ownerKey });
  const student = viewer.kind === "student";
  return (
    <main>
      <div className={styles.head}>
        <h1>{student ? "Sessions and quizzes" : "Classroom"}</h1>
        <MockBadge />
      </div>
      <p className={styles.lead}>
        {student
          ? "Your own sessions. Open one to review what happened or start a quiz."
          : viewer.kind === "firewall_admin"
            ? "All sessions, read-only."
            : "Every session in the class. Open one to see the transcript, the firewall decisions and the quiz."}
      </p>
      <ScreenNav kind={viewer.kind} current="sessions" />
      <FilterForm filters={filters} kind={viewer.kind} />
      <p className={styles.count} aria-live="polite">
        {rows.length} {rows.length === 1 ? "session" : "sessions"}
      </p>
      <SessionsTable rows={rows} />
    </main>
  );
}

