import { AccessDenied, ScreenNav, Unavailable } from "./_components/Common";
import { FilterForm } from "./_components/FilterForm";
import { SessionsTable } from "./_components/SessionsTable";
import styles from "./_components/classroom.module.css";
import { applyStudentNameFilter, filtersToApiQuery, toSessionList, type ApiSessionList } from "./_lib/adapt";
import { parseFilters } from "./_lib/filters";
import { load } from "./_lib/load";
import { requireViewer } from "./_lib/viewer";

// Reads GET /api/classroom/sessions. Filters live in the URL and are validated twice: parsed here
// (unknown values dropped) and by the API (422). A student is scoped to their own sessions by the API.
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const viewer = await requireViewer();
  const filters = parseFilters(await searchParams);
  const query = filtersToApiQuery(filters, viewer.kind);
  const loaded = await load<ApiSessionList>(["classroom", "sessions"], query ? `?${query}` : "");
  const student = viewer.kind === "student";
  const list = loaded.ok ? toSessionList(loaded.data) : null;
  const rows = list ? applyStudentNameFilter(list.rows, filters.student, viewer.kind) : [];
  return (
    <main>
      <div className={styles.head}>
        <h1>{student ? "Sessions and quizzes" : "Classroom"}</h1>
      </div>
      <p className={styles.lead}>
        {student
          ? "Your own sessions. Open one to review what happened or start a quiz."
          : viewer.kind === "firewall_admin"
            ? "All sessions, read-only."
            : "Every session in the class. Open one to see the transcript, the firewall decisions and the quiz."}
      </p>
      <ScreenNav kind={viewer.kind} current="sessions" />
      {!loaded.ok ? (
        loaded.reason === "forbidden" ? (
          <AccessDenied what="the sessions list" home="/" />
        ) : (
          <Unavailable what="sessions" />
        )
      ) : (
        <>
          <FilterForm filters={filters} kind={viewer.kind} levels={list?.levels ?? []} />
          <p className={styles.count} aria-live="polite">
            {rows.length} {rows.length === 1 ? "session" : "sessions"}
          </p>
          <SessionsTable rows={rows} />
        </>
      )}
    </main>
  );
}
