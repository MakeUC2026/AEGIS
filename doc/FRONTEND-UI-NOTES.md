# Frontend UI rebuild (feature/frontend_ui)

Base: `origin/master` (M1 + M4 + M2 early seam), plus `origin/m3/aff-intel-admin` merged in locally
(merge commit 3b02cee, not pushed, not on master). Design lead: Codex. Built by Claude.

## Shape
- Theme "AEGIS Learning Console" (`frontend/app/globals.css`), sidebar shell with two sections,
  **Agent Framework** and **Classroom** (`components/shell/`), AEGIS "A" mark in `Icon.tsx`.
- Student: Practice (3 levels) → chat; Classroom home cards (Quizzes, My sessions, Practice);
  My sessions shows what was tried and what stopped it (arena recap) per closed session.
- Teacher: Classroom only. Sessions are cards; Insights is a fixed 6-column grid (no holes).
- Admin: Overview (KPI cards + recent events), Live firewall (events / forensics / audit) and the
  Console (`/admin` → review queue; tabs: review, rules, levels, drafts, risky patterns, diverts).
  This session owns the console frontend; M3 owns its API (`backend/app/admin/router.py`).
- Backend: firewall_admin may READ insights and quizzes; writes stay owner/teacher only.

## No mock data
- Frontend mock files and the classroom demo seed hook are gone. Every screen calls the real API.
- Realistic data comes from real chats: `scripts/seed_chats.py` signs in the dev students and sends
  attack conversations through the arena API (`uv run python ../scripts/seed_chats.py` in backend/).
- Dev env: `AEGIS_USE_FAKES=firewall,read,admin,judge` (arena and risky history are real).

## Waiting for M2
These screens show "Waiting for M2" until M2's firewall seams (`app.firewall.interface`,
`read_api`, `admin_api`) land; the dev fakes return empty lists for them:
Overview KPIs + recent events, Live firewall events, Review queue, Diverts, and the Insights cards
Decisions per mode, Rules fired most, Attack families, Risky patterns (and the diverts count).
No frontend change is needed when M2 lands: they already call the real endpoints.

## Dev note
- In `next dev`, open http://localhost:3000 (not 127.0.0.1): Next blocks dev resources cross-origin
  and the page will not hydrate.
