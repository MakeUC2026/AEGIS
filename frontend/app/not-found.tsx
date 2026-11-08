import Link from "next/link";

// Themed 404 (Next's default page ignores the app styles).
export default function NotFound() {
  return (
    <main>
      <p className="eyebrow">404</p>
      <h1>Nothing here</h1>
      <p className="muted">This page does not exist or you cannot open it.</p>
      <Link className="btn-alt" href="/">
        Go home
      </Link>
    </main>
  );
}
