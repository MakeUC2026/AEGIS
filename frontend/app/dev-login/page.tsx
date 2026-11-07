import Link from "next/link";
import { notFound } from "next/navigation";

import { AuthStage } from "@/components/auth/AuthStage";
import { DEV_USERS, devAuthAllowed } from "@/lib/dev-auth";

// Dev sign-in (DD-12): pick a synthetic user. Not available in production.
export default function DevLogin() {
  if (!devAuthAllowed()) notFound();
  return (
    <AuthStage>
      <section className="auth-panel">
        <div>
          <h2>Dev sign-in</h2>
          <p className="hint">
            Local development only. Production uses Auth0 Universal Login. Read the{" "}
            <Link href="/privacy">privacy notice</Link>.
          </p>
        </div>
        <div className="auth-actions">
          {DEV_USERS.map((user) => (
            <form key={user.id} method="post" action="/dev-login/session">
              <input type="hidden" name="user" value={user.id} />
              <button className="btn-alt" type="submit">
                {user.name}
              </button>
            </form>
          ))}
        </div>
      </section>
    </AuthStage>
  );
}
