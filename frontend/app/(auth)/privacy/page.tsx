// Privacy notice (PRD §4.3 step 2, §15.2). Linked from sign-up because Divert collects network data.
export default function Privacy() {
  return (
    <main>
      <h1>Privacy notice</h1>
      <p className="panel">
        This is a security training arena. Suspicious actions may log your IP address, network and
        browser details for 30 days.
      </p>
      <ul>
        <li>Network details are stored as a salted hash of your IP plus its subnet, never in clear.</li>
        <li>Only firewall admins can see them. Teachers see that a divert happened, not network data.</li>
        <li>They are deleted after 30 days.</li>
        <li>Students see only their own sessions.</li>
      </ul>
    </main>
  );
}
