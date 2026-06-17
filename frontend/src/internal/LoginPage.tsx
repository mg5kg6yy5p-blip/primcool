import { useState } from "react";
import { useAuth } from "../auth";

export function LoginPage() {
  const { usersExist, login, bootstrap } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (usersExist) await login(email, password);
      else await bootstrap(email, password, fullName);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <h1>{usersExist ? "Sign in" : "Create the first admin"}</h1>
      <form onSubmit={submit} className="card">
        {!usersExist && (
          <label>
            Full name
            <input value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </label>
        )}
        <label>
          Email
          <input
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete={usersExist ? "current-password" : "new-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && <p className="field-error">{error}</p>}
        <button type="submit" disabled={busy || !email || !password}>
          {busy ? "…" : usersExist ? "Sign in" : "Create admin"}
        </button>
      </form>
    </main>
  );
}
