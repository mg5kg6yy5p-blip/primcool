import { createContext, useCallback, useContext, useEffect, useState } from "react";

export type Role = "admin" | "dispatcher" | "technician" | "portal_user";

export interface CurrentUser {
  id: string;
  email: string;
  full_name: string;
  role: Role;
  customer_account_id: string | null;
  is_active: boolean;
}

interface AuthCtx {
  user: CurrentUser | null;
  loading: boolean;
  usersExist: boolean;
  login: (email: string, password: string) => Promise<void>;
  bootstrap: (email: string, password: string, fullName: string) => Promise<void>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

const TOKEN_KEY = "primcool.token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [usersExist, setUsersExist] = useState(true);

  const refreshMe = useCallback(async () => {
    const token = getToken();
    if (!token) { setUser(null); setLoading(false); return; }
    const res = await fetch("/api/auth/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) setUser(await res.json());
    else { setToken(null); setUser(null); }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetch("/api/auth/status").then(async (r) => {
      if (r.ok) setUsersExist((await r.json()).users_exist);
    });
    refreshMe();
  }, [refreshMe]);

  async function login(email: string, password: string) {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? "Login failed");
    }
    const { access_token } = await res.json();
    setToken(access_token);
    setUsersExist(true);
    await refreshMe();
  }

  async function bootstrap(email: string, password: string, fullName: string) {
    const res = await fetch("/api/auth/bootstrap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, full_name: fullName }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? "Bootstrap failed");
    }
    const { access_token } = await res.json();
    setToken(access_token);
    setUsersExist(true);
    await refreshMe();
  }

  function logout() {
    setToken(null);
    setUser(null);
  }

  return (
    <Ctx.Provider value={{ user, loading, usersExist, login, bootstrap, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth(): AuthCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
