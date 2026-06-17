import { useEffect, useState } from "react";
import { useAuth } from "../auth";
import { portalApi } from "./portalApi";
import type {
  Notification,
  NotificationCategory,
  Severity,
  Site,
  WorkOrder,
} from "../types";
import { StatusChip } from "../components/StatusChip";

const CATEGORIES: NotificationCategory[] = [
  "cooling", "heating", "leak", "electrical", "noise", "maintenance_request", "other",
];
const SEVERITIES: Severity[] = ["emergency", "high", "medium", "low"];

export function PortalApp() {
  const { user, logout } = useAuth();
  const [sites, setSites] = useState<Site[]>([]);
  const [notifs, setNotifs] = useState<Notification[]>([]);
  const [orders, setOrders] = useState<WorkOrder[]>([]);

  const load = async () => {
    setSites(await portalApi.sites());
    setNotifs(await portalApi.notifications());
    setOrders(await portalApi.workOrders());
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="shell">
      <header>
        <span className="brand">Prime<span>Cool</span> · Customer Portal</span>
        <div className="user-badge">
          <span>{user?.full_name || user?.email}</span>
          <button onClick={logout}>Sign out</button>
        </div>
      </header>
      <main>
        <section>
          <h2>My sites</h2>
          <ul>
            {sites.map((s) => <li key={s.id}>{s.name} <small>{s.address}</small></li>)}
            {sites.length === 0 && <li><em>No sites linked yet</em></li>}
          </ul>
        </section>

        <div className="cols">
          <section>
            <h2>My requests</h2>
            <table>
              <thead><tr><th>Title</th><th>Severity</th><th>Status</th></tr></thead>
              <tbody>
                {notifs.map((n) => (
                  <tr key={n.id}>
                    <td>{n.title}</td>
                    <td><StatusChip status={n.severity} /></td>
                    <td><StatusChip status={n.status} /></td>
                  </tr>
                ))}
                {notifs.length === 0 && <tr><td colSpan={3}><em>None yet</em></td></tr>}
              </tbody>
            </table>
            <RaiseRequest sites={sites} onCreated={load} />
          </section>

          <section>
            <h2>My work orders</h2>
            <table>
              <thead><tr><th>Title</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>
                {orders.map((o) => (
                  <tr key={o.id}>
                    <td>{o.title}</td>
                    <td>{o.order_type}</td>
                    <td><StatusChip status={o.status} /></td>
                  </tr>
                ))}
                {orders.length === 0 && <tr><td colSpan={3}><em>No orders</em></td></tr>}
              </tbody>
            </table>
          </section>
        </div>
      </main>
    </div>
  );
}

function RaiseRequest({
  sites,
  onCreated,
}: {
  sites: Site[];
  onCreated: () => void;
}) {
  const { user } = useAuth();
  const [siteId, setSiteId] = useState("");
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState<NotificationCategory>("cooling");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!user?.customer_account_id) return;
    try {
      await portalApi.raiseRequest({
        customer_account_id: user.customer_account_id,
        site_id: siteId,
        category, severity, title, description,
      });
      setTitle(""); setDescription("");
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <form onSubmit={submit} className="card">
      <h3>Raise a request</h3>
      <label>
        Site
        <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          <option value="">—</option>
          {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </label>
      <label>
        Title
        <input value={title} onChange={(e) => setTitle(e.target.value)} />
      </label>
      <label>
        Category
        <select value={category}
                onChange={(e) => setCategory(e.target.value as NotificationCategory)}>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c.replace(/_/g, " ")}</option>)}
        </select>
      </label>
      <label>
        Severity
        <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
      <label>
        Description
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      {error && <p className="field-error">{error}</p>}
      <button type="submit" disabled={!siteId || !title}>Submit</button>
    </form>
  );
}
