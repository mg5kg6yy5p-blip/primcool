import { useEffect, useState } from "react";
import { api, ApiError, ValidationError } from "../api";
import type {
  CustomerAccount,
  FieldErrors,
  Notification,
  NotificationCategory,
  Severity,
  Site,
} from "../types";
import { StatusChip } from "../components/StatusChip";

const CATEGORIES: NotificationCategory[] = [
  "cooling", "heating", "leak", "electrical", "noise", "maintenance_request", "other",
];
const SEVERITIES: Severity[] = ["emergency", "high", "medium", "low"];

export function TriagePage() {
  const [notifs, setNotifs] = useState<Notification[]>([]);
  const [selected, setSelected] = useState<Notification | null>(null);

  const load = () => api.listNotifications().then(setNotifs);
  useEffect(() => { load(); }, []);

  return (
    <div className="cols">
      <section>
        <h2>Triage inbox</h2>
        <table>
          <thead><tr><th>Title</th><th>Sev</th><th>Status</th></tr></thead>
          <tbody>
            {notifs.map((n) => (
              <tr key={n.id} className="clickable" onClick={() => setSelected(n)}>
                <td>{n.title}</td>
                <td><StatusChip status={n.severity} /></td>
                <td><StatusChip status={n.status} /></td>
              </tr>
            ))}
            {notifs.length === 0 && <tr><td colSpan={3}><em>Inbox empty</em></td></tr>}
          </tbody>
        </table>
        <NewNotification onCreated={load} />
      </section>

      <section>
        {selected ? (
          <TriageDrawer
            notif={selected}
            onChanged={() => { load(); api.listNotifications().then((all) =>
              setSelected(all.find((x) => x.id === selected.id) ?? null)); }}
          />
        ) : <h2>Select a request</h2>}
      </section>
    </div>
  );
}

function TriageDrawer({ notif, onChanged }: { notif: Notification; onChanged: () => void }) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const terminal = notif.status === "converted" || notif.status === "closed_no_action";

  async function run(fn: () => Promise<unknown>) {
    setError("");
    try { await fn(); onChanged(); }
    catch (err) { setError(err instanceof ApiError ? err.message : String(err)); }
  }

  return (
    <div className="card">
      <h2>{notif.title} <StatusChip status={notif.status} /></h2>
      <p>{notif.category.replace(/_/g, " ")} · severity {notif.severity}</p>
      <p>{notif.description || <em>No description</em>}</p>

      {!terminal && (
        <div className="actions">
          {notif.status === "new" && (
            <button onClick={() => run(() => api.acknowledge(notif.id))}>Acknowledge</button>
          )}
          <button onClick={() => run(() => api.convertToOrder(notif.id))}>
            Convert to work order
          </button>
          <div className="close-row">
            <input
              placeholder="reason to close"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <button
              disabled={!reason}
              onClick={() => run(() => api.closeNoAction(notif.id, reason))}
            >
              Close — no action
            </button>
          </div>
        </div>
      )}
      {terminal && <p><em>This request is {notif.status.replace(/_/g, " ")}.</em></p>}
      {error && <p className="field-error">{error}</p>}
    </div>
  );
}

function NewNotification({ onCreated }: { onCreated: () => void }) {
  const [customers, setCustomers] = useState<CustomerAccount[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [customerId, setCustomerId] = useState("");
  const [siteId, setSiteId] = useState("");
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState<NotificationCategory>("cooling");
  const [severity, setSeverity] = useState<Severity>("high");
  const [errors, setErrors] = useState<FieldErrors>({});

  useEffect(() => { api.listCustomers().then(setCustomers); }, []);
  useEffect(() => {
    if (customerId) api.listSites(customerId).then(setSites);
    else setSites([]);
    setSiteId("");
  }, [customerId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createNotification({
        customer_account_id: customerId, site_id: siteId,
        category, severity, title,
      });
      setTitle("");
      onCreated();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }

  return (
    <form onSubmit={submit} className="card">
      <h3>New request</h3>
      <label>
        Customer
        <select value={customerId} onChange={(e) => setCustomerId(e.target.value)}>
          <option value="">—</option>
          {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </label>
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
        {errors.title && <span className="field-error">{errors.title}</span>}
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
          {SEVERITIES.map((sv) => <option key={sv} value={sv}>{sv}</option>)}
        </select>
      </label>
      <button type="submit" disabled={!customerId || !siteId}>Raise request</button>
    </form>
  );
}
