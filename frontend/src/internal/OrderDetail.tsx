import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { AuditLog, Operation, OrderStatus, WorkOrder } from "../types";
import { StatusChip } from "../components/StatusChip";

type Tab = "operations" | "parts" | "costs" | "history";

export function OrderDetail({
  orderId,
  onChanged,
}: {
  orderId: string;
  onChanged: () => void;
}) {
  const [order, setOrder] = useState<WorkOrder | null>(null);
  const [tab, setTab] = useState<Tab>("operations");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setOrder(await api.getWorkOrder(orderId));
  }, [orderId]);
  useEffect(() => { refresh(); }, [refresh]);

  if (!order) return <p>Loading…</p>;

  async function transition(target: OrderStatus) {
    setError("");
    try {
      await api.transitionOrder(orderId, target);
      await refresh();
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  return (
    <div>
      <h2>{order.title} <StatusChip status={order.status} /></h2>
      <p>
        <StatusChip status={order.priority} /> · {order.order_type} · billing{" "}
        {order.billing_class}
      </p>

      <div className="actions">
        {/* Transition buttons rendered ONLY for legal next states. */}
        {order.legal_transitions.map((t) => (
          <button key={t} onClick={() => transition(t)}>→ {t.replace(/_/g, " ")}</button>
        ))}
        {order.legal_transitions.length === 0 && <em>Terminal — no transitions</em>}
      </div>
      {error && <p className="field-error">{error}</p>}

      <nav className="tabs">
        {(["operations", "parts", "costs", "history"] as Tab[]).map((t) => (
          <button
            key={t}
            className={tab === t ? "tab active" : "tab"}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </nav>

      {tab === "operations" && (
        <OperationsTab orderId={orderId} frozen={order.status !== "created" &&
          order.status !== "scheduled" && order.status !== "in_progress"} />
      )}
      {tab === "parts" && <p><em>Parts consumption lands in Phase 3.</em></p>}
      {tab === "costs" && <p><em>Cost rollup lands in Phase 5 (billing).</em></p>}
      {tab === "history" && <HistoryTab orderId={orderId} />}
    </div>
  );
}

function OperationsTab({ orderId, frozen }: { orderId: string; frozen: boolean }) {
  const [ops, setOps] = useState<Operation[]>([]);
  const [description, setDescription] = useState("");
  const [hours, setHours] = useState("1");

  const load = useCallback(() => { api.listOperations(orderId).then(setOps); }, [orderId]);
  useEffect(() => { load(); }, [load]);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    await api.addOperation(orderId, {
      description, planned_hours: parseFloat(hours) || 0,
    });
    setDescription("");
    load();
  }

  return (
    <div>
      <table>
        <thead><tr><th>#</th><th>Description</th><th>Planned h</th><th>Status</th></tr></thead>
        <tbody>
          {ops.map((o) => (
            <tr key={o.id}>
              <td>{o.sequence}</td><td>{o.description}</td>
              <td>{o.planned_hours}</td><td><StatusChip status={o.status} /></td>
            </tr>
          ))}
          {ops.length === 0 && <tr><td colSpan={4}><em>No operations</em></td></tr>}
        </tbody>
      </table>
      {!frozen && (
        <form onSubmit={add} className="card">
          <h3>Add operation</h3>
          <label>
            Description
            <input value={description} onChange={(e) => setDescription(e.target.value)} />
          </label>
          <label>
            Planned hours
            <input type="number" value={hours} onChange={(e) => setHours(e.target.value)} />
          </label>
          <button type="submit">Add</button>
        </form>
      )}
    </div>
  );
}

function HistoryTab({ orderId }: { orderId: string }) {
  const [rows, setRows] = useState<AuditLog[]>([]);
  useEffect(() => { api.listAudit("work_order", orderId).then(setRows); }, [orderId]);
  return (
    <ol className="timeline">
      {rows.map((r) => (
        <li key={r.id}>
          <span className="ts">{new Date(r.at).toLocaleString()}</span>
          <strong>{r.action.replace(/_/g, " ")}</strong>
        </li>
      ))}
      {rows.length === 0 && <li><em>No audit entries</em></li>}
    </ol>
  );
}
