import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { SavedView, Severity, WorkOrder } from "../types";
import { StatusChip } from "../components/StatusChip";
import { OrderDetail } from "./OrderDetail";

const PRIORITIES: Severity[] = ["emergency", "high", "medium", "low"];

export function WorkQueuePage() {
  const [orders, setOrders] = useState<WorkOrder[]>([]);
  const [views, setViews] = useState<SavedView[]>([]);
  const [viewId, setViewId] = useState("");
  const [priority, setPriority] = useState("");
  const [includeClosed, setIncludeClosed] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = useCallback(() => {
    const qs = new URLSearchParams();
    if (viewId) qs.set("view_id", viewId);
    if (priority) qs.set("priority", priority);
    if (includeClosed) qs.set("include_closed", "true");
    api.listWorkOrders(qs.toString()).then(setOrders);
  }, [viewId, priority, includeClosed]);

  useEffect(() => { api.listSavedViews().then(setViews); }, []);
  useEffect(() => { load(); }, [load]);

  return (
    <div className="cols">
      <section>
        <h2>Work queue</h2>
        <div className="chips">
          <label className="chip">
            View
            <select value={viewId} onChange={(e) => setViewId(e.target.value)}>
              <option value="">— all —</option>
              {views.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
          </label>
          <label className="chip">
            Priority
            <select value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="">any</option>
              {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label className="chip">
            <input type="checkbox" checked={includeClosed}
              onChange={(e) => setIncludeClosed(e.target.checked)} />
            Include closed/cancelled
          </label>
        </div>

        <table>
          <thead><tr><th>Priority</th><th>Title</th><th>Type</th><th>Status</th></tr></thead>
          <tbody>
            {orders.map((o) => (
              <tr key={o.id} className="clickable" onClick={() => setSelectedId(o.id)}>
                <td><StatusChip status={o.priority} /></td>
                <td>{o.title}</td>
                <td>{o.order_type}</td>
                <td><StatusChip status={o.status} /></td>
              </tr>
            ))}
            {orders.length === 0 && <tr><td colSpan={4}><em>No work orders</em></td></tr>}
          </tbody>
        </table>
      </section>

      <section>
        {selectedId
          ? <OrderDetail orderId={selectedId} onChanged={load} />
          : <h2>Select a work order</h2>}
      </section>
    </div>
  );
}
