import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import type { WorkOrder } from "../types";
import { StatusChip } from "../components/StatusChip";

/** Technician's queue: only orders assigned to them, emergency first, then
 * by due date. Tap an order to drill in. */
export function TechQueue() {
  const { user } = useAuth();
  const [orders, setOrders] = useState<WorkOrder[]>([]);

  useEffect(() => {
    if (!user) return;
    const qs = new URLSearchParams({ assigned_to_user_id: user.id }).toString();
    api.listWorkOrders(qs).then(setOrders);
  }, [user]);

  return (
    <section className="tech-list">
      <h2>My queue</h2>
      {orders.length === 0 && <p><em>Nothing assigned to you.</em></p>}
      {orders.map((o) => (
        <Link to={`/tech/orders/${o.id}`} key={o.id} className="tech-card">
          <div className="row">
            <StatusChip status={o.priority} />
            <StatusChip status={o.status} />
          </div>
          <h3>{o.title}</h3>
          <p>{o.order_type}{o.due_date && ` · due ${o.due_date}`}</p>
        </Link>
      ))}
    </section>
  );
}
