import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "../api";
import type {
  Confirmation,
  Material,
  Operation,
  StockLocation,
  WorkOrder,
} from "../types";
import { StatusChip } from "../components/StatusChip";

/** Order detail for the technician — three taps from the queue to a final
 * confirmation: tap order, tap Confirm on the operation, fill + submit. */
export function TechOrder() {
  const { orderId } = useParams<{ orderId: string }>();
  const [order, setOrder] = useState<WorkOrder | null>(null);
  const [ops, setOps] = useState<Operation[]>([]);
  const [confirmingOp, setConfirmingOp] = useState<Operation | null>(null);

  const refresh = useCallback(async () => {
    if (!orderId) return;
    setOrder(await api.getWorkOrder(orderId));
    setOps(await api.listOperations(orderId));
  }, [orderId]);
  useEffect(() => { refresh(); }, [refresh]);

  if (!order) return <p>Loading…</p>;

  return (
    <section className="tech-order">
      <Link to="/tech" className="back">← My queue</Link>
      <h2>{order.title}</h2>
      <p>
        <StatusChip status={order.priority} /> · <StatusChip status={order.status} />
      </p>
      <p>{order.description || <em>No description</em>}</p>

      <h3>Operations</h3>
      <ul className="tech-ops">
        {ops.map((op) => (
          <li key={op.id}>
            <div>
              <strong>{op.description || "(no description)"}</strong>{" "}
              <StatusChip status={op.status} />
            </div>
            <small>planned {op.planned_hours}h</small>
            {op.status === "open" && (
              <button onClick={() => setConfirmingOp(op)}>Confirm</button>
            )}
            <ConfirmHistory operationId={op.id} />
          </li>
        ))}
      </ul>

      {confirmingOp && (
        <ConfirmDialog
          operation={confirmingOp}
          onClose={() => setConfirmingOp(null)}
          onDone={() => { setConfirmingOp(null); refresh(); }}
        />
      )}
    </section>
  );
}

function ConfirmHistory({ operationId }: { operationId: string }) {
  const [rows, setRows] = useState<Confirmation[]>([]);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (open) api.listOperationConfirmations(operationId).then(setRows);
  }, [open, operationId]);

  return (
    <div className="cnf-history">
      <button onClick={() => setOpen((x) => !x)} className="link">
        {open ? "Hide" : "Show"} confirmations ({rows.length || "…"})
      </button>
      {open && rows.length === 0 && <p><em>None yet</em></p>}
      {open && rows.map((c) => (
        <div key={c.id} className="cnf-row">
          <span className="ts">{new Date(c.at).toLocaleString()}</span>
          <span>{c.actual_hours}h · {c.is_final ? "final" : "partial"}</span>
          {c.reversal_of_id && <span className="rev">reversal</span>}
          {!c.reversal_of_id && <ReverseButton id={c.id} />}
        </div>
      ))}
    </div>
  );
}

function ReverseButton({ id }: { id: string }) {
  const [reason, setReason] = useState("");
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  async function go() {
    setError("");
    try {
      await api.reverseConfirmation(id, reason);
      setOpen(false);
      setReason("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }
  if (!open) return <button className="link" onClick={() => setOpen(true)}>Reverse</button>;
  return (
    <span className="reverse-inline">
      <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason" />
      <button disabled={!reason} onClick={go}>Confirm reversal</button>
      <button className="link" onClick={() => setOpen(false)}>Cancel</button>
      {error && <span className="field-error">{error}</span>}
    </span>
  );
}

function ConfirmDialog({
  operation,
  onClose,
  onDone,
}: {
  operation: Operation;
  onClose: () => void;
  onDone: () => void;
}) {
  const [hours, setHours] = useState(String(operation.planned_hours || 1));
  const [isFinal, setIsFinal] = useState(true);
  const [notes, setNotes] = useState("");
  const [materials, setMaterials] = useState<Material[]>([]);
  const [locations, setLocations] = useState<StockLocation[]>([]);
  const [parts, setParts] = useState<
    { material_id: string; stock_location_id: string; qty_used: number }[]
  >([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.listMaterials().then(setMaterials);
    api.listStockLocations().then(setLocations);
  }, []);

  function addPart() {
    setParts((p) => [
      ...p,
      { material_id: materials[0]?.id ?? "", stock_location_id: locations[0]?.id ?? "", qty_used: 1 },
    ]);
  }

  async function submit() {
    setBusy(true);
    setError("");
    try {
      await api.confirmOperation(operation.id, {
        actual_hours: parseFloat(hours) || 0,
        is_final: isFinal,
        notes,
        parts: parts.filter((p) => p.material_id && p.stock_location_id && p.qty_used > 0),
      });
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dialog-back">
      <div className="dialog">
        <h3>Confirm operation</h3>
        <p>{operation.description}</p>
        <label>
          Actual hours
          <input type="number" step="0.25" value={hours}
                 onChange={(e) => setHours(e.target.value)} />
        </label>
        <label>
          <input type="checkbox" checked={isFinal}
                 onChange={(e) => setIsFinal(e.target.checked)} />
          Final confirmation
        </label>
        <label>
          Notes
          <input value={notes} onChange={(e) => setNotes(e.target.value)} />
        </label>

        <h4>Parts</h4>
        {parts.map((p, i) => (
          <div key={i} className="part-row">
            <select value={p.material_id}
                    onChange={(e) => setParts((arr) =>
                      arr.map((x, j) => j === i ? { ...x, material_id: e.target.value } : x))}>
              {materials.map((m) => <option key={m.id} value={m.id}>{m.part_number}</option>)}
            </select>
            <select value={p.stock_location_id}
                    onChange={(e) => setParts((arr) =>
                      arr.map((x, j) =>
                        j === i ? { ...x, stock_location_id: e.target.value } : x))}>
              {locations.map((l) => <option key={l.id} value={l.id}>{l.name}</option>)}
            </select>
            <input type="number" step="0.5" value={p.qty_used}
                   onChange={(e) => setParts((arr) =>
                     arr.map((x, j) =>
                       j === i ? { ...x, qty_used: parseFloat(e.target.value) || 0 } : x))} />
            <button className="link" onClick={() =>
              setParts((arr) => arr.filter((_, j) => j !== i))}>×</button>
          </div>
        ))}
        <button className="link" onClick={addPart} disabled={materials.length === 0}>
          + add part
        </button>

        {error && <p className="field-error">{error}</p>}
        <div className="actions">
          <button onClick={submit} disabled={busy}>Submit</button>
          <button className="link" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
