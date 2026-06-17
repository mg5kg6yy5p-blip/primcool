import { useEffect, useState } from "react";
import { api, ValidationError } from "../api";
import type {
  BillingClass,
  CustomerAccount,
  FieldErrors,
  Meter,
  PmSchedule,
  PmTriggerKind,
  Severity,
  Site,
} from "../types";

export function PmSchedulesPage() {
  const [schedules, setSchedules] = useState<PmSchedule[]>([]);
  const [scanMessage, setScanMessage] = useState("");

  const load = () => api.listPmSchedules().then(setSchedules);
  useEffect(() => { load(); }, []);

  async function scan() {
    setScanMessage("");
    const r = await api.scanPm();
    setScanMessage(
      r.generated_work_order_ids.length === 0
        ? "No schedules due."
        : `Generated ${r.generated_work_order_ids.length} work order(s).`,
    );
    load();
  }

  return (
    <div className="cols">
      <section>
        <h2>PM schedules</h2>
        <div className="actions">
          <button onClick={scan}>Run engine scan</button>
          {scanMessage && <em>{scanMessage}</em>}
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th><th>Trigger</th><th>Next due</th>
              <th>Active</th>
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td>{s.trigger_kind === "calendar"
                  ? `every ${s.interval_days}d`
                  : `every ${s.interval_value} units`}</td>
                <td>
                  {s.trigger_kind === "calendar"
                    ? (s.next_due_at ? new Date(s.next_due_at).toLocaleDateString() : "—")
                    : (s.next_due_value ?? "—")}
                </td>
                <td>
                  <input type="checkbox" checked={s.is_active}
                         onChange={async (e) => {
                           await api.patchPmSchedule(s.id, { is_active: e.target.checked });
                           load();
                         }} />
                </td>
              </tr>
            ))}
            {schedules.length === 0 && <tr><td colSpan={4}><em>None</em></td></tr>}
          </tbody>
        </table>
      </section>

      <section>
        <NewPmSchedule onCreated={load} />
      </section>
    </div>
  );
}

const TRIGGERS: PmTriggerKind[] = ["calendar", "meter"];
const BILLING: BillingClass[] = ["contract", "billable", "warranty", "goodwill"];
const PRIORITIES: Severity[] = ["emergency", "high", "medium", "low"];

function NewPmSchedule({ onCreated }: { onCreated: () => void }) {
  const [customers, setCustomers] = useState<CustomerAccount[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [meters, setMeters] = useState<Meter[]>([]);

  const [customerId, setCustomerId] = useState("");
  const [siteId, setSiteId] = useState("");
  const [name, setName] = useState("");
  const [orderTitle, setOrderTitle] = useState("");
  const [triggerKind, setTriggerKind] = useState<PmTriggerKind>("calendar");
  const [intervalDays, setIntervalDays] = useState("90");
  const [meterId, setMeterId] = useState("");
  const [intervalValue, setIntervalValue] = useState("2000");
  const [billingClass, setBillingClass] = useState<BillingClass>("contract");
  const [priority, setPriority] = useState<Severity>("medium");
  const [errors, setErrors] = useState<FieldErrors>({});

  useEffect(() => { api.listCustomers().then(setCustomers); }, []);
  useEffect(() => {
    if (customerId) api.listSites(customerId).then(setSites);
    else setSites([]);
    setSiteId("");
  }, [customerId]);
  useEffect(() => {
    if (triggerKind === "meter") {
      api.listMeters().then(setMeters).catch(() => setMeters([]));
    }
  }, [triggerKind]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      const base = {
        customer_account_id: customerId,
        site_id: siteId,
        name,
        order_title: orderTitle,
        trigger_kind: triggerKind,
        billing_class: billingClass,
        priority,
      };
      const body = triggerKind === "calendar"
        ? { ...base, interval_days: parseInt(intervalDays, 10) || 0 }
        : { ...base, meter_id: meterId, interval_value: parseFloat(intervalValue) || 0 };
      await api.createPmSchedule(body);
      setName("");
      setOrderTitle("");
      onCreated();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }

  return (
    <form onSubmit={submit} className="card">
      <h3>New PM schedule</h3>
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
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} />
        {errors.name && <span className="field-error">{errors.name}</span>}
      </label>
      <label>
        Generated work-order title
        <input value={orderTitle} onChange={(e) => setOrderTitle(e.target.value)} />
        {errors.order_title && <span className="field-error">{errors.order_title}</span>}
      </label>
      <label>
        Trigger kind
        <select value={triggerKind}
                onChange={(e) => setTriggerKind(e.target.value as PmTriggerKind)}>
          {TRIGGERS.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>
      {triggerKind === "calendar" ? (
        <label>
          Every N days
          <input type="number" value={intervalDays}
                 onChange={(e) => setIntervalDays(e.target.value)} />
        </label>
      ) : (
        <>
          <label>
            Meter
            <select value={meterId} onChange={(e) => setMeterId(e.target.value)}>
              <option value="">—</option>
              {meters.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.meter_type} ({m.unit})
                </option>
              ))}
            </select>
          </label>
          <label>
            Every N units
            <input type="number" value={intervalValue}
                   onChange={(e) => setIntervalValue(e.target.value)} />
          </label>
        </>
      )}
      <label>
        Billing class
        <select value={billingClass}
                onChange={(e) => setBillingClass(e.target.value as BillingClass)}>
          {BILLING.map((b) => <option key={b} value={b}>{b}</option>)}
        </select>
      </label>
      <label>
        Priority
        <select value={priority} onChange={(e) => setPriority(e.target.value as Severity)}>
          {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
      </label>
      <button type="submit" disabled={!customerId || !siteId}>Create</button>
    </form>
  );
}
