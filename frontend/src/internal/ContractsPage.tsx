import { useEffect, useState } from "react";
import { api, ValidationError } from "../api";
import type {
  CustomerAccount,
  FieldErrors,
  ServiceContract,
  Site,
} from "../types";
import { StatusChip } from "../components/StatusChip";

export function ContractsPage() {
  const [contracts, setContracts] = useState<ServiceContract[]>([]);
  const load = () => api.listContracts().then(setContracts);
  useEffect(() => { load(); }, []);

  return (
    <div className="cols">
      <section>
        <h2>Service contracts</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Period</th>
              <th>PM entitlement</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {contracts.map((c) => (
              <tr key={c.id}>
                <td>{c.name}</td>
                <td>{c.starts_on} → {c.ends_on}</td>
                <td>
                  <EntitlementMeter
                    used={c.used_this_year}
                    total={c.included_pm_visits_per_year}
                  />
                </td>
                <td><StatusChip status={c.status} /></td>
              </tr>
            ))}
            {contracts.length === 0 && <tr><td colSpan={4}><em>None</em></td></tr>}
          </tbody>
        </table>
      </section>
      <section>
        <NewContract onCreated={load} />
      </section>
    </div>
  );
}

function EntitlementMeter({ used, total }: { used: number; total: number }) {
  const pct = total === 0 ? 0 : Math.min(100, Math.round((used / total) * 100));
  return (
    <div className="meter">
      <span>{used} of {total} used</span>
      <div className="bar"><div style={{ width: `${pct}%` }} /></div>
    </div>
  );
}

function NewContract({ onCreated }: { onCreated: () => void }) {
  const [customers, setCustomers] = useState<CustomerAccount[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [customerId, setCustomerId] = useState("");
  const [siteIds, setSiteIds] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [startsOn, setStartsOn] = useState("");
  const [endsOn, setEndsOn] = useState("");
  const [pmCount, setPmCount] = useState("4");
  const [errors, setErrors] = useState<FieldErrors>({});

  useEffect(() => { api.listCustomers().then(setCustomers); }, []);
  useEffect(() => {
    if (customerId) api.listSites(customerId).then(setSites);
    else setSites([]);
    setSiteIds([]);
  }, [customerId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createContract({
        customer_account_id: customerId,
        name,
        starts_on: startsOn,
        ends_on: endsOn,
        included_pm_visits_per_year: parseInt(pmCount, 10) || 0,
        site_ids: siteIds,
      });
      setName(""); setStartsOn(""); setEndsOn("");
      onCreated();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }

  function toggleSite(id: string) {
    setSiteIds((s) => s.includes(id) ? s.filter((x) => x !== id) : [...s, id]);
  }

  return (
    <form onSubmit={submit} className="card">
      <h3>New contract</h3>
      <label>
        Customer
        <select value={customerId} onChange={(e) => setCustomerId(e.target.value)}>
          <option value="">—</option>
          {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </label>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} />
        {errors.name && <span className="field-error">{errors.name}</span>}
      </label>
      <label>
        Starts on
        <input type="date" value={startsOn} onChange={(e) => setStartsOn(e.target.value)} />
      </label>
      <label>
        Ends on
        <input type="date" value={endsOn} onChange={(e) => setEndsOn(e.target.value)} />
      </label>
      <label>
        Included PM visits per year
        <input type="number" value={pmCount} onChange={(e) => setPmCount(e.target.value)} />
      </label>
      {sites.length > 0 && (
        <fieldset className="site-chips">
          <legend>Covered sites</legend>
          {sites.map((s) => (
            <label key={s.id} className="site-chip">
              <input type="checkbox" checked={siteIds.includes(s.id)}
                     onChange={() => toggleSite(s.id)} />
              {s.name}
            </label>
          ))}
        </fieldset>
      )}
      <button type="submit" disabled={!customerId || !name || !startsOn || !endsOn}>
        Create
      </button>
    </form>
  );
}
