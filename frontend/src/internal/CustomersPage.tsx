import { useEffect, useState } from "react";
import { api, ValidationError } from "../api";
import type { CustomerAccount, CustomerType, FieldErrors, Site } from "../types";
import { StatusChip } from "../components/StatusChip";

const TYPES: CustomerType[] = [
  "apartment_complex", "strip_mall", "commercial", "residential",
];

export function CustomersPage() {
  const [customers, setCustomers] = useState<CustomerAccount[]>([]);
  const [selected, setSelected] = useState<CustomerAccount | null>(null);
  const [sites, setSites] = useState<Site[]>([]);
  const [name, setName] = useState("");
  const [type, setType] = useState<CustomerType>("apartment_complex");
  const [errors, setErrors] = useState<FieldErrors>({});

  const load = () => api.listCustomers().then(setCustomers);
  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (selected) api.listSites(selected.id).then(setSites);
    else setSites([]);
  }, [selected]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createCustomer({ name, type });
      setName("");
      load();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }

  return (
    <div className="cols">
      <section>
        <h2>Customers</h2>
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Status</th></tr></thead>
          <tbody>
            {customers.map((c) => (
              <tr key={c.id} className="clickable" onClick={() => setSelected(c)}>
                <td>{c.name}</td>
                <td>{c.type.replace(/_/g, " ")}</td>
                <td><StatusChip status={c.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>

        <form onSubmit={submit} className="card">
          <h3>New customer</h3>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} />
            {errors.name && <span className="field-error">{errors.name}</span>}
          </label>
          <label>
            Type
            <select value={type} onChange={(e) => setType(e.target.value as CustomerType)}>
              {TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ")}</option>)}
            </select>
          </label>
          <button type="submit">Create</button>
        </form>
      </section>

      <section>
        <h2>{selected ? `${selected.name} — sites` : "Select a customer"}</h2>
        {selected && (
          <>
            <ul>
              {sites.map((s) => <li key={s.id}>{s.name} <small>{s.address}</small></li>)}
              {sites.length === 0 && <li><em>No sites yet</em></li>}
            </ul>
            <AddSite customerId={selected.id} onAdded={() =>
              api.listSites(selected.id).then(setSites)} />
          </>
        )}
      </section>
    </div>
  );
}

function AddSite({ customerId, onAdded }: { customerId: string; onAdded: () => void }) {
  const [name, setName] = useState("");
  const [errors, setErrors] = useState<FieldErrors>({});
  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createSite({ customer_account_id: customerId, name });
      setName("");
      onAdded();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }
  return (
    <form onSubmit={add} className="card">
      <h3>Add site</h3>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} />
        {errors.name && <span className="field-error">{errors.name}</span>}
      </label>
      <button type="submit">Add</button>
    </form>
  );
}
