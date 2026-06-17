import { useEffect, useState } from "react";
import { api, ValidationError } from "../api";
import type { AssetClass, FieldErrors, FunctionalLocation, Site } from "../types";
import { StatusChip } from "../components/StatusChip";

const CLASSES: AssetClass[] = [
  "split_ac", "central_ahu", "package_unit", "chiller", "cooling_tower", "exhaust", "other",
];

export function AssetTreePage() {
  const [sites, setSites] = useState<Site[]>([]);
  const [siteId, setSiteId] = useState("");
  const [fls, setFLs] = useState<FunctionalLocation[]>([]);
  const [name, setName] = useState("");
  const [klass, setKlass] = useState<AssetClass>("package_unit");
  const [errors, setErrors] = useState<FieldErrors>({});

  useEffect(() => { api.listSites().then(setSites); }, []);
  const loadFLs = (id: string) => api.listFLs(id).then(setFLs);
  useEffect(() => { if (siteId) loadFLs(siteId); else setFLs([]); }, [siteId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createFL({ site_id: siteId, name, fl_class: klass });
      setName("");
      loadFLs(siteId);
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }

  // Render FL parent/child as a shallow tree.
  const roots = fls.filter((f) => !f.parent_fl_id);
  const childrenOf = (id: string) => fls.filter((f) => f.parent_fl_id === id);

  return (
    <section>
      <h2>Functional locations</h2>
      <label>
        Site
        <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          <option value="">—</option>
          {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </label>

      {siteId && (
        <>
          <ul className="tree">
            {roots.map((f) => (
              <li key={f.id}>
                {f.name} <small>{f.fl_class.replace(/_/g, " ")}</small>{" "}
                <StatusChip status={f.status} />
                {childrenOf(f.id).length > 0 && (
                  <ul>
                    {childrenOf(f.id).map((c) => (
                      <li key={c.id}>{c.name} <small>{c.fl_class}</small></li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
            {roots.length === 0 && <li><em>No functional locations yet</em></li>}
          </ul>

          <form onSubmit={submit} className="card">
            <h3>New functional location</h3>
            <label>
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} />
              {errors.name && <span className="field-error">{errors.name}</span>}
            </label>
            <label>
              Class
              <select value={klass} onChange={(e) => setKlass(e.target.value as AssetClass)}>
                {CLASSES.map((c) => <option key={c} value={c}>{c.replace(/_/g, " ")}</option>)}
              </select>
            </label>
            <button type="submit">Create</button>
          </form>
        </>
      )}
    </section>
  );
}
