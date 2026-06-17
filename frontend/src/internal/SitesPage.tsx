import { useEffect, useState } from "react";
import { api, ValidationError } from "../api";
import type { Building, FieldErrors, Site, Space, SpaceType } from "../types";

const SPACE_TYPES: SpaceType[] = [
  "residential_unit", "retail", "office", "common_area", "mechanical_room", "exterior",
];

export function SitesPage() {
  const [sites, setSites] = useState<Site[]>([]);
  const [siteId, setSiteId] = useState("");
  const [buildings, setBuildings] = useState<Building[]>([]);
  const [spaces, setSpaces] = useState<Space[]>([]);

  useEffect(() => { api.listSites().then(setSites); }, []);

  const loadChildren = (id: string) => {
    api.listBuildings(id).then(setBuildings);
    api.listSpaces(id).then(setSpaces);
  };
  useEffect(() => {
    if (siteId) loadChildren(siteId);
    else { setBuildings([]); setSpaces([]); }
  }, [siteId]);

  return (
    <section>
      <h2>Sites &amp; spaces</h2>
      <label>
        Site
        <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          <option value="">—</option>
          {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </label>

      {siteId && (
        <div className="cols">
          <div>
            <h3>Buildings</h3>
            <ul>
              {buildings.map((b) => <li key={b.id}>{b.name}</li>)}
              {buildings.length === 0 && <li><em>None</em></li>}
            </ul>
            <AddBuilding siteId={siteId} onAdded={() => loadChildren(siteId)} />
          </div>

          <div>
            <h3>Spaces</h3>
            <table>
              <thead><tr><th>Identifier</th><th>Type</th><th>Building</th></tr></thead>
              <tbody>
                {spaces.map((s) => (
                  <tr key={s.id}>
                    <td>{s.identifier}</td>
                    <td>{s.space_type.replace(/_/g, " ")}</td>
                    <td>{buildings.find((b) => b.id === s.building_id)?.name ?? "—"}</td>
                  </tr>
                ))}
                {spaces.length === 0 && <tr><td colSpan={3}><em>None</em></td></tr>}
              </tbody>
            </table>
            <AddSpace
              siteId={siteId}
              buildings={buildings}
              onAdded={() => loadChildren(siteId)}
            />
          </div>
        </div>
      )}
    </section>
  );
}

function AddBuilding({ siteId, onAdded }: { siteId: string; onAdded: () => void }) {
  const [name, setName] = useState("");
  const [errors, setErrors] = useState<FieldErrors>({});
  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createBuilding({ site_id: siteId, name });
      setName("");
      onAdded();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }
  return (
    <form onSubmit={add} className="card">
      <h3>Add building</h3>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} />
        {errors.name && <span className="field-error">{errors.name}</span>}
      </label>
      <button type="submit">Add</button>
    </form>
  );
}

function AddSpace({
  siteId,
  buildings,
  onAdded,
}: {
  siteId: string;
  buildings: Building[];
  onAdded: () => void;
}) {
  const [identifier, setIdentifier] = useState("");
  const [spaceType, setSpaceType] = useState<SpaceType>("residential_unit");
  const [buildingId, setBuildingId] = useState("");
  const [errors, setErrors] = useState<FieldErrors>({});
  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createSpace({
        site_id: siteId,
        identifier,
        space_type: spaceType,
        building_id: buildingId || null,
      });
      setIdentifier("");
      onAdded();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }
  return (
    <form onSubmit={add} className="card">
      <h3>Add space</h3>
      <label>
        Identifier
        <input value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
        {errors.identifier && <span className="field-error">{errors.identifier}</span>}
      </label>
      <label>
        Type
        <select value={spaceType} onChange={(e) => setSpaceType(e.target.value as SpaceType)}>
          {SPACE_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ")}</option>)}
        </select>
      </label>
      <label>
        Building (optional)
        <select value={buildingId} onChange={(e) => setBuildingId(e.target.value)}>
          <option value="">— none —</option>
          {buildings.map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
        </select>
      </label>
      <button type="submit">Add</button>
    </form>
  );
}
