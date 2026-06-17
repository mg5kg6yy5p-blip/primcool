import { useEffect, useState } from "react";
import { api, ValidationError } from "../api";
import type { AssetClass, Equipment, FieldErrors } from "../types";
import { StatusChip } from "../components/StatusChip";
import { EquipmentDetail } from "./EquipmentDetail";

const CLASSES: AssetClass[] = [
  "split_ac", "central_ahu", "package_unit", "chiller", "cooling_tower", "exhaust", "other",
];

export function EquipmentPage() {
  const [items, setItems] = useState<Equipment[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [serial, setSerial] = useState("");
  const [klass, setKlass] = useState<AssetClass>("package_unit");
  const [errors, setErrors] = useState<FieldErrors>({});

  const load = () => api.listEquipment().then(setItems);
  useEffect(() => { load(); }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createEquipment({ serial: serial || null, equipment_class: klass });
      setSerial("");
      load();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }

  return (
    <div className="cols">
      <section>
        <h2>Equipment register</h2>
        <table>
          <thead><tr><th>Serial</th><th>Class</th><th>Status</th></tr></thead>
          <tbody>
            {items.map((e) => (
              <tr key={e.id} className="clickable" onClick={() => setSelectedId(e.id)}>
                <td>{e.serial ?? <em>—</em>}</td>
                <td>{e.equipment_class.replace(/_/g, " ")}</td>
                <td><StatusChip status={e.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>

        <form onSubmit={submit} className="card">
          <h3>New equipment</h3>
          <label>
            Serial (optional)
            <input value={serial} onChange={(e) => setSerial(e.target.value)} />
            {errors.serial && <span className="field-error">{errors.serial}</span>}
          </label>
          <label>
            Class
            <select value={klass} onChange={(e) => setKlass(e.target.value as AssetClass)}>
              {CLASSES.map((c) => <option key={c} value={c}>{c.replace(/_/g, " ")}</option>)}
            </select>
          </label>
          <button type="submit">Create</button>
        </form>
      </section>

      <section>
        {selectedId
          ? <EquipmentDetail equipmentId={selectedId} onChanged={load} />
          : <h2>Select equipment for its timeline</h2>}
      </section>
    </div>
  );
}
