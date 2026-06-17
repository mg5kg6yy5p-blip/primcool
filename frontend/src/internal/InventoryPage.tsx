import { useEffect, useState } from "react";
import { api, ValidationError } from "../api";
import type { FieldErrors, Material, StockLocation, StockQuant } from "../types";

export function InventoryPage() {
  const [materials, setMaterials] = useState<Material[]>([]);
  const [locations, setLocations] = useState<StockLocation[]>([]);
  const [stock, setStock] = useState<StockQuant[]>([]);

  const load = async () => {
    setMaterials(await api.listMaterials());
    setLocations(await api.listStockLocations());
    setStock(await api.listStock());
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="cols">
      <section>
        <h2>Materials</h2>
        <table>
          <thead><tr><th>Part #</th><th>Description</th><th>Unit cost</th></tr></thead>
          <tbody>
            {materials.map((m) => (
              <tr key={m.id}>
                <td>{m.part_number}</td><td>{m.description}</td>
                <td>{m.currency} {m.unit_cost.toFixed(2)}</td>
              </tr>
            ))}
            {materials.length === 0 && <tr><td colSpan={3}><em>None</em></td></tr>}
          </tbody>
        </table>
        <NewMaterial onAdded={load} />

        <h3>Stock locations</h3>
        <ul>
          {locations.map((l) => <li key={l.id}>{l.name} <small>{l.kind}</small></li>)}
          {locations.length === 0 && <li><em>None</em></li>}
        </ul>
        <NewLocation onAdded={load} />
      </section>

      <section>
        <h2>Stock balances</h2>
        <table>
          <thead><tr><th>Part #</th><th>Location</th><th>Qty</th></tr></thead>
          <tbody>
            {stock.map((s) => (
              <tr key={s.id}>
                <td>{materials.find((m) => m.id === s.material_id)?.part_number}</td>
                <td>{locations.find((l) => l.id === s.stock_location_id)?.name}</td>
                <td>{s.qty}</td>
              </tr>
            ))}
            {stock.length === 0 && <tr><td colSpan={3}><em>No stock</em></td></tr>}
          </tbody>
        </table>
        <SetStock materials={materials} locations={locations} onSet={load} />
      </section>
    </div>
  );
}

function NewMaterial({ onAdded }: { onAdded: () => void }) {
  const [partNumber, setPartNumber] = useState("");
  const [description, setDescription] = useState("");
  const [unitCost, setUnitCost] = useState("0");
  const [errors, setErrors] = useState<FieldErrors>({});

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createMaterial({
        part_number: partNumber, description, unit_cost: parseFloat(unitCost) || 0,
      });
      setPartNumber(""); setDescription("");
      onAdded();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }
  return (
    <form onSubmit={add} className="card">
      <h3>New material</h3>
      <label>
        Part number
        <input value={partNumber} onChange={(e) => setPartNumber(e.target.value)} />
        {errors.part_number && <span className="field-error">{errors.part_number}</span>}
      </label>
      <label>
        Description
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      <label>
        Unit cost (JMD)
        <input type="number" value={unitCost} onChange={(e) => setUnitCost(e.target.value)} />
      </label>
      <button type="submit">Add</button>
    </form>
  );
}

function NewLocation({ onAdded }: { onAdded: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState("shop");
  async function add(e: React.FormEvent) {
    e.preventDefault();
    await api.createStockLocation({ name, kind });
    setName("");
    onAdded();
  }
  return (
    <form onSubmit={add} className="card">
      <h3>New stock location</h3>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label>
        Kind
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="shop">shop</option>
          <option value="van">van</option>
        </select>
      </label>
      <button type="submit">Add</button>
    </form>
  );
}

function SetStock({
  materials,
  locations,
  onSet,
}: {
  materials: Material[];
  locations: StockLocation[];
  onSet: () => void;
}) {
  const [materialId, setMaterialId] = useState("");
  const [locationId, setLocationId] = useState("");
  const [qty, setQty] = useState("0");

  async function go(e: React.FormEvent) {
    e.preventDefault();
    await api.setStock({
      material_id: materialId, stock_location_id: locationId, qty: parseFloat(qty) || 0,
    });
    setQty("0");
    onSet();
  }
  return (
    <form onSubmit={go} className="card">
      <h3>Set stock</h3>
      <label>
        Material
        <select value={materialId} onChange={(e) => setMaterialId(e.target.value)}>
          <option value="">—</option>
          {materials.map((m) => <option key={m.id} value={m.id}>{m.part_number}</option>)}
        </select>
      </label>
      <label>
        Location
        <select value={locationId} onChange={(e) => setLocationId(e.target.value)}>
          <option value="">—</option>
          {locations.map((l) => <option key={l.id} value={l.id}>{l.name}</option>)}
        </select>
      </label>
      <label>
        Qty
        <input type="number" value={qty} onChange={(e) => setQty(e.target.value)} />
      </label>
      <button type="submit" disabled={!materialId || !locationId}>Set</button>
    </form>
  );
}
