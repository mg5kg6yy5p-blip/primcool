import { useCallback, useEffect, useState } from "react";
import { api, ApiError, ValidationError } from "../api";
import type {
  Equipment,
  EquipmentHistory,
  EquipmentInstall,
  FieldErrors,
  FunctionalLocation,
  Meter,
  MeterType,
  Site,
} from "../types";
import { StatusChip } from "../components/StatusChip";

export function EquipmentDetail({
  equipmentId,
  onChanged,
}: {
  equipmentId: string;
  onChanged: () => void;
}) {
  const [equipment, setEquipment] = useState<Equipment | null>(null);
  const [history, setHistory] = useState<EquipmentHistory | null>(null);
  const [active, setActive] = useState<EquipmentInstall | null>(null);

  const refresh = useCallback(async () => {
    const [eq, hist, act] = await Promise.all([
      api.getEquipment(equipmentId),
      api.equipmentHistory(equipmentId),
      api.activeInstall(equipmentId),
    ]);
    setEquipment(eq);
    setHistory(hist);
    setActive(act);
  }, [equipmentId]);

  useEffect(() => { refresh(); }, [refresh]);

  if (!equipment) return <p>Loading…</p>;

  return (
    <div>
      <h2>
        {equipment.serial ?? "Unserialised"} <StatusChip status={equipment.status} />
      </h2>
      <p>
        {equipment.manufacturer} {equipment.model} · {equipment.equipment_class.replace(/_/g, " ")}
        {equipment.warranty_months != null && ` · ${equipment.warranty_months}mo warranty`}
      </p>

      {active ? (
        <RemovePanel
          onRemove={async () => {
            await api.remove(equipmentId);
            await refresh();
            onChanged();
          }}
        />
      ) : (
        <InstallPanel
          equipmentId={equipmentId}
          onInstalled={async () => { await refresh(); onChanged(); }}
        />
      )}

      <MetersPanel equipmentId={equipmentId} onReadingAdded={refresh} />

      <h3>Timeline</h3>
      <ol className="timeline">
        {history?.events.map((ev, i) => (
          <li key={i}>
            <span className="ts">{new Date(ev.at).toLocaleString()}</span>
            <strong>{ev.kind.replace(/_/g, " ")}</strong>
            <code>{JSON.stringify(ev.detail)}</code>
          </li>
        ))}
        {history?.events.length === 0 && <li><em>No events yet</em></li>}
      </ol>
    </div>
  );
}

const METER_TYPES: MeterType[] = ["run_hours", "starts", "other"];

function MetersPanel({
  equipmentId,
  onReadingAdded,
}: {
  equipmentId: string;
  onReadingAdded: () => void;
}) {
  const [meters, setMeters] = useState<Meter[]>([]);
  const [meterType, setMeterType] = useState<MeterType>("run_hours");
  const [unit, setUnit] = useState("h");
  const [errors, setErrors] = useState<FieldErrors>({});
  const [reading, setReading] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    api.listMeters(equipmentId).then(setMeters);
  }, [equipmentId]);
  useEffect(() => { load(); }, [load]);

  async function addMeter(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    try {
      await api.createMeter({ equipment_id: equipmentId, meter_type: meterType, unit });
      load();
    } catch (err) {
      if (err instanceof ValidationError) setErrors(err.fields);
      else alert(String(err));
    }
  }

  async function addReading(meterId: string) {
    const value = parseFloat(reading[meterId] ?? "");
    if (Number.isNaN(value)) return;
    try {
      await api.addReading(meterId, value);
      setReading((r) => ({ ...r, [meterId]: "" }));
      onReadingAdded();
    } catch (err) {
      alert(String(err));
    }
  }

  return (
    <div className="card">
      <h3>Meters</h3>
      <ul>
        {meters.map((m) => (
          <li key={m.id}>
            {m.meter_type.replace(/_/g, " ")} ({m.unit || "—"})
            <span className="inline-reading">
              <input
                type="number"
                placeholder="reading"
                value={reading[m.id] ?? ""}
                onChange={(e) =>
                  setReading((r) => ({ ...r, [m.id]: e.target.value }))}
              />
              <button type="button" onClick={() => addReading(m.id)}>Log</button>
            </span>
          </li>
        ))}
        {meters.length === 0 && <li><em>No meters</em></li>}
      </ul>
      <form onSubmit={addMeter}>
        <label>
          Meter type
          <select value={meterType} onChange={(e) => setMeterType(e.target.value as MeterType)}>
            {METER_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ")}</option>)}
          </select>
        </label>
        <label>
          Unit
          <input value={unit} onChange={(e) => setUnit(e.target.value)} />
          {errors.unit && <span className="field-error">{errors.unit}</span>}
        </label>
        <button type="submit">Add meter</button>
      </form>
    </div>
  );
}

function InstallPanel({
  equipmentId,
  onInstalled,
}: {
  equipmentId: string;
  onInstalled: () => void;
}) {
  const [sites, setSites] = useState<Site[]>([]);
  const [fls, setFLs] = useState<FunctionalLocation[]>([]);
  const [siteId, setSiteId] = useState("");
  const [flId, setFlId] = useState("");
  const [error, setError] = useState("");

  useEffect(() => { api.listSites().then(setSites); }, []);
  useEffect(() => {
    if (siteId) api.listFLs(siteId).then(setFLs);
    else setFLs([]);
  }, [siteId]);

  async function doInstall() {
    setError("");
    try {
      await api.install(equipmentId, flId);
      onInstalled();
    } catch (err) {
      // Surface the partial-unique-index conflict as a friendly message.
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  return (
    <div className="card">
      <h3>Install</h3>
      <label>
        Site
        <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          <option value="">—</option>
          {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </label>
      <label>
        Functional location
        <select value={flId} onChange={(e) => setFlId(e.target.value)}>
          <option value="">—</option>
          {fls.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
        </select>
      </label>
      <button disabled={!flId} onClick={doInstall}>Install here</button>
      {error && <p className="field-error">{error}</p>}
    </div>
  );
}

function RemovePanel({ onRemove }: { onRemove: () => void }) {
  const [confirming, setConfirming] = useState(false);
  return (
    <div className="card">
      <h3>Currently installed</h3>
      {confirming ? (
        <>
          <p>Remove this unit from its slot?</p>
          <button onClick={onRemove}>Confirm remove</button>
          <button onClick={() => setConfirming(false)}>Cancel</button>
        </>
      ) : (
        <button onClick={() => setConfirming(true)}>Remove from slot</button>
      )}
    </div>
  );
}
