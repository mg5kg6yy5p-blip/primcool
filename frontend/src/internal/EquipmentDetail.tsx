import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type {
  Equipment,
  EquipmentHistory,
  EquipmentInstall,
  FunctionalLocation,
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
