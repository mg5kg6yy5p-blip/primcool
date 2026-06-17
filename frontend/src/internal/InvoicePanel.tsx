import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { InvoiceDraft } from "../types";
import { StatusChip } from "../components/StatusChip";

/** Generates / displays / issues the invoice draft for a work order. */
export function InvoicePanel({
  orderId,
  canGenerate,
}: {
  orderId: string;
  canGenerate: boolean;
}) {
  const [draft, setDraft] = useState<InvoiceDraft | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const d = await api.getInvoiceDraft(orderId);
    setDraft(d);
  }, [orderId]);
  useEffect(() => { load(); }, [load]);

  async function generate() {
    setError("");
    setBusy(true);
    try {
      const d = await api.generateInvoiceDraft(orderId);
      setDraft(d);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function issue() {
    if (!draft) return;
    setBusy(true);
    setError("");
    try {
      const d = await api.issueInvoice(draft.id);
      setDraft(d);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="actions">
        {canGenerate && (
          <button onClick={generate} disabled={busy}>
            {draft ? "Regenerate draft" : "Generate draft"}
          </button>
        )}
        {draft?.status === "draft" && (
          <button onClick={issue} disabled={busy}>Mark issued</button>
        )}
        {draft && <StatusChip status={draft.status} />}
        {draft && <StatusChip status={draft.billing_class} />}
      </div>
      {error && <p className="field-error">{error}</p>}

      {!draft && <p><em>No draft yet.</em></p>}
      {draft && (
        <>
          <table>
            <thead>
              <tr>
                <th>Kind</th><th>Description</th>
                <th>Qty</th><th>Unit</th><th>Total</th>
              </tr>
            </thead>
            <tbody>
              {draft.lines.map((line) => (
                <tr key={line.id}>
                  <td>{line.kind}</td>
                  <td>{line.description}</td>
                  <td>{line.qty}</td>
                  <td>{draft.currency} {line.unit_amount.toFixed(2)}</td>
                  <td>{draft.currency} {line.total.toFixed(2)}</td>
                </tr>
              ))}
              {draft.lines.length === 0 && (
                <tr><td colSpan={5}><em>No lines</em></td></tr>
              )}
            </tbody>
            <tfoot>
              <tr>
                <td colSpan={4}><strong>Subtotal</strong></td>
                <td>{draft.currency} {draft.subtotal.toFixed(2)}</td>
              </tr>
              {draft.gct_amount > 0 && (
                <tr>
                  <td colSpan={4}>GCT @ {draft.gct_rate}%</td>
                  <td>{draft.currency} {draft.gct_amount.toFixed(2)}</td>
                </tr>
              )}
              <tr>
                <td colSpan={4}><strong>Total</strong></td>
                <td><strong>{draft.currency} {draft.total.toFixed(2)}</strong></td>
              </tr>
            </tfoot>
          </table>
        </>
      )}
    </div>
  );
}
