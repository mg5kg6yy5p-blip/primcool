import type {
  CustomerAccount,
  Equipment,
  EquipmentHistory,
  EquipmentInstall,
  FieldErrors,
  FunctionalLocation,
  Site,
} from "./types";

const BASE = "/api/v1";

/** Raised on a 422 so callers can render field-level messages (parity rule). */
export class ValidationError extends Error {
  fields: FieldErrors;
  constructor(fields: FieldErrors) {
    super("Validation failed");
    this.fields = fields;
  }
}

export class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (res.status === 422) {
    const body = await res.json();
    const fields: FieldErrors = {};
    for (const item of body.detail ?? []) {
      const field = (item.loc ?? []).slice(1).join(".");
      fields[field || "_"] = item.msg;
    }
    throw new ValidationError(fields);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) });
const patch = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "PATCH", body: JSON.stringify(body) });

export const api = {
  // customers
  listCustomers: () => request<CustomerAccount[]>("/customers"),
  getCustomer: (id: string) => request<CustomerAccount>(`/customers/${id}`),
  createCustomer: (body: Partial<CustomerAccount>) =>
    post<CustomerAccount>("/customers", body),
  updateCustomer: (id: string, body: Partial<CustomerAccount>) =>
    patch<CustomerAccount>(`/customers/${id}`, body),

  // sites
  listSites: (customerId?: string) =>
    request<Site[]>(`/sites${customerId ? `?customer_account_id=${customerId}` : ""}`),
  createSite: (body: Partial<Site>) => post<Site>("/sites", body),

  // functional locations
  listFLs: (siteId?: string) =>
    request<FunctionalLocation[]>(
      `/functional-locations${siteId ? `?site_id=${siteId}` : ""}`,
    ),
  createFL: (body: Partial<FunctionalLocation>) =>
    post<FunctionalLocation>("/functional-locations", body),

  // equipment
  listEquipment: () => request<Equipment[]>("/equipment"),
  getEquipment: (id: string) => request<Equipment>(`/equipment/${id}`),
  createEquipment: (body: Partial<Equipment>) => post<Equipment>("/equipment", body),
  equipmentHistory: (id: string) =>
    request<EquipmentHistory>(`/equipment/${id}/history`),
  activeInstall: (id: string) =>
    request<EquipmentInstall | null>(`/equipment/${id}/active-install`),
  install: (id: string, flId: string) =>
    post<EquipmentInstall>(`/equipment/${id}/install`, { fl_id: flId }),
  remove: (id: string) =>
    post<EquipmentInstall>(`/equipment/${id}/remove`, {}),
};
