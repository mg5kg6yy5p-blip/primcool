import type {
  AuditLog,
  Building,
  Confirmation,
  ConfirmationPartIn,
  CustomerAccount,
  Equipment,
  EquipmentHistory,
  EquipmentInstall,
  FieldErrors,
  FunctionalLocation,
  Material,
  Meter,
  MeterReading,
  Notification,
  Operation,
  OrderStatus,
  PmSchedule,
  PmScanResult,
  SavedView,
  Site,
  Space,
  StockLocation,
  StockQuant,
  WorkOrder,
} from "./types";

import { getToken } from "./auth";

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
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { ...headers, ...((init?.headers as Record<string, string>) ?? {}) },
  });
  if (res.status === 401) {
    localStorage.removeItem("primcool.token");
    window.location.assign("/app/login");
    throw new ApiError("Unauthorized");
  }
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

  // buildings
  listBuildings: (siteId?: string) =>
    request<Building[]>(`/buildings${siteId ? `?site_id=${siteId}` : ""}`),
  createBuilding: (body: Partial<Building>) => post<Building>("/buildings", body),

  // spaces
  listSpaces: (siteId?: string) =>
    request<Space[]>(`/spaces${siteId ? `?site_id=${siteId}` : ""}`),
  createSpace: (body: Partial<Space>) => post<Space>("/spaces", body),

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

  // meters & readings
  listMeters: (equipmentId?: string) =>
    request<Meter[]>(`/meters${equipmentId ? `?equipment_id=${equipmentId}` : ""}`),
  createMeter: (body: Partial<Meter>) => post<Meter>("/meters", body),
  listReadings: (meterId: string) =>
    request<MeterReading[]>(`/meters/${meterId}/readings`),
  addReading: (meterId: string, value: number) =>
    post<MeterReading>(`/meters/${meterId}/readings`, { reading_value: value }),

  // notifications / triage
  listNotifications: (params?: { customer_account_id?: string; status?: string }) => {
    const q = new URLSearchParams(params as Record<string, string>).toString();
    return request<Notification[]>(`/notifications${q ? `?${q}` : ""}`);
  },
  createNotification: (body: Partial<Notification>) =>
    post<Notification>("/notifications", body),
  acknowledge: (id: string) => post<Notification>(`/notifications/${id}/acknowledge`, {}),
  convertToOrder: (id: string) => post<WorkOrder>(`/notifications/${id}/convert-to-order`, {}),
  closeNoAction: (id: string, reason: string) =>
    post<Notification>(`/notifications/${id}/close-no-action`, { reason }),

  // work orders
  listWorkOrders: (qs?: string) => request<WorkOrder[]>(`/work-orders${qs ? `?${qs}` : ""}`),
  getWorkOrder: (id: string) => request<WorkOrder>(`/work-orders/${id}`),
  transitionOrder: (id: string, target: OrderStatus) =>
    post<WorkOrder>(`/work-orders/${id}/transition`, { target }),
  listOperations: (orderId: string) =>
    request<Operation[]>(`/work-orders/${orderId}/operations`),
  addOperation: (orderId: string, body: Partial<Operation>) =>
    post<Operation>(`/work-orders/${orderId}/operations`, body),

  // saved views
  listSavedViews: () => request<SavedView[]>("/saved-views"),
  createSavedView: (body: Partial<SavedView>) => post<SavedView>("/saved-views", body),

  // audit
  listAudit: (entityType: string, entityId: string) =>
    request<AuditLog[]>(`/audit?entity_type=${entityType}&entity_id=${entityId}`),

  // inventory
  listMaterials: () => request<Material[]>("/materials"),
  createMaterial: (body: Partial<Material>) => post<Material>("/materials", body),
  listStockLocations: () => request<StockLocation[]>("/stock-locations"),
  createStockLocation: (body: Partial<StockLocation>) =>
    post<StockLocation>("/stock-locations", body),
  listStock: (params?: { material_id?: string; stock_location_id?: string }) => {
    const q = new URLSearchParams(params as Record<string, string>).toString();
    return request<StockQuant[]>(`/stock${q ? `?${q}` : ""}`);
  },
  setStock: (body: { material_id: string; stock_location_id: string; qty: number }) =>
    request<StockQuant>("/stock", { method: "PUT", body: JSON.stringify(body) }),

  // PM schedules
  listPmSchedules: () => request<PmSchedule[]>("/pm-schedules"),
  createPmSchedule: (body: Partial<PmSchedule> & {
    start_at?: string; start_value?: number;
  }) => post<PmSchedule>("/pm-schedules", body),
  patchPmSchedule: (id: string, body: Partial<PmSchedule>) =>
    patch<PmSchedule>(`/pm-schedules/${id}`, body),
  scanPm: () => post<PmScanResult>("/pm-schedules/scan", {}),

  // confirmations
  listOperationConfirmations: (operationId: string) =>
    request<Confirmation[]>(`/operations/${operationId}/confirmations`),
  confirmOperation: (
    operationId: string,
    body: {
      actual_hours: number; is_final: boolean; notes?: string;
      parts?: ConfirmationPartIn[];
    },
  ) => post<Confirmation>(`/operations/${operationId}/confirm`, body),
  reverseConfirmation: (confirmationId: string, reason: string) =>
    post<Confirmation>(`/confirmations/${confirmationId}/reverse`, { reason }),
};
