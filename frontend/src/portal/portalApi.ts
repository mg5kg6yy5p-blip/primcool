import { getToken } from "../auth";
import type { Notification, Site, WorkOrder } from "../types";

const BASE = "/api/customer-portal";

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
    window.location.assign("/portal/login");
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

export const portalApi = {
  sites: () => request<Site[]>("/sites"),
  notifications: () => request<Notification[]>("/notifications"),
  raiseRequest: (body: Partial<Notification>) =>
    request<Notification>("/notifications", {
      method: "POST", body: JSON.stringify(body),
    }),
  workOrders: () => request<WorkOrder[]>("/work-orders"),
};
