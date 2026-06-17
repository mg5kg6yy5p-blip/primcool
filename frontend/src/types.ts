export type CustomerType =
  | "apartment_complex" | "strip_mall" | "commercial" | "residential";
export type CustomerStatus = "active" | "inactive";
export type SpaceType =
  | "residential_unit" | "retail" | "office"
  | "common_area" | "mechanical_room" | "exterior";
export type AssetClass =
  | "split_ac" | "central_ahu" | "package_unit"
  | "chiller" | "cooling_tower" | "exhaust" | "other";
export type FLStatus = "active" | "inactive";
export type EquipmentStatus = "installed" | "in_storage" | "in_repair" | "scrapped";
export type MeterType = "run_hours" | "starts" | "other";

export interface CustomerAccount {
  id: string;
  name: string;
  type: CustomerType;
  billing_currency: string;
  contact_name: string;
  contact_email: string;
  contact_phone: string;
  status: CustomerStatus;
}

export interface Site {
  id: string;
  customer_account_id: string;
  name: string;
  address: string;
  geo_lat: number | null;
  geo_lng: number | null;
}

export interface FunctionalLocation {
  id: string;
  site_id: string;
  building_id: string | null;
  space_id: string | null;
  parent_fl_id: string | null;
  name: string;
  fl_class: AssetClass;
  status: FLStatus;
}

export interface Equipment {
  id: string;
  serial: string | null;
  model: string;
  manufacturer: string;
  equipment_class: AssetClass;
  status: EquipmentStatus;
  warranty_months: number | null;
  notes: string;
}

export interface EquipmentInstall {
  id: string;
  equipment_id: string;
  functional_location_id: string;
  installed_at: string;
  removed_at: string | null;
  installed_by_user_id: string | null;
  warranty_expires_at: string | null;
}

export interface TimelineEvent {
  at: string;
  kind: string;
  detail: Record<string, unknown>;
}

export interface EquipmentHistory {
  equipment_id: string;
  events: TimelineEvent[];
}

export interface FieldErrors {
  [field: string]: string;
}
