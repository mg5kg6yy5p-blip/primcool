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

export interface Building {
  id: string;
  site_id: string;
  name: string;
}

export interface Space {
  id: string;
  site_id: string;
  building_id: string | null;
  identifier: string;
  space_type: SpaceType;
}

export interface Meter {
  id: string;
  equipment_id: string;
  meter_type: MeterType;
  unit: string;
}

export interface MeterReading {
  id: string;
  meter_id: string;
  reading_value: number;
  read_at: string;
  source: string;
  recorded_by: string | null;
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

export type NotificationCategory =
  | "cooling" | "heating" | "leak" | "electrical"
  | "noise" | "maintenance_request" | "other";
export type Severity = "emergency" | "high" | "medium" | "low";
export type NotificationStatus = "new" | "acknowledged" | "converted" | "closed_no_action";
export type OrderType = "corrective" | "preventive" | "install" | "inspection";
export type BillingClass = "contract" | "billable" | "warranty" | "goodwill";
export type OrderStatus =
  | "created" | "scheduled" | "in_progress" | "tech_complete" | "closed" | "cancelled";
export type OperationStatus = "open" | "confirmed";

export interface Notification {
  id: string;
  customer_account_id: string;
  site_id: string;
  space_id: string | null;
  category: NotificationCategory;
  severity: Severity;
  title: string;
  description: string;
  photo_url: string | null;
  status: NotificationStatus;
  acknowledged_at: string | null;
  closed_at: string | null;
}

export interface WorkOrder {
  id: string;
  notification_id: string | null;
  customer_account_id: string;
  site_id: string;
  functional_location_id: string | null;
  equipment_id: string | null;
  pm_schedule_id: string | null;
  order_type: OrderType;
  billing_class: BillingClass;
  priority: Severity;
  title: string;
  description: string;
  status: OrderStatus;
  assigned_to_user_id: string | null;
  scheduled_date: string | null;
  due_date: string | null;
  closed_at: string | null;
  legal_transitions: OrderStatus[];
}

export interface Operation {
  id: string;
  work_order_id: string;
  sequence: number;
  description: string;
  status: OperationStatus;
  planned_hours: number;
}

export interface SavedView {
  id: string;
  user_id: string | null;
  entity: string;
  name: string;
  filters: Record<string, unknown>;
  columns: string[];
  sort: Record<string, unknown>;
  is_default: boolean;
}

export interface AuditLog {
  id: string;
  actor_user_id: string | null;
  entity_type: string;
  entity_id: string;
  action: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  at: string;
}

export interface FieldErrors {
  [field: string]: string;
}
