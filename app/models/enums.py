import enum


class CustomerType(str, enum.Enum):
    apartment_complex = "apartment_complex"
    strip_mall = "strip_mall"
    commercial = "commercial"
    residential = "residential"


class CustomerStatus(str, enum.Enum):
    active = "active"
    inactive = "inactive"


class SpaceType(str, enum.Enum):
    residential_unit = "residential_unit"
    retail = "retail"
    office = "office"
    common_area = "common_area"
    mechanical_room = "mechanical_room"
    exterior = "exterior"


class AssetClass(str, enum.Enum):
    """Shared enum family for functional_location.fl_class and
    equipment.equipment_class."""
    split_ac = "split_ac"
    central_ahu = "central_ahu"
    package_unit = "package_unit"
    chiller = "chiller"
    cooling_tower = "cooling_tower"
    exhaust = "exhaust"
    other = "other"


class FLStatus(str, enum.Enum):
    active = "active"
    inactive = "inactive"


class EquipmentStatus(str, enum.Enum):
    installed = "installed"
    in_storage = "in_storage"
    in_repair = "in_repair"
    scrapped = "scrapped"


class MeterType(str, enum.Enum):
    run_hours = "run_hours"
    starts = "starts"
    other = "other"


class ReadingSource(str, enum.Enum):
    manual = "manual"
    import_ = "import"


class NotificationCategory(str, enum.Enum):
    cooling = "cooling"
    heating = "heating"
    leak = "leak"
    electrical = "electrical"
    noise = "noise"
    maintenance_request = "maintenance_request"
    other = "other"


class Severity(str, enum.Enum):
    emergency = "emergency"
    high = "high"
    medium = "medium"
    low = "low"


class NotificationStatus(str, enum.Enum):
    new = "new"
    acknowledged = "acknowledged"
    converted = "converted"
    closed_no_action = "closed_no_action"


class OrderType(str, enum.Enum):
    corrective = "corrective"
    preventive = "preventive"
    install = "install"
    inspection = "inspection"


class BillingClass(str, enum.Enum):
    contract = "contract"
    billable = "billable"
    warranty = "warranty"
    goodwill = "goodwill"


class OrderStatus(str, enum.Enum):
    created = "created"
    scheduled = "scheduled"
    in_progress = "in_progress"
    tech_complete = "tech_complete"
    closed = "closed"
    cancelled = "cancelled"


class OperationStatus(str, enum.Enum):
    open = "open"
    confirmed = "confirmed"


class AuditAction(str, enum.Enum):
    create = "create"
    update = "update"
    status_change = "status_change"
    install = "install"
    remove = "remove"
    delete = "delete"
