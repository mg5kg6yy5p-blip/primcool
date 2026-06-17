import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import { CustomersPage } from "./internal/CustomersPage";
import { EquipmentPage } from "./internal/EquipmentPage";
import { AssetTreePage } from "./internal/AssetTreePage";
import { SitesPage } from "./internal/SitesPage";
import { TriagePage } from "./internal/TriagePage";
import { WorkQueuePage } from "./internal/WorkQueuePage";
import { InventoryPage } from "./internal/InventoryPage";
import { PmSchedulesPage } from "./internal/PmSchedulesPage";
import { ContractsPage } from "./internal/ContractsPage";
import { LoginPage } from "./internal/LoginPage";
import { TechQueue } from "./technician/TechQueue";
import { TechOrder } from "./technician/TechOrder";
import { PortalApp } from "./portal/PortalApp";

type Surface = "internal" | "technician" | "portal";

export default function App({ surface }: { surface: Surface }) {
  if (surface === "technician") return <TechnicianApp />;
  if (surface === "portal") return <PortalShell />;
  return <InternalApp />;
}

function PortalShell() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <main><p>Loading…</p></main>;
  if (location.pathname.endsWith("/login")) return <LoginPage />;
  if (!user) return <Navigate to="/portal/login" replace />;
  return <PortalApp />;
}

function InternalApp() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <main><p>Loading…</p></main>;
  if (location.pathname.endsWith("/login")) return <LoginPage />;
  if (!user) return <Navigate to="/app/login" replace state={{ from: location }} />;

  return (
    <div className="shell">
      <header>
        <span className="brand">Prime<span>Cool</span> · Maintenance</span>
        <nav>
          <NavLink to="/app/triage">Triage</NavLink>
          <NavLink to="/app/queue">Work Queue</NavLink>
          <NavLink to="/app/customers">Customers</NavLink>
          <NavLink to="/app/sites">Sites &amp; Spaces</NavLink>
          <NavLink to="/app/assets">Functional Locations</NavLink>
          <NavLink to="/app/equipment">Equipment</NavLink>
          <NavLink to="/app/inventory">Inventory</NavLink>
          <NavLink to="/app/pm">PM</NavLink>
          <NavLink to="/app/contracts">Contracts</NavLink>
        </nav>
        <UserBadge />
      </header>
      <main>
        <Routes>
          <Route path="triage" element={<TriagePage />} />
          <Route path="queue" element={<WorkQueuePage />} />
          <Route path="customers" element={<CustomersPage />} />
          <Route path="sites" element={<SitesPage />} />
          <Route path="assets" element={<AssetTreePage />} />
          <Route path="equipment" element={<EquipmentPage />} />
          <Route path="inventory" element={<InventoryPage />} />
          <Route path="pm" element={<PmSchedulesPage />} />
          <Route path="contracts" element={<ContractsPage />} />
          <Route path="*" element={<Navigate to="triage" replace />} />
        </Routes>
      </main>
    </div>
  );
}

function TechnicianApp() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <main><p>Loading…</p></main>;
  if (location.pathname.endsWith("/login")) return <LoginPage />;
  if (!user) return <Navigate to="/tech/login" replace />;

  return (
    <div className="tech-shell">
      <header className="tech-header">
        <span className="brand">Prime<span>Cool</span></span>
        <UserBadge />
      </header>
      <main>
        <Routes>
          <Route index element={<TechQueue />} />
          <Route path="orders/:orderId" element={<TechOrder />} />
          <Route path="*" element={<Navigate to="/tech" replace />} />
        </Routes>
      </main>
    </div>
  );
}

function UserBadge() {
  const { user, logout } = useAuth();
  if (!user) return null;
  return (
    <div className="user-badge">
      <span>{user.full_name || user.email} <small>({user.role})</small></span>
      <button onClick={logout}>Sign out</button>
    </div>
  );
}
