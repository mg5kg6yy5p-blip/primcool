import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import { CustomersPage } from "./internal/CustomersPage";
import { EquipmentPage } from "./internal/EquipmentPage";
import { AssetTreePage } from "./internal/AssetTreePage";
import { SitesPage } from "./internal/SitesPage";
import { TriagePage } from "./internal/TriagePage";
import { WorkQueuePage } from "./internal/WorkQueuePage";
import { LoginPage } from "./internal/LoginPage";

type Surface = "internal" | "technician" | "portal";

const TITLES: Record<Surface, string> = {
  internal: "Dispatcher / Admin",
  technician: "Technician Mobile",
  portal: "Customer Portal",
};

export default function App({ surface }: { surface: Surface }) {
  if (surface !== "internal") {
    return (
      <main>
        <h1>PrimeCool — {TITLES[surface]}</h1>
        <p>Surface scaffolded. UI lands in {surface === "technician" ? "Phase 3" : "Phase 5"}.</p>
      </main>
    );
  }
  return <InternalApp />;
}

function InternalApp() {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) return <main><p>Loading…</p></main>;

  // /app/login is reachable without auth.
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
          <Route path="*" element={<Navigate to="triage" replace />} />
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
