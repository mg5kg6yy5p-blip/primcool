import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { CustomersPage } from "./internal/CustomersPage";
import { EquipmentPage } from "./internal/EquipmentPage";
import { AssetTreePage } from "./internal/AssetTreePage";
import { SitesPage } from "./internal/SitesPage";

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

  return (
    <div className="shell">
      <header>
        <span className="brand">Prime<span>Cool</span> · Maintenance</span>
        <nav>
          <NavLink to="/app/customers">Customers</NavLink>
          <NavLink to="/app/sites">Sites &amp; Spaces</NavLink>
          <NavLink to="/app/assets">Functional Locations</NavLink>
          <NavLink to="/app/equipment">Equipment</NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="customers" element={<CustomersPage />} />
          <Route path="sites" element={<SitesPage />} />
          <Route path="assets" element={<AssetTreePage />} />
          <Route path="equipment" element={<EquipmentPage />} />
          <Route path="*" element={<Navigate to="customers" replace />} />
        </Routes>
      </main>
    </div>
  );
}
