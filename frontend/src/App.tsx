type Surface = "internal" | "technician" | "portal";

const TITLES: Record<Surface, string> = {
  internal: "Dispatcher / Admin",
  technician: "Technician Mobile",
  portal: "Customer Portal",
};

export default function App({ surface }: { surface: Surface }) {
  return (
    <main>
      <h1>PrimeCool — {TITLES[surface]}</h1>
      <p>Phase 0 scaffold. Real UI lands in Phase 1.</p>
    </main>
  );
}
