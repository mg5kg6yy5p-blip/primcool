// One shared status chip with one color map, used across every surface.
const COLORS: Record<string, string> = {
  // customer / FL
  active: "#22A08A",
  inactive: "#8A94A6",
  // equipment
  installed: "#22A08A",
  in_storage: "#5A6472",
  in_repair: "#E0A33E",
  scrapped: "#C0504D",
};

export function StatusChip({ status }: { status: string }) {
  const bg = COLORS[status] ?? "#5A6472";
  return (
    <span
      style={{
        background: bg,
        color: "#fff",
        borderRadius: 12,
        padding: "2px 10px",
        fontSize: 12,
        textTransform: "uppercase",
        letterSpacing: "0.05em",
      }}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}
