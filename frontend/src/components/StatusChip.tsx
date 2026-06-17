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
  // notification status
  new: "#2D6CDF",
  acknowledged: "#E0A33E",
  converted: "#22A08A",
  closed_no_action: "#8A94A6",
  // work-order status
  created: "#2D6CDF",
  scheduled: "#7A5AF0",
  in_progress: "#E0A33E",
  tech_complete: "#1F9E8A",
  closed: "#5A6472",
  cancelled: "#8A94A6",
  // severity / priority
  emergency: "#C0504D",
  high: "#E0772E",
  medium: "#E0A33E",
  low: "#5A6472",
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
