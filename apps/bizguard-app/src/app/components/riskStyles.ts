export type RiskLevel = "Critical" | "High" | "Medium" | "Safe";

export const riskColors: Record<RiskLevel, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Safe: "#22c55e",
};

export const riskBgColors: Record<RiskLevel, string> = {
  Critical: "rgba(239,68,68,0.1)",
  High: "rgba(249,115,22,0.1)",
  Medium: "rgba(234,179,8,0.1)",
  Safe: "rgba(34,197,94,0.1)",
};
