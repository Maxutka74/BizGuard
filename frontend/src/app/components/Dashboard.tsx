import { useState, useEffect, useCallback } from "react";
import {
    Shield,
    AlertTriangle,
    CheckCircle,
    XCircle,
    RefreshCw,
    LogOut,
    Search,
    ChevronRight,
    Mail,
} from "lucide-react";
import { riskColors, riskBgColors, type RiskLevel } from "./mockData";
import {
    fetchEmails,
    fetchEmailStats,
    triggerScan,
    type EmailListItem,
    type EmailStats,
} from "../../api/gmail";
import type { User } from "../../api/auth";

interface DashboardProps {
    user: User | null;
    onSelectEmail: (id: string) => void;
    onLogout: () => void;
}

const levelTranslations: Record<RiskLevel, string> = {
    Critical: "КРИТИЧНИЙ",
    High: "ВИСОКИЙ",
    Medium: "СЕРЕДНІЙ",
    Safe: "БЕЗПЕЧНИЙ",
};

const levelLabels: Record<RiskLevel, string> = {
    Critical: "Критичний",
    High: "Високий",
    Medium: "Середній",
    Safe: "Безпечний",
};

function RiskBadge({ level }: { level: RiskLevel }) {
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded"
            style={{
                background: riskBgColors[level],
                color: riskColors[level],
                fontFamily: "var(--font-mono)",
                fontSize: "0.7rem",
                fontWeight: 600,
                letterSpacing: "0.05em",
                border: `1px solid ${riskColors[level]}33`,
            }}
        >
      {levelTranslations[level]}
    </span>
    );
}

export function Dashboard({ user, onSelectEmail, onLogout }: DashboardProps) {
    const [search, setSearch] = useState("");
    const [filterRisk, setFilterRisk] = useState<RiskLevel | "All">("All");
    const [scanning, setScanning] = useState(false);

    const [emails, setEmails] = useState<EmailListItem[]>([]);
    const [stats, setStats] = useState<EmailStats | null>(null);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const loadEmails = useCallback(() => {
        setError(null);
        // @ts-ignore
        return Promise.all([
            fetchEmails({ search, risk_level: filterRisk }),
            fetchEmailStats(),
        ])
            .then((results: any[]) => {
                const emailsRes = results[0];
                const statsRes = results[1];
                setEmails(emailsRes.emails);
                setTotal(emailsRes.total);
                setStats(statsRes);
                setLoading(false);
            })
            .catch((err: any) => {
                setError(err?.detail ?? "Не вдалося завантажити листи");
                setLoading(false);
            });
    }, [search, filterRisk]);

    useEffect(() => {
        setLoading(true);
        const timer = setTimeout(loadEmails, search ? 300 : 0);
        return () => clearTimeout(timer);
    }, [loadEmails]);

    const handleScan = () => {
        setScanning(true);
        triggerScan(50)
            .then(() => {
                return loadEmails();
            })
            .catch((err: any) => {
                setError(err?.detail ?? "Помилка сканування");
            })
            .then(() => {
                setScanning(false);
            });
    };

    const riskFilters: (RiskLevel | "All")[] = ["All", "Critical", "High", "Medium", "Safe"];
    const distribution = stats?.distribution ?? { Critical: 0, High: 0, Medium: 0, Safe: 0 };

    const distributionKeys = Object.keys(distribution) as RiskLevel[];
    const totalForBar = distributionKeys.reduce((acc: number, key: RiskLevel) => {
        return acc + (distribution[key] || 0);
    }, 0);

    return (
        <div
            className="min-h-screen"
            style={{ background: "var(--background)", fontFamily: "var(--font-sans)" }}
        >
            <header
                className="sticky top-0 z-20 flex items-center justify-between px-6 h-14"
                style={{
                    background: "rgba(8,12,20,0.9)",
                    borderBottom: "1px solid var(--border)",
                    backdropFilter: "blur(12px)",
                }}
            >
                <div className="flex items-center gap-2.5">
                    <Shield className="w-5 h-5" style={{ color: "#3b82f6" }} />
                    <span
                        style={{
                            color: "var(--foreground)",
                            fontWeight: 700,
                            fontSize: "1rem",
                            letterSpacing: "-0.01em",
                        }}
                    >
            BizGuard
          </span>
                    {user && (
                        <span
                            style={{
                                color: "var(--muted-foreground)",
                                fontFamily: "var(--font-mono)",
                                fontSize: "0.65rem",
                                letterSpacing: "0.08em",
                                marginLeft: 4,
                            }}
                        >
              {user.email}
            </span>
                    )}
                </div>

                <div className="flex items-center gap-3">
                    <button
                        onClick={handleScan}
                        disabled={scanning}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all duration-200 hover:opacity-90 active:scale-[0.97]"
                        style={{
                            background: "var(--primary)",
                            color: "#fff",
                            fontSize: "0.8125rem",
                            fontWeight: 600,
                            border: "none",
                            cursor: scanning ? "not-allowed" : "pointer",
                            opacity: scanning ? 0.7 : 1,
                        }}
                    >
                        <RefreshCw className={`w-3.5 h-3.5 ${scanning ? "animate-spin" : ""}`} />
                        {scanning ? "Сканування..." : "Пересканувати"}
                    </button>

                    <button
                        onClick={onLogout}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all duration-200 hover:opacity-80"
                        style={{
                            background: "var(--secondary)",
                            color: "var(--muted-foreground)",
                            fontSize: "0.8125rem",
                            border: "1px solid var(--border)",
                            cursor: "pointer",
                        }}
                    >
                        <LogOut className="w-3.5 h-3.5" />
                        Вийти
                    </button>
                </div>
            </header>

            <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
                {error && (
                    <div
                        className="rounded-lg px-4 py-3 flex items-center gap-2"
                        style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)" }}
                    >
                        <XCircle className="w-4 h-4 flex-shrink-0" style={{ color: "#ef4444" }} />
                        <span style={{ color: "#ef4444", fontSize: "0.875rem" }}>{error}</span>
                    </div>
                )}

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                        {
                            label: "Проаналізовано листів",
                            value: stats?.total ?? 0,
                            icon: Mail,
                            color: "#3b82f6",
                            bg: "rgba(59,130,246,0.1)",
                        },
                        {
                            label: "Підозрілі",
                            value: stats?.suspicious ?? 0,
                            icon: AlertTriangle,
                            color: "#eab308",
                            bg: "rgba(234,179,8,0.1)",
                        },
                        {
                            label: "Високий ризик",
                            value: stats?.high ?? 0,
                            icon: XCircle,
                            color: "#f97316",
                            bg: "rgba(249,115,22,0.1)",
                        },
                        {
                            label: "Критичні",
                            value: stats?.critical ?? 0,
                            icon: Shield,
                            color: "#ef4444",
                            bg: "rgba(239,68,68,0.1)",
                        },
                    ].map(({ label, value, icon: Icon, color, bg }) => (
                        <div
                            key={label}
                            className="rounded-xl p-5"
                            style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                        >
                            <div className="flex items-center justify-between mb-3">
                <span style={{ color: "var(--muted-foreground)", fontSize: "0.8rem" }}>
                  {label}
                </span>
                                <div
                                    className="w-8 h-8 rounded-lg flex items-center justify-center"
                                    style={{ background: bg }}
                                >
                                    <Icon className="w-4 h-4" style={{ color }} />
                                </div>
                            </div>
                            <div
                                style={{
                                    color: "var(--foreground)",
                                    fontSize: "1.875rem",
                                    fontWeight: 700,
                                    fontFamily: "var(--font-mono)",
                                    lineHeight: 1,
                                }}
                            >
                                {loading ? "—" : value}
                            </div>
                        </div>
                    ))}
                </div>

                <div
                    className="rounded-xl p-5"
                    style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                >
                    <p
                        className="mb-3"
                        style={{ color: "var(--muted-foreground)", fontSize: "0.8rem", fontWeight: 500 }}
                    >
                        РОЗПОДІЛ ЗАГРОЗ
                    </p>
                    <div className="flex rounded-full overflow-hidden h-3 gap-0.5">
                        {(["Critical", "High", "Medium", "Safe"] as RiskLevel[]).map((level) => {
                            const count = distribution[level] ?? 0;
                            const pct = totalForBar > 0 ? (count / totalForBar) * 100 : 0;
                            return (
                                <div
                                    key={level}
                                    style={{ width: `${pct}%`, background: riskColors[level] }}
                                    title={`${levelLabels[level]}: ${count}`}
                                />
                            );
                        })}
                    </div>
                    <div className="flex gap-5 mt-3">
                        {(["Critical", "High", "Medium", "Safe"] as RiskLevel[]).map((level) => (
                            <div key={level} className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-full" style={{ background: riskColors[level] }} />
                                <span style={{ color: "var(--muted-foreground)", fontSize: "0.75rem" }}>
                  {levelLabels[level]} ({distribution[level] ?? 0})
                </span>
                            </div>
                        ))}
                    </div>
                    {stats?.lastScannedAt && (
                        <p
                            className="mt-3"
                            style={{
                                color: "var(--muted-foreground)",
                                fontFamily: "var(--font-mono)",
                                fontSize: "0.7rem",
                            }}
                        >
                            Востаннє відскановано:{" "}
                            {new Date(stats.lastScannedAt).toLocaleString("uk-UA", {
                                day: "2-digit",
                                month: "short",
                                hour: "2-digit",
                                minute: "2-digit",
                            })}
                        </p>
                    )}
                </div>

                <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center">
                    <div
                        className="flex items-center gap-2 flex-1 rounded-lg px-3 py-2"
                        style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
                    >
                        <Search className="w-4 h-4" style={{ color: "var(--muted-foreground)" }} />
                        <input
                            type="text"
                            placeholder="Пошук листів, відправників, доменів..."
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            className="bg-transparent outline-none flex-1"
                            style={{
                                color: "var(--foreground)",
                                fontSize: "0.875rem",
                                fontFamily: "var(--font-sans)",
                            }}
                        />
                    </div>

                    <div className="flex gap-2 flex-wrap">
                        {riskFilters.map((r) => (
                            <button
                                key={r}
                                onClick={() => setFilterRisk(r)}
                                className="px-3 py-1.5 rounded-lg transition-all duration-150"
                                style={{
                                    background:
                                        filterRisk === r
                                            ? r === "All"
                                                ? "#3b82f6"
                                                : riskBgColors[r as RiskLevel]
                                            : "var(--secondary)",
                                    color:
                                        filterRisk === r
                                            ? r === "All"
                                                ? "#fff"
                                                : riskColors[r as RiskLevel]
                                            : "var(--muted-foreground)",
                                    border:
                                        filterRisk === r && r !== "All"
                                            ? `1px solid ${riskColors[r as RiskLevel]}44`
                                            : "1px solid var(--border)",
                                    fontSize: "0.75rem",
                                    fontWeight: 600,
                                    fontFamily: "var(--font-mono)",
                                    cursor: "pointer",
                                    letterSpacing: "0.04em",
                                }}
                            >
                                {r === "All" ? "ВСІ" : levelTranslations[r as RiskLevel]}
                            </button>
                        ))}
                    </div>
                </div>

                <div
                    className="rounded-xl overflow-hidden"
                    style={{ border: "1px solid var(--border)", background: "var(--card)" }}
                >
                    <div
                        className="grid grid-cols-12 px-5 py-2.5"
                        style={{
                            borderBottom: "1px solid var(--border)",
                            background: "var(--secondary)",
                        }}
                    >
                        {["Тема", "Відправник", "Домен", "Дата", "Ризик", ""].map((h, i) => (
                            <div
                                key={i}
                                className={
                                    i === 0
                                        ? "col-span-4"
                                        : i === 1
                                            ? "col-span-2"
                                            : i === 2
                                                ? "col-span-2"
                                                : i === 3
                                                    ? "col-span-2"
                                                    : i === 4
                                                        ? "col-span-1"
                                                        : "col-span-1"
                                }
                                style={{
                                    color: "var(--muted-foreground)",
                                    fontSize: "0.7rem",
                                    fontFamily: "var(--font-mono)",
                                    letterSpacing: "0.08em",
                                    fontWeight: 600,
                                }}
                            >
                                {h}
                            </div>
                        ))}
                    </div>

                    {loading ? (
                        <div className="py-16 flex flex-col items-center gap-3" style={{ color: "var(--muted-foreground)" }}>
                            <style>{`@keyframes spin { to { transform: rotate(360deg); } } .spinner { animation: spin 0.8s linear infinite; }`}</style>
                            <div
                                className="spinner w-6 h-6 rounded-full"
                                style={{ border: "2px solid rgba(59,130,246,0.15)", borderTopColor: "#3b82f6" }}
                            />
                            <p style={{ fontSize: "0.875rem" }}>Завантаження листів…</p>
                        </div>
                    ) : emails.length === 0 ? (
                        <div className="py-16 flex flex-col items-center" style={{ color: "var(--muted-foreground)" }}>
                            <CheckCircle className="w-8 h-8 mb-3" style={{ color: "#22c55e" }} />
                            <p>Немає листів, що відповідають запиту</p>
                        </div>
                    ) : (
                        emails.map((email, idx) => (
                            <button
                                key={email.id}
                                onClick={() => onSelectEmail(email.id)}
                                className="w-full grid grid-cols-12 px-5 py-3.5 text-left transition-all duration-150 group"
                                style={{
                                    background: "transparent",
                                    border: "none",
                                    borderBottom: idx < emails.length - 1 ? "1px solid var(--border)" : "none",
                                    cursor: "pointer",
                                }}
                                onMouseEnter={(e) =>
                                    ((e.currentTarget as HTMLElement).style.background = "var(--accent)")
                                }
                                onMouseLeave={(e) =>
                                    ((e.currentTarget as HTMLElement).style.background = "transparent")
                                }
                            >
                                <div
                                    className="col-span-4 pr-4 flex items-center gap-2 min-w-0"
                                    style={{ color: "var(--foreground)", fontSize: "0.875rem" }}
                                >
                                    <div
                                        className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                                        style={{ background: riskColors[email.riskLevel] }}
                                    />
                                    <span className="truncate">{email.subject}</span>
                                </div>

                                <div
                                    className="col-span-2 truncate pr-4 flex items-center"
                                    style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem" }}
                                >
                                    {email.senderName}
                                </div>

                                <div className="col-span-2 pr-4 flex items-center">
                  <span
                      className="truncate"
                      style={{
                          color:
                              email.domainReputation === "Trusted"
                                  ? "var(--muted-foreground)"
                                  : riskColors[email.riskLevel],
                          fontFamily: "var(--font-mono)",
                          fontSize: "0.75rem",
                      }}
                  >
                    {email.domain}
                  </span>
                                </div>

                                <div
                                    className="col-span-2 flex items-center"
                                    style={{
                                        color: "var(--muted-foreground)",
                                        fontFamily: "var(--font-mono)",
                                        fontSize: "0.75rem",
                                    }}
                                >
                                    {new Date(email.date).toLocaleDateString("uk-UA", {
                                        day: "2-digit",
                                        month: "short",
                                    })}
                                </div>

                                <div className="col-span-1 flex items-center">
                                    <RiskBadge level={email.riskLevel} />
                                </div>

                                <div className="col-span-1 flex items-center justify-end">
                                    <ChevronRight
                                        className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity"
                                        style={{ color: "var(--muted-foreground)" }}
                                    />
                                </div>
                            </button>
                        ))
                    )}
                </div>

                <p
                    className="text-center pb-6"
                    style={{
                        color: "var(--muted-foreground)",
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.7rem",
                    }}
                >
                    ПОКАЗАНО {emails.length} З {total} ЛИСТІВ
                </p>
            </main>
        </div>
    );
}