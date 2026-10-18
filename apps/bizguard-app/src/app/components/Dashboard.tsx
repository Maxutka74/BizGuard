import { useState, useEffect, useCallback, useRef, type FormEvent } from "react";
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
    KeyRound,
    Activity,
    Plus,
    Trash2,
} from "lucide-react";
import { riskColors, riskBgColors, type RiskLevel } from "./riskStyles";
import {
    fetchEmails,
    fetchEmailProgress,
    fetchEmailStats,
    fetchGmailStatus,
    fetchScanStatus,
    fetchTrustedSenderRules,
    createTrustedSenderRule,
    deleteTrustedSenderRule,
    triggerScan,
    type EmailListItem,
    type GmailAccountStatus,
    type ScanStatus,
    type TrustedSenderRule,
    type EmailStats,
} from "../../api/gmail";
import type { User } from "../../api/auth";
import { fetchLicensePlans, type LicensePlanInfo } from "../../api/licenses";

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

function AiPendingBadge() {
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded whitespace-nowrap"
            style={{
                background: "rgba(59,130,246,0.12)",
                color: "#60a5fa",
                fontFamily: "var(--font-mono)",
                fontSize: "0.7rem",
                fontWeight: 600,
                letterSpacing: "0.04em",
                border: "1px solid rgba(96,165,250,0.28)",
            }}
        >
            ОЧІКУЄ AI
        </span>
    );
}

function SpamMovedBadge() {
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded whitespace-nowrap"
            style={{
                background: "rgba(239,68,68,0.12)",
                color: "#fecaca",
                fontFamily: "var(--font-mono)",
                fontSize: "0.65rem",
                fontWeight: 700,
                letterSpacing: "0.04em",
                border: "1px solid rgba(248,113,113,0.28)",
            }}
        >
            SPAM
        </span>
    );
}

function isAiPending(email: EmailListItem) {
    return email.analysis_status !== "done";
}

function formatDate(value?: string | null) {
    if (!value) return "—";
    return new Date(value).toLocaleDateString("uk-UA", {
        day: "2-digit",
        month: "short",
        year: "numeric",
    });
}

function formatScanDateTime(value: string) {
    const parts = new Intl.DateTimeFormat("uk-UA", {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
    }).formatToParts(new Date(value));
    const part = (type: Intl.DateTimeFormatPartTypes) =>
        parts.find((item) => item.type === type)?.value ?? "";
    return `${part("day")} ${part("month")} ${part("hour")}:${part("minute")}`;
}
const emptyEmailStats: EmailStats = {
    total: 0,
    analyzed: 0,
    pendingAi: 0,
    suspicious: 0,
    high: 0,
    critical: 0,
    distribution: { Critical: 0, High: 0, Medium: 0, Safe: 0 },
    lastScannedAt: null,
};

export function Dashboard({ user, onSelectEmail, onLogout }: DashboardProps) {
    const [search, setSearch] = useState("");
    const [filterRisk, setFilterRisk] = useState<RiskLevel | "All">("All");
    const [scanning, setScanning] = useState(false);
    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);

    const [emails, setEmails] = useState<EmailListItem[]>([]);
    const [stats, setStats] = useState<EmailStats | null>(null);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [autoScanStarted, setAutoScanStarted] = useState(false);
    const [showPlanPanel, setShowPlanPanel] = useState(false);
    const [plans, setPlans] = useState<LicensePlanInfo[]>([]);
    const [gmailStatus, setGmailStatus] = useState<GmailAccountStatus | null>(null);
    const [trustedRules, setTrustedRules] = useState<TrustedSenderRule[]>([]);
    const [trustedRuleType, setTrustedRuleType] = useState<"domain" | "email">("domain");
    const [trustedRuleValue, setTrustedRuleValue] = useState("");
    const [trustedRulesLoading, setTrustedRulesLoading] = useState(false);
    const [trustedRuleBusy, setTrustedRuleBusy] = useState(false);
    const [trustedRulesError, setTrustedRulesError] = useState<string | null>(null);
    const scanTimerRef = useRef<number | null>(null);
    const progressTimerRef = useRef<number | null>(null);
    const [highlightedRows, setHighlightedRows] = useState<Record<string, number>>({});
    const capabilities = user?.license?.capabilities;
    const scanLimit = capabilities?.maxMessagesPerRun ?? 30;
    const realTimeLabel = capabilities?.autoMonitor
        ? `Моніторинг кожні ${capabilities.autoMonitorIntervalMinutes} хв`
        : "Ручна перевірка";
    const planLabel = user?.license?.planLabel ?? "Ліцензія";
    const criticalAlertsEnabled = Boolean(capabilities?.criticalAlerts);
    const highCriticalCount = stats?.high ?? ((stats?.distribution?.High ?? 0) + (stats?.distribution?.Critical ?? 0));
    const gmailConnected = gmailStatus?.connected === true;
    const gmailChecked = gmailStatus !== null;
    const gmailReconnectRequired = Boolean(capabilities?.autoSpamCritical && gmailStatus?.account?.reconnectRequired);

    useEffect(() => {
        fetchLicensePlans()
            .then(setPlans)
            .catch(() => setPlans([]));
        fetchGmailStatus()
            .then(setGmailStatus)
            .catch(() => setGmailStatus({ connected: false }));
    }, []);

    const loadTrustedRules = useCallback(() => {
        if (!capabilities?.trustedSenderAllowlist) {
            setTrustedRules([]);
            return Promise.resolve();
        }
        setTrustedRulesLoading(true);
        setTrustedRulesError(null);
        return fetchTrustedSenderRules()
            .then((data) => setTrustedRules(data.rules ?? []))
            .catch((err: any) => {
                setTrustedRulesError(err?.detail ?? "Не вдалося завантажити дозволені домени");
                setTrustedRules([]);
            })
            .finally(() => setTrustedRulesLoading(false));
    }, [capabilities?.trustedSenderAllowlist]);

    useEffect(() => {
        if (showPlanPanel) {
            void loadTrustedRules();
        }
    }, [loadTrustedRules, showPlanPanel]);

    const addTrustedRule = useCallback((event: FormEvent) => {
        event.preventDefault();
        const value = trustedRuleValue.trim().toLowerCase().replace(/^@/, "");
        if (!value || trustedRuleBusy || !capabilities?.trustedSenderAllowlist) return;
        setTrustedRuleBusy(true);
        setTrustedRulesError(null);
        createTrustedSenderRule({ ruleType: trustedRuleType, value, active: true })
            .then((rule) => {
                setTrustedRules((current) => [rule, ...current.filter((item) => item.id !== rule.id)]);
                setTrustedRuleValue("");
            })
            .catch((err: any) => setTrustedRulesError(err?.detail ?? "Не вдалося додати правило"))
            .finally(() => setTrustedRuleBusy(false));
    }, [capabilities?.trustedSenderAllowlist, trustedRuleBusy, trustedRuleType, trustedRuleValue]);

    const removeTrustedRule = useCallback((ruleId: number) => {
        if (trustedRuleBusy) return;
        setTrustedRuleBusy(true);
        setTrustedRulesError(null);
        deleteTrustedSenderRule(ruleId)
            .then(() => setTrustedRules((current) => current.filter((rule) => rule.id !== ruleId)))
            .catch((err: any) => setTrustedRulesError(err?.detail ?? "Не вдалося видалити правило"))
            .finally(() => setTrustedRuleBusy(false));
    }, [trustedRuleBusy]);

    const loadEmails = useCallback(() => {
        setError(null);
        if (!gmailChecked) {
            return Promise.resolve({ emailsRes: { emails: [], total: 0 }, statsRes: emptyEmailStats });
        }
        if (!gmailConnected) {
            setEmails([]);
            setTotal(0);
            setStats(emptyEmailStats);
            setLoading(false);
            return Promise.resolve({ emailsRes: { emails: [], total: 0 }, statsRes: emptyEmailStats });
        }
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
                return { emailsRes, statsRes };
            })
            .catch((err: any) => {
                setError(err?.detail ?? "Не вдалося завантажити листи");
                setLoading(false);
            });
    }, [search, filterRisk, gmailChecked, gmailConnected]);


    const mergeProgress = useCallback((progress: any) => {
        if (progress?.stats) {
            setStats(progress.stats);
            if (!search && filterRisk === "All") {
                setTotal(progress.stats.total ?? 0);
            }
        }
        const items = new Map((progress?.emails ?? []).map((item: any) => [item.id, item]));
        const completedIds: string[] = [];
        setEmails((current) => current.map((email) => {
            const item: any = items.get(email.id);
            if (!item) return email;
            const wasPending = isAiPending(email);
            const next = {
                ...email,
                analysis_status: item.analysis_status ?? email.analysis_status,
                analysisSource: item.analysisSource ?? email.analysisSource,
                riskLevel: item.riskLevel ?? email.riskLevel,
                threatScore: typeof item.threatScore === "number" ? item.threatScore : email.threatScore,
                spamActionStatus: item.spamActionStatus ?? email.spamActionStatus,
                spamActionAt: item.spamActionAt ?? email.spamActionAt,
            };
            if (wasPending && next.analysis_status === "done") {
                completedIds.push(email.id);
            }
            return next;
        }));
        if (completedIds.length) {
            const expiresAt = Date.now() + 1800;
            setHighlightedRows((current) => {
                const next = { ...current };
                completedIds.forEach((id) => {
                    next[id] = expiresAt;
                });
                return next;
            });
            window.setTimeout(() => {
                setHighlightedRows((current) => {
                    const next = { ...current };
                    completedIds.forEach((id) => delete next[id]);
                    return next;
                });
            }, 1900);
        }
        return progress;
    }, [filterRisk, search]);
    useEffect(() => {
        setLoading(true);
        const timer = setTimeout(loadEmails, search ? 300 : 0);
        return () => clearTimeout(timer);
    }, [loadEmails]);

    const stopPolling = useCallback(() => {
        if (scanTimerRef.current !== null) {
            window.clearInterval(scanTimerRef.current);
            scanTimerRef.current = null;
        }
    }, []);

    useEffect(() => stopPolling, [stopPolling]);

    const scanIsComplete = useCallback((status: ScanStatus, loaded: any) => {
        const loadedStats = loaded?.statsRes;
        const loadedTotal = loadedStats?.total ?? loaded?.emailsRes?.total ?? 0;
        const fetched = status.fetched || loadedTotal;
        const targetReached = loadedTotal >= scanLimit || (status.ready && fetched < scanLimit);
        const aiFinished = (loadedStats?.pendingAi ?? 0) === 0;
        return status.ready && targetReached && aiFinished;
    }, [scanLimit]);

    const pollScanUntilComplete = useCallback((scanId?: string) => {
        stopPolling();
        scanTimerRef.current = window.setInterval(() => {
            const statusPromise = scanId
                ? fetchScanStatus(scanId)
                : Promise.resolve({
                    state: "INLINE",
                    fetched: total,
                    processed: total,
                    created: 0,
                    updated: 0,
                    errors: 0,
                    pending_ai: stats?.pendingAi ?? 0,
                    ready: true,
                } as ScanStatus);

            statusPromise
                .then((status) => {
                    setScanStatus(status);
                    return loadEmails().then((loaded: any) => {
                        if (scanIsComplete(status, loaded)) {
                            stopPolling();
                            setScanning(false);
                        }
                    });
                })
                .catch((err: any) => {
                    stopPolling();
                    setError(err?.detail ?? "Не вдалося прочитати статус сканування");
                    setScanning(false);
                });
        }, 2000);
    }, [loadEmails, scanIsComplete, stats?.pendingAi, stopPolling, total]);


    useEffect(() => {
        let cancelled = false;
        const clearProgressTimer = () => {
            if (progressTimerRef.current !== null) {
                window.clearTimeout(progressTimerRef.current);
                progressTimerRef.current = null;
            }
        };
        const schedule = (delay: number) => {
            clearProgressTimer();
            if (!cancelled) {
                progressTimerRef.current = window.setTimeout(run, delay);
            }
        };
        const run = () => {
            if (cancelled || !user?.email || !gmailConnected) return;
            if (document.hidden) {
                schedule(10000);
                return;
            }
            fetchEmailProgress()
                .then((progress) => {
                    mergeProgress(progress);
                    const fast = Boolean(progress?.hasPending || scanning);
                    if (!fast && scanning) {
                        setScanning(false);
                    }
                    schedule(fast ? 1000 : 10000);
                })
                .catch(() => schedule(5000));
        };
        run();
        const onVisibilityChange = () => {
            if (!document.hidden) {
                run();
            }
        };
        document.addEventListener("visibilitychange", onVisibilityChange);
        return () => {
            cancelled = true;
            clearProgressTimer();
            document.removeEventListener("visibilitychange", onVisibilityChange);
        };
    }, [gmailConnected, mergeProgress, scanning, user?.email]);
    const handleScan = useCallback(() => {
        if (scanning) return;
        if (!gmailConnected) {
            setError("Спочатку підключіть Gmail, щоб сканувати листи.");
            return;
        }
        setScanning(true);
        setScanStatus(null);
        stopPolling();
        triggerScan(scanLimit)
            .then((result) => {
                if (result.scan_id && result.queued) {
                    setScanStatus({
                        state: "PENDING",
                        fetched: 0,
                        processed: 0,
                        created: 0,
                        updated: 0,
                        errors: 0,
                        pending_ai: 0,
                        ready: false,
                    });
                    pollScanUntilComplete(result.scan_id);
                    return loadEmails();
                }
                return loadEmails().then((loaded: any) => {
                    if ((loaded?.statsRes?.pendingAi ?? 0) > 0) {
                        pollScanUntilComplete();
                    } else {
                        setScanning(false);
                    }
                });
            })
            .catch((err: any) => {
                setError(err?.detail ?? "Помилка сканування");
                setScanning(false);
            });
    }, [gmailConnected, loadEmails, pollScanUntilComplete, scanLimit, scanning, stopPolling]);

    useEffect(() => {
        if (autoScanStarted || loading || scanning || search || filterRisk !== "All" || !gmailConnected) {
            return;
        }
        if ((stats?.total ?? 0) === 0 && user?.email) {
            setAutoScanStarted(true);
            handleScan();
        }
    }, [autoScanStarted, filterRisk, gmailConnected, handleScan, loading, scanning, search, stats?.total, user?.email]);

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
                    <span
                        className="hidden sm:inline-flex items-center rounded px-2 py-0.5"
                        style={{
                            color: "#93c5fd",
                            background: "rgba(59,130,246,0.12)",
                            border: "1px solid rgba(96,165,250,0.25)",
                            fontFamily: "var(--font-mono)",
                            fontSize: "0.65rem",
                            letterSpacing: "0.04em",
                        }}
                    >
                        {planLabel}
                    </span>
                    <span
                        className="hidden md:inline-flex items-center rounded px-2 py-0.5"
                        style={{
                            color: capabilities?.autoMonitor ? "#bbf7d0" : "var(--muted-foreground)",
                            background: capabilities?.autoMonitor ? "rgba(34,197,94,0.1)" : "var(--secondary)",
                            border: capabilities?.autoMonitor ? "1px solid rgba(34,197,94,0.25)" : "1px solid var(--border)",
                            fontFamily: "var(--font-mono)",
                            fontSize: "0.65rem",
                            letterSpacing: "0.04em",
                        }}
                    >
                        {realTimeLabel}
                    </span>
                </div>

                <div className="flex items-center gap-3">
                    <button
                        onClick={() => setShowPlanPanel(true)}
                        className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all duration-200 hover:opacity-85"
                        style={{
                            background: "var(--secondary)",
                            color: "var(--foreground)",
                            fontSize: "0.8125rem",
                            border: "1px solid var(--border)",
                            cursor: "pointer",
                        }}
                    >
                        <KeyRound className="w-3.5 h-3.5" />
                        Мій тариф
                    </button>

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
                        {scanning ? "Сканування..." : `Перевірити ${scanLimit}`}
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

            {showPlanPanel && (
                <div
                    className="fixed inset-0 z-40 flex items-center justify-center px-4"
                    style={{ background: "rgba(2,6,23,0.72)", backdropFilter: "blur(8px)" }}
                    onClick={() => setShowPlanPanel(false)}
                >
                    <div
                        className="w-full max-w-4xl rounded-xl overflow-hidden"
                        style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div
                            className="flex items-start justify-between gap-4 px-5 py-4"
                            style={{ borderBottom: "1px solid var(--border)" }}
                        >
                            <div>
                                <p style={{ color: "var(--foreground)", fontWeight: 700, fontSize: "1rem" }}>
                                    Мій тариф
                                </p>
                                <p style={{ color: "var(--muted-foreground)", fontSize: "0.8rem", marginTop: 4 }}>
                                    {planLabel} · діє до {formatDate(user?.license?.expiresAt)}
                                </p>
                            </div>
                            <button
                                onClick={() => setShowPlanPanel(false)}
                                className="px-3 py-1.5 rounded-lg"
                                style={{
                                    background: "var(--secondary)",
                                    color: "var(--muted-foreground)",
                                    border: "1px solid var(--border)",
                                    fontSize: "0.8rem",
                                }}
                            >
                                Закрити
                            </button>
                        </div>

                        <div className="grid md:grid-cols-3 gap-3 p-5">
                            {[
                                ["Ручна перевірка", `Останні ${scanLimit} листів`],
                                [
                                    "Вікно моніторингу",
                                    capabilities?.autoMonitor
                                        ? `${capabilities?.recentLookbackDays ?? 1} дн.`
                                        : "Без фонового моніторингу",
                                ],
                                [
                                    "Підтвердження ключа",
                                    capabilities?.monthlyConfirmation
                                        ? `До ${formatDate(user?.license?.confirmationDueAt)}`
                                        : "Не потрібне",
                                ],
                                ["URL за лист", `${capabilities?.maxUrlsPerEmail ?? 0}`],
                                ["Вкладення за лист", `${capabilities?.maxAttachmentsPerEmail ?? 0}`],
                                ["AI-черга", capabilities?.priorityAi ? "Пріоритетна" : "Стандартна"],
                                ["Автоспам критичних", capabilities?.autoSpamCritical ? "Увімкнено" : "Недоступно"],
                                ["Дозволені домени", capabilities?.trustedSenderAllowlist ? "Увімкнено" : "Недоступно"],
                                ["Пріоритетна повторна перевірка", capabilities?.priorityRecheck ? "Увімкнено" : "Стандартна"],
                                [
                                    "Активації ключа",
                                    user?.license?.maxActivations
                                        ? `Використано ${user.license.activationCount}/${user.license.maxActivations}`
                                        : "Немає даних",
                                ],
                            ].map(([label, value]) => (
                                <div
                                    key={label}
                                    className="rounded-lg px-3 py-3"
                                    style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
                                >
                                    <p style={{ color: "var(--muted-foreground)", fontSize: "0.72rem" }}>{label}</p>
                                    <p style={{ color: "var(--foreground)", fontSize: "0.9rem", marginTop: 4 }}>{value}</p>
                                </div>
                            ))}
                        </div>

                        <div className="px-5 pb-5">
                            <div
                                className="rounded-lg p-4"
                                style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
                            >
                                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 mb-3">
                                    <div>
                                        <p style={{ color: "var(--foreground)", fontWeight: 650, fontSize: "0.9rem" }}>
                                            Дозволені домени та відправники
                                        </p>
                                        <p style={{ color: "var(--muted-foreground)", fontSize: "0.78rem", marginTop: 3 }}>
                                            Critical-листи з цього списку не переносяться у спам автоматично.
                                        </p>
                                    </div>
                                    {!capabilities?.trustedSenderAllowlist && (
                                        <span
                                            className="rounded px-2 py-1"
                                            style={{ color: "#fde68a", background: "rgba(234,179,8,0.12)", border: "1px solid rgba(234,179,8,0.25)", fontSize: "0.72rem" }}
                                        >
                                            Доступно на річному тарифі
                                        </span>
                                    )}
                                </div>

                                {capabilities?.trustedSenderAllowlist ? (
                                    <>
                                        <form onSubmit={addTrustedRule} className="grid md:grid-cols-[130px_1fr_auto] gap-2 mb-3">
                                            <select
                                                value={trustedRuleType}
                                                onChange={(event) => setTrustedRuleType(event.target.value as "domain" | "email")}
                                                className="rounded-lg px-3 py-2 outline-none"
                                                style={{ background: "var(--card)", border: "1px solid var(--border)", color: "var(--foreground)", fontSize: "0.82rem" }}
                                            >
                                                <option value="domain">Домен</option>
                                                <option value="email">Email</option>
                                            </select>
                                            <input
                                                value={trustedRuleValue}
                                                onChange={(event) => setTrustedRuleValue(event.target.value)}
                                                placeholder={trustedRuleType === "domain" ? "example.com" : "security@example.com"}
                                                className="rounded-lg px-3 py-2 outline-none"
                                                style={{ background: "var(--card)", border: "1px solid var(--border)", color: "var(--foreground)", fontSize: "0.82rem" }}
                                                autoComplete="off"
                                                spellCheck={false}
                                            />
                                            <button
                                                type="submit"
                                                disabled={!trustedRuleValue.trim() || trustedRuleBusy}
                                                className="flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 transition-opacity hover:opacity-85"
                                                style={{ background: "var(--primary)", color: "#fff", border: "none", fontSize: "0.82rem", fontWeight: 650, opacity: !trustedRuleValue.trim() || trustedRuleBusy ? 0.6 : 1 }}
                                            >
                                                <Plus className="w-3.5 h-3.5" />
                                                Додати
                                            </button>
                                        </form>

                                        {trustedRulesError && (
                                            <p className="mb-3" style={{ color: "#fca5a5", fontSize: "0.78rem" }}>{trustedRulesError}</p>
                                        )}

                                        <div className="space-y-2">
                                            {trustedRulesLoading ? (
                                                <p style={{ color: "var(--muted-foreground)", fontSize: "0.78rem" }}>Завантаження списку...</p>
                                            ) : trustedRules.length ? trustedRules.map((rule) => (
                                                <div
                                                    key={rule.id}
                                                    className="flex items-center justify-between gap-3 rounded-lg px-3 py-2"
                                                    style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                                                >
                                                    <div className="min-w-0">
                                                        <p style={{ color: "var(--foreground)", fontSize: "0.84rem", overflowWrap: "anywhere" }}>{rule.value}</p>
                                                        <p style={{ color: "var(--muted-foreground)", fontSize: "0.68rem", marginTop: 2 }}>
                                                            {rule.rule_type === "domain" ? "Домен" : "Email"} · {rule.active ? "Активне" : "Вимкнене"}
                                                        </p>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => removeTrustedRule(rule.id)}
                                                        disabled={trustedRuleBusy}
                                                        className="w-8 h-8 rounded-lg flex items-center justify-center transition-opacity hover:opacity-80"
                                                        style={{ background: "rgba(239,68,68,0.12)", color: "#fca5a5", border: "1px solid rgba(239,68,68,0.28)", opacity: trustedRuleBusy ? 0.6 : 1 }}
                                                        title="Видалити правило"
                                                    >
                                                        <Trash2 className="w-3.5 h-3.5" />
                                                    </button>
                                                </div>
                                            )) : (
                                                <p style={{ color: "var(--muted-foreground)", fontSize: "0.78rem" }}>
                                                    Список порожній. Додайте домен або email, якому довіряєте.
                                                </p>
                                            )}
                                        </div>
                                    </>
                                ) : (
                                    <p style={{ color: "var(--muted-foreground)", fontSize: "0.82rem", lineHeight: 1.5 }}>
                                        На поточному тарифі можна бачити статус функції, але керування списком дозволених доменів відкривається тільки на річному плані.
                                    </p>
                                )}
                            </div>
                        </div>
                        <div className="px-5 pb-5 overflow-x-auto">
                            <div
                                className="min-w-[720px] rounded-lg overflow-hidden"
                                style={{ border: "1px solid var(--border)" }}
                            >
                                <div
                                    className="grid grid-cols-6 px-3 py-2"
                                    style={{ background: "var(--secondary)", color: "var(--muted-foreground)", fontSize: "0.7rem", fontFamily: "var(--font-mono)" }}
                                >
                                    <span>ТАРИФ</span>
                                    <span>ТРИВАЛІСТЬ</span>
                                    <span>МОНІТОРИНГ</span>
                                    <span>РУЧНА</span>
                                    <span>ФОНОВИЙ</span>
                                    <span>ГЛИБОКА ПЕРЕВІРКА</span>
                                </div>
                                {plans.map((plan) => {
                                    const caps = plan.capabilities;
                                    const isCurrent = plan.plan === user?.license?.plan;
                                    return (
                                        <div
                                            key={plan.plan}
                                            className="grid grid-cols-6 px-3 py-3"
                                            style={{
                                                borderTop: "1px solid var(--border)",
                                                background: isCurrent ? "rgba(59,130,246,0.08)" : "transparent",
                                                color: "var(--foreground)",
                                                fontSize: "0.8rem",
                                            }}
                                        >
                                            <span>{plan.planLabel}</span>
                                            <span>{plan.durationDays} дн.</span>
                                            <span>{caps.autoMonitor ? `${caps.autoMonitorIntervalMinutes} хв` : "Ручний"}</span>
                                            <span>Останні {caps.maxMessagesPerRun}</span>
                                            <span>{caps.autoMonitor ? `${caps.recentLookbackDays} дн.` : "Немає"}</span>
                                            <span>
                                                До {caps.maxUrlsPerEmail} URL / до {caps.maxAttachmentsPerEmail} вклад.
                                                {caps.autoSpamCritical ? " / автоспам" : ""}
                                                {caps.trustedSenderAllowlist ? " / дозволені домени" : ""}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            )}

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

                {gmailReconnectRequired && (
                    <div
                        className="rounded-lg px-4 py-3 flex items-center gap-2"
                        style={{ background: "rgba(234,179,8,0.1)", border: "1px solid rgba(234,179,8,0.3)" }}
                    >
                        <AlertTriangle className="w-4 h-4 flex-shrink-0" style={{ color: "#eab308" }} />
                        <span style={{ color: "#fde68a", fontSize: "0.875rem" }}>
                            Потрібно перепідключити Google для автоматичного перенесення критичних листів у спам. Поточний доступ не має gmail.modify.
                        </span>
                    </div>
                )}

                {scanning && scanStatus && (
                    <div
                        className="rounded-lg px-4 py-3 flex items-center justify-between gap-3"
                        style={{ background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.3)" }}
                    >
                        <span style={{ color: "#93c5fd", fontSize: "0.875rem" }}>
                            {scanStatus.ready
                                ? `AI аналіз: ${stats?.analyzed ?? 0}/${stats?.total ?? 0} завершено`
                                : `Завантаження листів: ${scanStatus.processed}/${scanStatus.fetched}`}
                        </span>
                        <span style={{ color: "var(--muted-foreground)", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                            +{scanStatus.created} нових, {scanStatus.updated} оновлено, очікує AI: {stats?.pendingAi ?? scanStatus.pending_ai ?? 0}
                        </span>
                    </div>
                )}

                {criticalAlertsEnabled && highCriticalCount > 0 && (
                    <div
                        className="rounded-lg px-4 py-3 flex items-center justify-between gap-3"
                        style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.28)" }}
                    >
                        <div className="flex items-center gap-2">
                            <Activity className="w-4 h-4" style={{ color: "#ef4444" }} />
                            <span style={{ color: "#fecaca", fontSize: "0.875rem", fontWeight: 600 }}>
                                Попередження високого/критичного рівня: {highCriticalCount} листів потребують уваги
                            </span>
                        </div>
                        <button
                            onClick={() => setFilterRisk((stats?.critical ?? 0) > 0 ? "Critical" : "High")}
                            className="px-3 py-1.5 rounded-lg"
                            style={{
                                background: "rgba(239,68,68,0.16)",
                                border: "1px solid rgba(248,113,113,0.3)",
                                color: "#fecaca",
                                fontSize: "0.78rem",
                                cursor: "pointer",
                            }}
                        >
                            Показати
                        </button>
                    </div>
                )}

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                        {
                            label: "Завантажено листів",
                            value: stats?.total ?? 0,
                            icon: Mail,
                            color: "#3b82f6",
                            bg: "rgba(59,130,246,0.1)",
                        },
                        {
                            label: "Проаналізовано AI",
                            value: stats?.analyzed ?? 0,
                            icon: CheckCircle,
                            color: "#22c55e",
                            bg: "rgba(34,197,94,0.1)",
                        },
                        {
                            label: "Очікує AI",
                            value: stats?.pendingAi ?? 0,
                            icon: AlertTriangle,
                            color: "#eab308",
                            bg: "rgba(234,179,8,0.1)",
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
                            {formatScanDateTime(stats.lastScannedAt)}
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
                            <p style={{ fontSize: "0.875rem" }}>Завантаження листів...</p>
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
                                    ((e.currentTarget as HTMLElement).style.background = highlightedRows[email.id] ? "rgba(34,197,94,0.08)" : "transparent")
                                }
                            >
                                <div
                                    className="col-span-4 pr-4 flex items-center gap-2 min-w-0"
                                    style={{ color: "var(--foreground)", fontSize: "0.875rem" }}
                                >
                                    <div
                                        className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                                        style={{ background: isAiPending(email) ? "#60a5fa" : riskColors[email.riskLevel] }}
                                    />
                                    <span className="truncate">{email.subject}</span>
                                    {email.spamActionStatus === "moved" && <SpamMovedBadge />}
                                </div>

                                <div
                                    className="col-span-2 pr-4 flex items-center min-w-0 overflow-hidden"
                                    style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem" }}
                                >
                                    <span className="truncate min-w-0" title={email.senderName || email.sender}>
                                        {email.senderName || email.sender}
                                    </span>
                                </div>

                                <div className="col-span-2 pr-4 flex items-center min-w-0 overflow-hidden">
                  <span
                      className="truncate min-w-0"
                      style={{
                          color:
                              email.domainReputation === "Trusted"
                                  ? "var(--muted-foreground)"
                                  : isAiPending(email) ? "#60a5fa" : riskColors[email.riskLevel],
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

                                <div className="col-span-1 flex items-center min-w-0">
                                    {isAiPending(email) ? <AiPendingBadge /> : <RiskBadge level={email.riskLevel} />}
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





