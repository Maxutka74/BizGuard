import { useState, useEffect } from "react";
import {
    ArrowLeft,
    Shield,
    AlertTriangle,
    CheckCircle,
    Globe,
    Clock,
    Copy,
    ExternalLink,
    Link2,
    Paperclip,
    XCircle,
} from "lucide-react";
import { riskColors, riskBgColors, type RiskLevel } from "./mockData";
import { fetchEmailDetail, type EmailDetail as EmailDetailData } from "../../api/gmail";

interface EmailDetailProps {
    emailId: string;
    onBack: () => void;
}

const levelTranslations: Record<RiskLevel, string> = {
    Critical: "КРИТИЧНИЙ",
    High: "ВИСОКИЙ",
    Medium: "СЕРЕДНІЙ",
    Safe: "БЕЗПЕЧНИЙ",
};

const repTranslations = {
    Trusted: "Надійний",
    Suspicious: "Підозрілий",
    Malicious: "Шкідливий",
};

const aiMetricLabels: Record<string, string> = {
    "Urgency": "Терміновість",
    "Pressure / Threats": "Тиск / погрози",
    "Credential Theft": "Крадіжка облікових даних",
    "Financial Fraud": "Фінансове шахрайство",
    "Authority Impersonation": "Імітація авторитету",
};

const recommendationLabels: Record<string, string> = {
    "Email appears legitimate": "Лист виглядає легітимним",
    "No action required": "Дії не потрібні",
    "Do not click any links": "Не переходьте за посиланнями",
    "Do not enter credentials": "Не вводьте облікові дані",
    "Do not reply or engage": "Не відповідайте та не взаємодійте",
    "Mark as phishing in Gmail": "Позначте як фішинг у Gmail",
    "Report to IT Security": "Повідомте службу ІТ-безпеки",
    "Block sender domain immediately": "Негайно заблокуйте домен відправника",
};

function ScoreBar({ label, value, color }: { label: string; value: number; color: string }) {
    return (
        <div className="space-y-1.5">
            <div className="flex justify-between items-center">
                <span style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem" }}>{aiMetricLabels[label] ?? label}</span>
                <span
                    style={{
                        color,
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.8rem",
                        fontWeight: 600,
                    }}
                >
          {value}%
        </span>
            </div>
            <div
                className="h-1.5 rounded-full overflow-hidden"
                style={{ background: "var(--secondary)" }}
            >
                <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${value}%`, background: color }}
                />
            </div>
        </div>
    );
}

function UrlScanSection({ email }: { email: EmailDetailData }) {
    const urls = email.scannedUrls ?? [];
    if (urls.length === 0) return null;

    const score = email.urlScore ?? 0;
    const color = score >= 70 ? "#ef4444" : score >= 40 ? "#eab308" : "#22c55e";

    return (
        <div
            className="rounded-xl p-6"
            style={{ background: "var(--card)", border: "1px solid var(--border)" }}
        >
            <div className="flex items-center justify-between gap-3 mb-4">
                <div className="flex items-center gap-2">
                    <Link2 className="w-4 h-4" style={{ color }} />
                    <h3 style={{ color: "var(--foreground)", fontWeight: 600 }}>Перевірка репутації URL</h3>
                </div>
                <span
                    style={{
                        color,
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.8rem",
                        fontWeight: 700,
                    }}
                >
                    {score}/100
                </span>
            </div>
            {email.urlScanSummary && (
                <p className="mb-4" style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem" }}>
                    {email.urlScanSummary}
                </p>
            )}
            <div className="space-y-2">
                {urls.map((item) => {
                    const itemColor =
                        item.verdict === "Malicious"
                            ? "#ef4444"
                            : item.verdict === "Suspicious" || item.verdict === "Pending"
                              ? "#eab308"
                              : item.verdict === "Error"
                                ? "var(--muted-foreground)"
                                : "#22c55e";
                    return (
                        <div
                            key={item.url}
                            className="rounded-lg p-3"
                            style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
                        >
                            <div className="flex items-center justify-between gap-3 min-w-0">
                                <span
                                    className="truncate min-w-0"
                                    title={item.url}
                                    style={{
                                        color: "var(--foreground)",
                                        fontFamily: "var(--font-mono)",
                                        fontSize: "0.75rem",
                                        overflowWrap: "anywhere",
                                        wordBreak: "break-word",
                                    }}
                                >
                                    {item.url}
                                </span>
                                <span
                                    style={{
                                        color: itemColor,
                                        fontFamily: "var(--font-mono)",
                                        fontSize: "0.7rem",
                                        fontWeight: 700,
                                    }}
                                >
                                    {item.verdict}{item.confidence ? ` (${item.confidence})` : ""} · {item.score}
                                </span>
                            </div>
                            {item.error && (
                                <p className="mt-2" style={{ color: "var(--muted-foreground)", fontSize: "0.72rem" }}>
                                    {item.error}
                                </p>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function AttachmentScanSection({ email }: { email: EmailDetailData }) {
    const attachments = email.scannedAttachments ?? [];
    if (attachments.length === 0) return null;

    const score = email.attachmentScore ?? 0;
    const color = score >= 70 ? "#ef4444" : score >= 40 ? "#eab308" : "#22c55e";

    return (
        <div
            className="rounded-xl p-6"
            style={{ background: "var(--card)", border: "1px solid var(--border)" }}
        >
            <div className="flex items-center justify-between gap-3 mb-4">
                <div className="flex items-center gap-2">
                    <Paperclip className="w-4 h-4" style={{ color }} />
                    <h3 style={{ color: "var(--foreground)", fontWeight: 600 }}>Перевірка вкладень</h3>
                </div>
                <span
                    style={{
                        color,
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.8rem",
                        fontWeight: 700,
                    }}
                >
                    {score}/100
                </span>
            </div>
            {email.attachmentScanSummary && (
                <p className="mb-4" style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem" }}>
                    {email.attachmentScanSummary}
                </p>
            )}
            <div className="space-y-2">
                {attachments.map((item) => {
                    const itemColor =
                        item.verdict === "Malicious"
                            ? "#ef4444"
                            : item.verdict === "Suspicious" || item.verdict === "Pending"
                              ? "#eab308"
                              : item.verdict === "Error"
                                ? "var(--muted-foreground)"
                                : "#22c55e";
                    return (
                        <div
                            key={`${item.filename}-${item.size_bytes}`}
                            className="rounded-lg p-3"
                            style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
                        >
                            <div className="flex items-center justify-between gap-3 min-w-0">
                                <span
                                    className="truncate min-w-0"
                                    title={item.filename}
                                    style={{
                                        color: "var(--foreground)",
                                        fontFamily: "var(--font-mono)",
                                        fontSize: "0.75rem",
                                        overflowWrap: "anywhere",
                                        wordBreak: "break-word",
                                    }}
                                >
                                    {item.filename}
                                </span>
                                <span
                                    style={{
                                        color: itemColor,
                                        fontFamily: "var(--font-mono)",
                                        fontSize: "0.7rem",
                                        fontWeight: 700,
                                    }}
                                >
                                    {item.verdict} · {item.score}
                                </span>
                            </div>
                            <div className="mt-1 flex flex-wrap gap-2" style={{ color: "var(--muted-foreground)", fontSize: "0.72rem" }}>
                                <span>{item.mime_type || "unknown"}</span>
                                <span>{Math.max(0, Math.round((item.size_bytes || 0) / 1024))} KB</span>
                            </div>
                            {item.local_findings && item.local_findings.length > 0 && (
                                <p className="mt-2" style={{ color: "var(--muted-foreground)", fontSize: "0.72rem" }}>
                                    {item.local_findings.join(", ")}
                                </p>
                            )}
                            {item.error && (
                                <p className="mt-2" style={{ color: "var(--muted-foreground)", fontSize: "0.72rem" }}>
                                    {item.error}
                                </p>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function SpamActionBanner({ email }: { email: EmailDetailData }) {
    if (!email.spamActionStatus || email.spamActionStatus === "none") return null;

    const moved = email.spamActionStatus === "moved";
    const skipped = email.spamActionStatus === "skipped";
    const color = moved ? "#22c55e" : skipped ? "#93c5fd" : "#ef4444";
    const bg = moved ? "rgba(34,197,94,0.1)" : skipped ? "rgba(59,130,246,0.12)" : "rgba(239,68,68,0.1)";
    const border = moved ? "rgba(34,197,94,0.28)" : skipped ? "rgba(96,165,250,0.3)" : "rgba(239,68,68,0.3)";
    const Icon = moved ? CheckCircle : skipped ? Shield : AlertTriangle;
    const title = moved
        ? "Лист переведено у спам"
        : skipped
          ? "Автоспам пропущено"
          : "Не вдалося перенести у спам";
    const body = moved
        ? "Критичний лист автоматично прибрано з INBOX через Gmail."
        : skipped
          ? "Відправник або домен є у списку дозволених."
          : email.spamActionError || "Потрібно перепідключити Google для автоматичного перенесення у спам.";

    return (
        <div
            className="rounded-xl p-4 flex items-start gap-3"
            style={{ background: bg, border: `1px solid ${border}` }}
        >
            <Icon className="w-5 h-5 flex-shrink-0 mt-0.5" style={{ color }} />
            <div>
                <p style={{ color, fontWeight: 700, fontSize: "0.9rem" }}>{title}</p>
                <p style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem", marginTop: 4 }}>
                    {body}
                </p>
                {email.spamActionAt && (
                    <p style={{ color: "var(--muted-foreground)", fontFamily: "var(--font-mono)", fontSize: "0.7rem", marginTop: 6 }}>
                        {new Date(email.spamActionAt).toLocaleString("uk-UA")}
                    </p>
                )}
            </div>
        </div>
    );
}

function RiskMeter({ score, level, pending = false }: { score: number; level: RiskLevel; pending?: boolean }) {
    const color = pending ? "#60a5fa" : riskColors[level];
    const bg = pending ? "rgba(59,130,246,0.12)" : riskBgColors[level];
    const label = pending ? "ОЧІКУЄ AI" : levelTranslations[level];
    const circumference = 2 * Math.PI * 42;
    const offset = circumference - (score / 100) * circumference;

    return (
        <div className="flex flex-col items-center">
            <div className="relative w-28 h-28">
                <svg className="w-28 h-28 -rotate-90" viewBox="0 0 96 96">
                    <circle cx="48" cy="48" r="42" fill="none" stroke="var(--secondary)" strokeWidth="8" />
                    <circle
                        cx="48"
                        cy="48"
                        r="42"
                        fill="none"
                        stroke={color}
                        strokeWidth="8"
                        strokeLinecap="round"
                        strokeDasharray={circumference}
                        strokeDashoffset={offset}
                        style={{
                            filter: `drop-shadow(0 0 6px ${color}88)`,
                            transition: "stroke-dashoffset 1s ease",
                        }}
                    />
                </svg>
                <div
                    className="absolute inset-0 flex flex-col items-center justify-center"
                    style={{ fontFamily: "var(--font-mono)" }}
                >
                    <span style={{ color, fontSize: "1.5rem", fontWeight: 700, lineHeight: 1 }}>{score}</span>
                    <span style={{ color: "var(--muted-foreground)", fontSize: "0.65rem" }}>/100</span>
                </div>
            </div>
            <div
                className="mt-3 px-4 py-1 rounded-full"
                style={{ background: bg, border: `1px solid ${color}44` }}
            >
        <span
            style={{
                color,
                fontFamily: "var(--font-mono)",
                fontSize: "0.75rem",
                fontWeight: 700,
                letterSpacing: "0.08em",
            }}
        >
          {label}
        </span>
            </div>
        </div>
    );
}

type RepValue = string | null | undefined;

const repMap: Record<
    string,
    { color: string; label: string; icon: any }
> = {
    Trusted: {
        color: "#22c55e",
        label: "Надійний",
        icon: CheckCircle,
    },
    Suspicious: {
        color: "#eab308",
        label: "Підозрілий",
        icon: AlertTriangle,
    },
    Malicious: {
        color: "#ef4444",
        label: "Шкідливий",
        icon: XCircle,
    },
    Neutral: {
        color: "#60a5fa",
        label: "Нейтральний",
        icon: Shield,
    },
};

function normalize(rep: RepValue): string {
    if (!rep) return "Neutral";

    return rep
        .toString()
        .trim()
        .toLowerCase()
        .replace(/^./, (c) => c.toUpperCase());
}

export function ReputationBadge({ rep }: { rep: RepValue }) {
    const safeRep = normalize(rep);

    const data = repMap[safeRep] ?? repMap["Neutral"];

    const Icon = data.icon;

    return (
        <div className="flex items-center gap-1.5">
            <Icon className="w-4 h-4" style={{ color: data.color }} />
            <span
                style={{
                    color: data.color,
                    fontFamily: "var(--font-mono)",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                }}
            >
                {data.label}
            </span>
        </div>
    );
}

export function EmailDetail({ emailId, onBack }: EmailDetailProps) {
    const [email, setEmail] = useState<EmailDetailData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        fetchEmailDetail(emailId)
            .then((data) => {
                setEmail(data);
                setLoading(false);
            })
            .catch((err: { detail?: string }) => {
                setError(err?.detail ?? "Не вдалося завантажити лист");
                setLoading(false);
            });
    }, [emailId]);

    useEffect(() => {
        if (!email || email.analysis_status === "done" || email.analysis_status === "failed") {
            return;
        }
        const timer = window.setInterval(() => {
            fetchEmailDetail(emailId)
                .then((data) => {
                    setEmail(data);
                    if (data.analysis_status === "done" || data.analysis_status === "failed") {
                        window.clearInterval(timer);
                    }
                })
                .catch(() => {});
        }, 3000);
        return () => window.clearInterval(timer);
    }, [emailId, email?.analysis_status]);

    const aiBarColor = (v: number) => {
        if (v >= 70) return "#ef4444";
        if (v >= 40) return "#eab308";
        return "#22c55e";
    };

    if (loading) {
        return (
            <div
                className="min-h-screen flex items-center justify-center"
                style={{ background: "var(--background)" }}
            >
                <style>{`@keyframes spin { to { transform: rotate(360deg); } } .spinner { animation: spin 0.8s linear infinite; }`}</style>
                <div
                    className="spinner w-6 h-6 rounded-full"
                    style={{ border: "2px solid rgba(59,130,246,0.15)", borderTopColor: "#3b82f6" }}
                />
            </div>
        );
    }

    if (error || !email) {
        return (
            <div
                className="min-h-screen flex items-center justify-center"
                style={{ background: "var(--background)" }}
            >
                <div className="text-center">
                    <p style={{ color: "#ef4444", marginBottom: 12 }}>{error ?? "Лист не знайдено"}</p>
                    <button
                        onClick={onBack}
                        style={{ color: "#3b82f6", background: "none", border: "none", cursor: "pointer" }}
                    >
                        ← Назад до панелі
                    </button>
                </div>
            </div>
        );
    }

    // Прибираємо явний тип JSX.Element, дозволяємо TypeScript вивести тип автоматично (any)
    const riskIconMap: Record<RiskLevel, any> = {
        Critical: <XCircle className="w-5 h-5" style={{ color: "#ef4444" }} />,
        High: <AlertTriangle className="w-5 h-5" style={{ color: "#f97316" }} />,
        Medium: <AlertTriangle className="w-5 h-5" style={{ color: "#eab308" }} />,
        Safe: <CheckCircle className="w-5 h-5" style={{ color: "#22c55e" }} />,
    };
    const hasAiVerdict = email.analysis_status === "done" && Boolean(email.verdict);
    const aiPending = email.analysis_status !== "done";
    const statusColor = aiPending ? "#60a5fa" : riskColors[email.riskLevel];
    const statusBg = aiPending ? "rgba(59,130,246,0.12)" : riskBgColors[email.riskLevel];
    const recommendationItems = hasAiVerdict && email.recommendations?.length
        ? email.recommendations
        : aiPending
          ? ["AI ще аналізує лист. Рекомендації зʼявляться після завершення аналізу."]
          : [];

    return (
        <div
            className="min-h-screen"
            style={{ background: "var(--background)", fontFamily: "var(--font-sans)" }}
        >
            {/* Header */}
            <header
                className="sticky top-0 z-20 flex items-center gap-4 px-6 h-14"
                style={{
                    background: "rgba(8,12,20,0.9)",
                    borderBottom: "1px solid var(--border)",
                    backdropFilter: "blur(12px)",
                }}
            >
                <button
                    onClick={onBack}
                    className="flex items-center gap-2 transition-opacity hover:opacity-80"
                    style={{
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        color: "var(--muted-foreground)",
                        fontSize: "0.875rem",
                    }}
                >
                    <ArrowLeft className="w-4 h-4" />
                    Назад до панелі
                </button>
                <div className="w-px h-5" style={{ background: "var(--border)" }} />
                <div className="flex items-center gap-2 min-w-0">
                    {aiPending ? <Clock className="w-5 h-5" style={{ color: statusColor }} /> : riskIconMap[email.riskLevel]}
                    <span
                        className="truncate"
                        style={{ color: "var(--foreground)", fontSize: "0.9rem", fontWeight: 600 }}
                    >
            {email.subject}
          </span>
                </div>
            </header>

            <main className="max-w-5xl mx-auto px-6 py-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left column */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Email meta */}
                    <div
                        className="rounded-xl p-6"
                        style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                    >
                        <div className="flex items-start justify-between gap-4 mb-5">
                            <div>
                                <h2
                                    className="mb-1"
                                    style={{ color: "var(--foreground)", fontWeight: 600, fontSize: "1.0625rem" }}
                                >
                                    {email.subject}
                                </h2>
                                <div className="flex flex-wrap gap-x-4 gap-y-1">
                  <span style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem" }}>
                    Від:{" "}
                      <span
                          style={{
                              color: "var(--foreground)",
                              fontFamily: "var(--font-mono)",
                              fontSize: "0.8rem",
                              overflowWrap: "anywhere",
                              wordBreak: "break-word",
                          }}
                      >
                      {email.sender}
                    </span>
                  </span>
                                    <span style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem" }}>
                    {new Date(email.date).toLocaleString("uk-UA", {
                        day: "2-digit",
                        month: "short",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                    })}
                  </span>
                                </div>
                            </div>
                        </div>
                        <div
                            className="rounded-lg p-4"
                            style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
                        >
                            <p
                                style={{
                                    color: "var(--foreground)",
                                    fontSize: "0.875rem",
                                    lineHeight: 1.7,
                                    whiteSpace: "pre-wrap",
                                    overflowWrap: "anywhere",
                                    wordBreak: "break-word",
                                    maxWidth: "100%",
                                }}
                            >
                                {email.body}
                            </p>
                        </div>
                    </div>

                    <SpamActionBanner email={email} />

                    {/* Аналіз домену */}
                    <div
                        className="rounded-xl p-6"
                        style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                    >
                        <div className="flex items-center gap-2 mb-5">
                            <Globe className="w-4 h-4" style={{ color: "#3b82f6" }} />
                            <h3 style={{ color: "var(--foreground)", fontWeight: 600 }}>
                                Аналіз домену відправника
                            </h3>
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            {[
                                {
                                    label: "ДОМЕН",
                                    content: (
                                        <div className="flex items-center gap-2">
                                            <Copy className="w-3.5 h-3.5" style={{ color: "var(--muted-foreground)" }} />
                                            <span
                                                style={{
                                                    color: "var(--foreground)",
                                                    fontFamily: "var(--font-mono)",
                                                    fontSize: "0.85rem",
                                                    fontWeight: 600,
                                                }}
                                            >
                        {email.domain}
                      </span>
                                        </div>
                                    ),
                                },
                                {
                                    label: "ВІК ДОМЕНУ",
                                    content: (
                                        <div className="flex items-center gap-2">
                                            <Clock
                                                className="w-3.5 h-3.5"
                                                style={{ color: "var(--muted-foreground)" }}
                                            />
                                            <span
                                                style={{
                                                    color:
                                                        email.domainAge.indexOf("days") !== -1 || email.domainAge.indexOf("day") !== -1
                                                            ? "#ef4444"
                                                            : "var(--foreground)",
                                                    fontFamily: "var(--font-mono)",
                                                    fontSize: "0.85rem",
                                                    fontWeight: 600,
                                                }}
                                            >
                        {email.domainAge}
                      </span>
                                        </div>
                                    ),
                                },
                                {
                                    label: "РЕПУТАЦІЯ",
                                    content: <ReputationBadge rep={email.domainReputation} />,
                                },
                                {
                                    label: "СХОЖИЙ НА",
                                    content: email.lookalikeDomain ? (
                                        <div className="flex items-center gap-2">
                                            <Link2 className="w-3.5 h-3.5" style={{ color: "#ef4444" }} />
                                            <span
                                                style={{
                                                    color: "#ef4444",
                                                    fontFamily: "var(--font-mono)",
                                                    fontSize: "0.85rem",
                                                    fontWeight: 600,
                                                }}
                                            >
                        {email.lookalikeDomain}
                      </span>
                                        </div>
                                    ) : (
                                        <span
                                            style={{
                                                color: "#22c55e",
                                                fontFamily: "var(--font-mono)",
                                                fontSize: "0.85rem",
                                                fontWeight: 600,
                                            }}
                                        >
                      Не виявлено
                    </span>
                                    ),
                                },
                            ].map(({ label, content }) => (
                                <div
                                    key={label}
                                    className="rounded-lg p-4"
                                    style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
                                >
                                    <p
                                        style={{
                                            color: "var(--muted-foreground)",
                                            fontSize: "0.7rem",
                                            fontFamily: "var(--font-mono)",
                                            letterSpacing: "0.08em",
                                            marginBottom: 6,
                                        }}
                                    >
                                        {label}
                                    </p>
                                    {content}
                                </div>
                            ))}
                        </div>
                    </div>

                    <UrlScanSection email={email} />
                    <AttachmentScanSection email={email} />

                    {/* AI Analysis */}
                    <div
                        className="rounded-xl p-6"
                        style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                    >
                        <div className="flex items-center gap-2 mb-5">
                            <Shield className="w-4 h-4" style={{ color: "#3b82f6" }} />
                            <h3 style={{ color: "var(--foreground)", fontWeight: 600 }}>
                                Аналіз листа
                                <span
                                    className="ml-2"
                                    style={{
                                        fontFamily: "var(--font-mono)",
                                        fontSize: "0.65rem",
                                        color: "var(--muted-foreground)",
                                        letterSpacing: "0.06em",
                                    }}
                                >
                  {hasAiVerdict ? "AI-аналіз" : (email.analysisSource ?? "очікує AI")}
                </span>
                            </h3>
                        </div>
                        <div className="space-y-4 mb-6">
                            {[
                                { label: "Urgency", value: email.urgency },
                                { label: "Pressure / Threats", value: email.fear },
                                { label: "Credential Theft", value: email.credentialTheft },
                                { label: "Financial Fraud", value: email.financialFraud },
                                { label: "Authority Impersonation", value: email.authorityImpersonation },
                            ].map(({ label, value }) => (
                                <ScoreBar key={label} label={label} value={value} color={aiBarColor(value)} />
                            ))}
                        </div>
                        <div
                            className="rounded-lg p-4"
                            style={{
                                background: statusBg,
                                border: `1px solid ${statusColor}33`,
                            }}
                        >
                            <p
                                className="mb-1.5"
                                style={{
                                    color: "var(--muted-foreground)",
                                    fontSize: "0.7rem",
                                    fontFamily: "var(--font-mono)",
                                    letterSpacing: "0.08em",
                                }}
                            >
                                ВЕРДИКТ АНАЛІЗУ
                            </p>
                            {email.analysisNotice && (
                                <p style={{ color: "var(--muted-foreground)", fontSize: "0.75rem", marginBottom: 8 }}>
                                    {email.analysisNotice}
                                </p>
                            )}
                            <p style={{ color: "var(--foreground)", fontSize: "0.875rem", lineHeight: 1.65 }}>
                                {hasAiVerdict ? email.verdict : "AI-аналізує лист. Фінальний вердикт ще не готовий."}
                            </p>
                        </div>

                    </div>
                </div>

                {/* Right column */}
                <div className="space-y-6">
                    {/* Рейтинг загрози */}
                    <div
                        className="rounded-xl p-6 flex flex-col items-center"
                        style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                    >
                        <p
                            className="mb-5"
                            style={{
                                color: "var(--muted-foreground)",
                                fontSize: "0.7rem",
                                fontFamily: "var(--font-mono)",
                                letterSpacing: "0.1em",
                                fontWeight: 600,
                            }}
                        >
                            РЕЙТИНГ ЗАГРОЗИ
                        </p>
                        <RiskMeter score={email.threatScore} level={email.riskLevel} pending={aiPending} />
                        <div className="w-full mt-6 space-y-2.5">
                            {[
                                { label: "Оцінка ШІ", value: email.aiScore, weight: "70%" },
                                { label: "Оцінка домену", value: email.domainScore, weight: "30%" },
                                { label: "URL / репутація", value: email.urlScore ?? 0, weight: "signal" },
                                { label: "Вкладення", value: email.attachmentScore ?? 0, weight: "signal" },
                            ].map(({ label, value, weight }) => (
                                <div key={label} className="flex items-center justify-between">
                                    <div>
                    <span style={{ color: "var(--muted-foreground)", fontSize: "0.8rem" }}>
                      {label}
                    </span>
                                        <span
                                            className="ml-1.5"
                                            style={{
                                                color: "var(--muted-foreground)",
                                                fontFamily: "var(--font-mono)",
                                                fontSize: "0.65rem",
                                                opacity: 0.6,
                                            }}
                                        >
                      ({weight})
                    </span>
                                    </div>
                                    <span
                                        style={{
                                            color: "var(--foreground)",
                                            fontFamily: "var(--font-mono)",
                                            fontSize: "0.875rem",
                                            fontWeight: 700,
                                        }}
                                    >
                    {value}
                  </span>
                                </div>
                            ))}
                            <div className="h-px w-full my-1" style={{ background: "var(--border)" }} />
                            <div className="flex items-center justify-between">
                <span style={{ color: "var(--foreground)", fontSize: "0.8rem", fontWeight: 600 }}>
                  Фінальна оцінка
                </span>
                                <span
                                    style={{
                                        color: statusColor,
                                        fontFamily: "var(--font-mono)",
                                        fontSize: "1rem",
                                        fontWeight: 700,
                                    }}
                                >
                  {aiPending ? "AI" : email.threatScore}
                </span>
                            </div>
                        </div>
                    </div>

                    {/* Рекомендації */}
                    <div
                        className="rounded-xl p-6"
                        style={{ background: "var(--card)", border: "1px solid var(--border)" }}
                    >
                        <h3
                            className="mb-4"
                            style={{ color: "var(--foreground)", fontWeight: 600, fontSize: "0.9375rem" }}
                        >
                            Рекомендації
                        </h3>
                        <div className="space-y-3">
                            {recommendationItems.length ? recommendationItems.map((r) => {
                                const safe = email.riskLevel === "Safe" && !aiPending;
                                return (
                                    <div key={r} className="flex items-center gap-2.5">
                                        {aiPending ? (
                                            <Clock className="w-4 h-4 flex-shrink-0" style={{ color: statusColor }} />
                                        ) : safe ? (
                                            <CheckCircle className="w-4 h-4 flex-shrink-0" style={{ color: "#22c55e" }} />
                                        ) : (
                                            <AlertTriangle
                                                className="w-4 h-4 flex-shrink-0"
                                                style={{
                                                    color:
                                                        email.riskLevel === "Critical"
                                                            ? "#ef4444"
                                                            : email.riskLevel === "High"
                                                              ? "#f97316"
                                                              : "#eab308",
                                                }}
                                            />
                                        )}
                                        <span style={{ color: "var(--foreground)", fontSize: "0.8125rem", overflowWrap: "anywhere", wordBreak: "break-word", minWidth: 0 }}>
                                            {recommendationLabels[r] ?? r}
                                        </span>
                                    </div>
                                );
                            }) : (
                                <p style={{ color: "var(--muted-foreground)", fontSize: "0.8125rem", lineHeight: 1.5 }}>
                                    Рекомендації недоступні для цього аналізу.
                                </p>
                            )}
                        </div>
                    </div>

                    {/* VirusTotal link */}
                    {email.riskLevel !== "Safe" && (
                        <a
                            href={`https://www.virustotal.com/gui/domain/${email.domain}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center justify-center gap-2 w-full py-2.5 rounded-xl transition-opacity hover:opacity-80"
                            style={{
                                background: "var(--secondary)",
                                border: "1px solid var(--border)",
                                color: "var(--muted-foreground)",
                                fontSize: "0.8125rem",
                                textDecoration: "none",
                            }}
                        >
                            <ExternalLink className="w-3.5 h-3.5" />
                            Перевірити на VirusTotal
                        </a>
                    )}
                </div>
            </main>
        </div>
    );
}


