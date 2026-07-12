import { useMemo, useState, type FormEvent } from "react";
import { AlertCircle, CheckCircle, KeyRound, LockKeyhole, LogOut, Shield } from "lucide-react";
import type { User } from "../../api/auth";
import type { LicenseStatus } from "../../api/licenses";

interface LicenseGateProps {
  user: User | null;
  onActivate: (key: string) => Promise<LicenseStatus>;
  onLogout: () => void;
  isBusy?: boolean;
  errorMessage?: string;
}

export function LicenseGate({
  user,
  onActivate,
  onLogout,
  isBusy = false,
  errorMessage,
}: LicenseGateProps) {
  const [licenseKey, setLicenseKey] = useState("");
  const [success, setSuccess] = useState(false);

  const currentStatus = user?.license?.status ?? "missing";
  const isConfirmation = currentStatus === "confirmation_required";
  const statusText = useMemo(() => {
    if (currentStatus === "confirmation_required") {
      return "Потрібно щомісячне підтвердження ключа.";
    }
    if (currentStatus === "expired") return "Термін дії ліцензії завершився.";
    if (currentStatus === "revoked") return "Ліцензію відкликано.";
    return "Для доступу потрібен активний ліцензійний ключ.";
  }, [currentStatus]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!licenseKey.trim() || isBusy) return;
    try {
      const license = await onActivate(licenseKey.trim());
      setSuccess(license.status === "active");
    } catch {
      setSuccess(false);
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden" style={{ background: "var(--background)" }}>
      <div className="absolute inset-0 blur-sm scale-[1.02] opacity-55 pointer-events-none">
        <LockedDashboardPreview user={user} />
      </div>
      <div
        className="absolute inset-0"
        style={{
          background:
            "linear-gradient(180deg, rgba(8,12,20,0.78), rgba(8,12,20,0.9)), radial-gradient(circle at 50% 35%, rgba(59,130,246,0.12), transparent 52%)",
        }}
      />

      <div className="relative z-10 min-h-screen flex items-center justify-center px-4 py-10">
        <form
          onSubmit={submit}
          className="w-full max-w-md rounded-xl p-7"
          style={{
            background: "var(--card)",
            border: "1px solid var(--border)",
            boxShadow: "0 20px 70px rgba(0,0,0,0.46)",
          }}
        >
          <div className="flex items-center justify-between gap-3 mb-6">
            <div className="flex items-center gap-3 min-w-0">
              <div
                className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
                style={{
                  background: "rgba(59,130,246,0.12)",
                  border: "1px solid rgba(96,165,250,0.3)",
                }}
              >
                <LockKeyhole className="w-5 h-5" style={{ color: "#60a5fa" }} />
              </div>
              <div className="min-w-0">
                <h2 style={{ color: "var(--foreground)", fontWeight: 700, fontSize: "1.08rem" }}>
                  {isConfirmation ? "Підтвердіть ключ" : "Потрібна ліцензія"}
                </h2>
                <p className="truncate" style={{ color: "var(--muted-foreground)", fontSize: "0.78rem" }}>
                  {user?.email ?? "BizGuard"}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={onLogout}
              className="w-9 h-9 rounded-lg flex items-center justify-center transition-opacity hover:opacity-80"
              style={{
                background: "var(--secondary)",
                border: "1px solid var(--border)",
                color: "var(--muted-foreground)",
                cursor: "pointer",
              }}
              title="Вийти"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>

          <p className="mb-5" style={{ color: "var(--muted-foreground)", fontSize: "0.9rem" }}>
            {statusText}{" "}
            {isConfirmation
              ? "Введіть той самий ключ, який уже активований для цього акаунта."
              : "Введіть новий активний ключ, щоб розблокувати сканування й аналіз."}
          </p>

          {errorMessage && (
            <div
              className="flex items-start gap-2 rounded-lg px-4 py-3 mb-4"
              style={{
                background: "rgba(239,68,68,0.1)",
                border: "1px solid rgba(239,68,68,0.3)",
              }}
            >
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: "#ef4444" }} />
              <span style={{ color: "#fecaca", fontSize: "0.86rem" }}>{errorMessage}</span>
            </div>
          )}

          {success && (
            <div
              className="flex items-start gap-2 rounded-lg px-4 py-3 mb-4"
              style={{
                background: "rgba(34,197,94,0.1)",
                border: "1px solid rgba(34,197,94,0.3)",
              }}
            >
              <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: "#22c55e" }} />
              <span style={{ color: "#bbf7d0", fontSize: "0.86rem" }}>
                {isConfirmation ? "Ключ підтверджено." : "Ліцензію активовано."}
              </span>
            </div>
          )}

          <label className="block mb-2" style={{ color: "var(--muted-foreground)", fontSize: "0.78rem" }}>
            {isConfirmation ? "Поточний ліцензійний ключ" : "Новий ліцензійний ключ"}
          </label>
          <div
            className="flex items-center gap-2 rounded-lg px-3 py-2.5 mb-5"
            style={{ background: "var(--secondary)", border: "1px solid var(--border)" }}
          >
            <KeyRound className="w-4 h-4 flex-shrink-0" style={{ color: "#60a5fa" }} />
            <input
              value={licenseKey}
              onChange={(event) => setLicenseKey(event.target.value)}
              placeholder="BG-XXXX-XXXX-XXXX-XXXX"
              className="bg-transparent outline-none flex-1 min-w-0"
              style={{
                color: "var(--foreground)",
                fontFamily: "var(--font-mono)",
                fontSize: "0.9rem",
              }}
              autoComplete="off"
              spellCheck={false}
            />
          </div>

          <button
            type="submit"
            disabled={!licenseKey.trim() || isBusy}
            className="w-full flex items-center justify-center gap-2 rounded-lg py-3 px-4 transition-all duration-200 hover:opacity-90 active:scale-[0.98]"
            style={{
              background: "var(--primary)",
              color: "#ffffff",
              fontWeight: 650,
              fontSize: "0.9375rem",
              border: "none",
              cursor: !licenseKey.trim() || isBusy ? "not-allowed" : "pointer",
              opacity: !licenseKey.trim() || isBusy ? 0.65 : 1,
            }}
          >
            <KeyRound className="w-4 h-4" />
            {isBusy ? "Перевірка..." : isConfirmation ? "Підтвердити ключ" : "Активувати ліцензію"}
          </button>
        </form>
      </div>
    </div>
  );
}

function LockedDashboardPreview({ user }: { user: User | null }) {
  return (
    <div className="min-h-screen" style={{ background: "var(--background)", fontFamily: "var(--font-sans)" }}>
      <header
        className="flex items-center justify-between px-6 h-14"
        style={{
          background: "rgba(8,12,20,0.9)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div className="flex items-center gap-2.5">
          <Shield className="w-5 h-5" style={{ color: "#60a5fa" }} />
          <span style={{ color: "var(--foreground)", fontWeight: 700 }}>BizGuard</span>
          {user?.email && (
            <span style={{ color: "var(--muted-foreground)", fontFamily: "var(--font-mono)", fontSize: "0.65rem" }}>
              {user.email}
            </span>
          )}
        </div>
      </header>
      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {["Завантажені листи", "AI проаналізовано", "Очікує AI", "Критичні"].map((label) => (
            <div
              key={label}
              className="rounded-xl p-5"
              style={{ background: "var(--card)", border: "1px solid var(--border)" }}
            >
              <p style={{ color: "var(--muted-foreground)", fontSize: "0.8rem" }}>{label}</p>
              <div
                className="mt-4 h-8 rounded"
                style={{ background: "rgba(148,163,184,0.18)", width: label === "Критичні" ? "34%" : "58%" }}
              />
            </div>
          ))}
        </div>
        <div className="rounded-xl p-5" style={{ background: "var(--card)", border: "1px solid var(--border)" }}>
          <div className="h-3 rounded-full" style={{ background: "rgba(59,130,246,0.22)" }} />
          <div className="grid grid-cols-12 gap-4 mt-8">
            {Array.from({ length: 24 }).map((_, index) => (
              <div
                key={index}
                className="col-span-12 md:col-span-6 h-5 rounded"
                style={{ background: "rgba(148,163,184,0.12)" }}
              />
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}