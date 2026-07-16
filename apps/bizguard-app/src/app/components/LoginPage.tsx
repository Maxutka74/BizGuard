import { AlertCircle, Mail, Shield } from "lucide-react";

interface LoginPageProps {
  onLogin: () => void;
  isBusy?: boolean;
  errorMessage?: string;
  needsGmailAccess?: boolean;
}

export function LoginPage({ onLogin, isBusy = false, errorMessage, needsGmailAccess = false }: LoginPageProps) {
  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden px-4 py-10" style={{ background: "var(--background)" }}>
      <div
        className="absolute inset-0 opacity-20"
        style={{
          backgroundImage:
            "linear-gradient(rgba(59,130,246,0.16) 1px, transparent 1px), linear-gradient(90deg, rgba(34,197,94,0.1) 1px, transparent 1px)",
          backgroundSize: "42px 42px",
        }}
      />
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 58% 48% at 50% 46%, rgba(59,130,246,0.08) 0%, rgba(34,197,94,0.04) 38%, transparent 72%)",
        }}
      />

      <div className="relative z-10 w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div
            className="w-16 h-16 rounded-2xl flex items-center justify-center mb-4"
            style={{
              background: "linear-gradient(135deg, #1e3a6e 0%, #102a43 60%, #064e3b 100%)",
              border: "1px solid rgba(96,165,250,0.38)",
              boxShadow: "0 0 32px rgba(59,130,246,0.18)",
            }}
          >
            <Shield className="w-8 h-8" style={{ color: "#60a5fa" }} />
          </div>
          <h1 style={{ color: "var(--foreground)", fontSize: "1.75rem", fontWeight: 700 }}>BizGuard</h1>
          <p className="mt-1 text-center" style={{ color: "var(--muted-foreground)", fontFamily: "var(--font-mono)", fontSize: "0.72rem", letterSpacing: "0.08em" }}>
            ЗАХИСТ GMAIL ВІД ФІШИНГУ
          </p>
        </div>

        <div className="rounded-xl p-7" style={{ background: "var(--card)", border: "1px solid var(--border)", boxShadow: "0 8px 48px rgba(0,0,0,0.4)" }}>
          <h2 className="mb-2" style={{ color: "var(--foreground)", fontWeight: 650 }}>
            {needsGmailAccess ? "Надайте доступ до Gmail" : "Увійдіть через Google"}
          </h2>
          <p className="mb-6" style={{ color: "var(--muted-foreground)", fontSize: "0.875rem", lineHeight: 1.6 }}>
            Оберіть Google акаунт із поштою, яку потрібно захищати. Після входу BizGuard попросить ліцензійний ключ, і лише після його активації відкриє аналіз листів.
          </p>

          {errorMessage && (
            <div className="flex items-start gap-2 rounded-lg px-4 py-3 mb-5" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)" }}>
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: "#ef4444" }} />
              <span style={{ color: "#fecaca", fontSize: "0.875rem" }}>{errorMessage}</span>
            </div>
          )}

          <div className="space-y-3 mb-6">
            {[
              "Google-вхід одразу підключає Gmail для перевірки листів",
              "Після входу потрібно ввести придбаний ключ активації",
              "Повторний вхід з того самого email не списує нове місце",
            ].map((text) => (
              <div key={text} className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: "var(--accent)", border: "1px solid var(--border)" }}>
                  <Mail className="w-4 h-4" style={{ color: "#60a5fa" }} />
                </div>
                <span style={{ color: "var(--muted-foreground)", fontSize: "0.875rem" }}>{text}</span>
              </div>
            ))}
          </div>

          <button
            type="button"
            onClick={onLogin}
            disabled={isBusy}
            className="w-full flex items-center justify-center gap-2 rounded-lg py-3 px-4 transition-all duration-200 hover:opacity-90 active:scale-[0.98]"
            style={{
              background: "#ffffff",
              color: "#1f2937",
              fontWeight: 650,
              fontSize: "0.9375rem",
              border: "none",
              cursor: isBusy ? "not-allowed" : "pointer",
              opacity: isBusy ? 0.65 : 1,
            }}
          >
            <GoogleIcon />
            {isBusy ? "Відкриваємо Google..." : "Увійти через Google"}
          </button>
        </div>
      </div>
    </div>
  );
}

function GoogleIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
    </svg>
  );
}
