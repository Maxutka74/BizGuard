import { Shield, Mail, Lock, Eye, AlertCircle } from "lucide-react";

interface LoginPageProps {
  onLogin: () => void;
  errorMessage?: string;
}

export function LoginPage({ onLogin, errorMessage }: LoginPageProps) {
  return (
    <div
      className="min-h-screen flex items-center justify-center relative overflow-hidden"
      style={{ background: "var(--background)" }}
    >
      {/* Grid background */}
      <div
        className="absolute inset-0 opacity-20"
        style={{
          backgroundImage:
            "linear-gradient(rgba(59,130,246,0.15) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.15) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      {/* Radial glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 60% 50% at 50% 50%, rgba(59,130,246,0.06) 0%, transparent 70%)",
        }}
      />

      <div className="relative z-10 w-full max-w-md px-6">
        {/* Logo */}
        <div className="flex flex-col items-center mb-10">
          <div
            className="w-16 h-16 rounded-2xl flex items-center justify-center mb-4"
            style={{
              background: "linear-gradient(135deg, #1e3a6e 0%, #0d1f40 100%)",
              border: "1px solid rgba(59,130,246,0.4)",
              boxShadow: "0 0 32px rgba(59,130,246,0.2)",
            }}
          >
            <Shield className="w-8 h-8" style={{ color: "#3b82f6" }} />
          </div>
          <h1
            className="tracking-tight"
            style={{
              color: "var(--foreground)",
              fontFamily: "var(--font-sans)",
              fontSize: "1.75rem",
              fontWeight: 700,
            }}
          >
            BizGuard
          </h1>
          <p
            className="mt-1"
            style={{
              color: "var(--muted-foreground)",
              fontFamily: "var(--font-mono)",
              fontSize: "0.75rem",
              letterSpacing: "0.1em",
            }}
          >
            EMAIL THREAT INTELLIGENCE
          </p>
        </div>

        {/* Card */}
        <div
          className="rounded-xl p-8"
          style={{
            background: "var(--card)",
            border: "1px solid var(--border)",
            boxShadow: "0 8px 48px rgba(0,0,0,0.4)",
          }}
        >
          <h2 className="mb-2" style={{ color: "var(--foreground)", fontWeight: 600 }}>
            Sign in to continue
          </h2>
          <p className="mb-8" style={{ color: "var(--muted-foreground)", fontSize: "0.875rem" }}>
            Connect your Gmail account to scan for phishing threats
          </p>

          {/* Error message */}
          {errorMessage && (
            <div
              className="flex items-center gap-2 rounded-lg px-4 py-3 mb-6"
              style={{
                background: "rgba(239,68,68,0.1)",
                border: "1px solid rgba(239,68,68,0.3)",
              }}
            >
              <AlertCircle className="w-4 h-4 flex-shrink-0" style={{ color: "#ef4444" }} />
              <span style={{ color: "#ef4444", fontSize: "0.875rem" }}>{errorMessage}</span>
            </div>
          )}

          {/* Feature list */}
          <div className="space-y-3 mb-8">
            {[
              { icon: Mail, text: "Scan your last 50 emails automatically" },
              { icon: Eye, text: "AI-powered phishing detection" },
              { icon: Lock, text: "Domain reputation & lookalike analysis" },
            ].map(({ icon: Icon, text }) => (
              <div key={text} className="flex items-center gap-3">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ background: "var(--accent)", border: "1px solid var(--border)" }}
                >
                  <Icon className="w-4 h-4" style={{ color: "#3b82f6" }} />
                </div>
                <span style={{ color: "var(--muted-foreground)", fontSize: "0.875rem" }}>
                  {text}
                </span>
              </div>
            ))}
          </div>

          {/* Google Login Button */}
          <button
            onClick={onLogin}
            className="w-full flex items-center justify-center gap-3 rounded-lg py-3 px-4 transition-all duration-200 hover:opacity-90 active:scale-[0.98]"
            style={{
              background: "#ffffff",
              color: "#1f2937",
              fontWeight: 600,
              fontSize: "0.9375rem",
              border: "none",
              cursor: "pointer",
            }}
          >
            {/* Google SVG */}
            <svg width="20" height="20" viewBox="0 0 24 24">
              <path
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                fill="#4285F4"
              />
              <path
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                fill="#34A853"
              />
              <path
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                fill="#FBBC05"
              />
              <path
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                fill="#EA4335"
              />
            </svg>
            Continue with Google
          </button>

          <p
            className="mt-5 text-center"
            style={{ color: "var(--muted-foreground)", fontSize: "0.75rem" }}
          >
            We only request read access to your Gmail. Your data is never stored.
          </p>
        </div>
      </div>
    </div>
  );
}
