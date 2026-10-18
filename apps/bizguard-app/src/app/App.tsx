/**
 * src/app/App.tsx
 *
 * Root component. Replaces the mock state machine with real auth:
 * - useAuth() checks JWT on mount via /api/accounts/me
 * - /auth/callback route handled by AuthCallback
 * - Dashboard/EmailDetail use live API data
 */

import { useCallback, useState } from "react";
import { LoginPage } from "./components/LoginPage";
import { LicenseGate } from "./components/LicenseGate";
import { Dashboard } from "./components/Dashboard";
import { EmailDetail } from "./components/EmailDetail";
import { AuthCallback } from "./components/AuthCallback";
import { useAuth } from "./hooks/useAuth";

type View = "dashboard" | "detail";

export default function App() {
  const {
    state,
    user,
    error,
    licenseError,
    licenseBusy,
    authBusy,
    handleActivateLicenseKey,
    handleLogin,
    handleLogout,
    setAuthenticatedUser,
  } = useAuth();

  const [view, setView] = useState<View>("dashboard");
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);
  const handleAuthSuccess = useCallback(
    (u: Parameters<typeof setAuthenticatedUser>[0]) => {
      setAuthenticatedUser(u);
    },
    [setAuthenticatedUser]
  );

  // ── Handle /auth/callback from Google OAuth ──────────────────────────────
  const isCallback = window.location.pathname === "/auth/callback";

  if (isCallback) {
    return (
      <AuthCallback
        onSuccess={handleAuthSuccess}
        onError={() => {
          window.history.replaceState({}, document.title, "/");
          window.location.assign("/");
        }}
      />
    );
  }

  // ── Loading splash ────────────────────────────────────────────────────────
  if (state === "loading" || state === "authenticating") {
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

  // ── Unauthenticated → show login ─────────────────────────────────────────
  if (state === "unauthenticated" || state === "needs_google") {
    return (
      <LoginPage
        onLogin={handleLogin}
        isBusy={authBusy}
        errorMessage={error ?? undefined}
        needsGmailAccess={state === "needs_google"}
      />
    );
  }

  if (state === "needs_license") {
    return (
      <LicenseGate
        user={user}
        onActivate={handleActivateLicenseKey}
        onLogout={handleLogout}
        isBusy={licenseBusy}
        errorMessage={licenseError ?? undefined}
      />
    );
  }

  // ── Authenticated ─────────────────────────────────────────────────────────
  return (
    <div className="size-full" style={{ fontFamily: "var(--font-sans)" }}>
      {view === "dashboard" && (
        <Dashboard
          user={user}
          onSelectEmail={(id: string) => {
            setSelectedEmailId(id);
            setView("detail");
          }}
          onLogout={handleLogout}
        />
      )}
      {view === "detail" && selectedEmailId && (
        <EmailDetail
          emailId={selectedEmailId}
          onBack={() => {
            setSelectedEmailId(null);
            setView("dashboard");
          }}
        />
      )}
    </div>
  );
}
