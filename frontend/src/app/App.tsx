/**
 * src/app/App.tsx
 *
 * Root component. Replaces the mock state machine with real auth:
 * - useAuth() checks JWT on mount via /api/accounts/me
 * - /auth/callback route handled by AuthCallback
 * - Dashboard/EmailDetail use live API data
 */

import { useState } from "react";
import { LoginPage } from "./components/LoginPage";
import { Dashboard } from "./components/Dashboard";
import { EmailDetail } from "./components/EmailDetail";
import { AuthCallback } from "./components/AuthCallback";
import { useAuth } from "./hooks/useAuth";
import type { EmailDetail as EmailDetailType } from "../api/gmail";

type View = "dashboard" | "detail";

export default function App() {
  const { state, user, error, handleLogin, handleLogout, setAuthenticatedUser } = useAuth();

  const [view, setView] = useState<View>("dashboard");
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);

  // ── Handle /auth/callback from Google OAuth ──────────────────────────────
  const isCallback = window.location.pathname === "/auth/callback";

  if (isCallback) {
    return (
      <AuthCallback
        onSuccess={(u) => {
          setAuthenticatedUser(u);
          window.history.replaceState({}, "", "/");
        }}
        onError={() => {
          window.history.replaceState({}, "", "/");
        }}
      />
    );
  }

  // ── Loading splash ────────────────────────────────────────────────────────
  if (state === "loading") {
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
  if (state === "unauthenticated") {
    return <LoginPage onLogin={handleLogin} errorMessage={error ?? undefined} />;
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
