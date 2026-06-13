/**
 * src/app/hooks/useAuth.ts
 *
 * Manages authentication state for BizGuard.
 *
 * Flow:
 *  1. On mount → call /api/accounts/me
 *     - Success: user is logged in → show Dashboard
 *     - 401: not logged in → show LoginPage
 *  2. handleLogin() → redirect user to Google consent screen
 *  3. After Google redirects to /auth/callback?code=...
 *     → AuthCallback component exchanges code → sets JWT → redirects home
 *  4. handleLogout() → blacklists token, clears storage, shows LoginPage
 */

import { useState, useEffect, useCallback } from "react";
import { fetchMe, getGoogleAuthUrl, logout, type User } from "../../api/auth";
import { tokenStorage } from "../../api/client";

type AuthState = "loading" | "authenticated" | "unauthenticated";

export function useAuth() {
  const [state, setState] = useState<AuthState>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);

  // ── Check existing session on mount ────────────────────────────────────────

  useEffect(() => {
    const access = tokenStorage.getAccess();
    if (!access) {
      setState("unauthenticated");
      return;
    }

    fetchMe()
      .then((u) => {
        setUser(u);
        setState("authenticated");
      })
      .catch(() => {
        tokenStorage.clear();
        setState("unauthenticated");
      });
  }, []);

  // ── Start Google OAuth flow ────────────────────────────────────────────────

  const handleLogin = useCallback(async () => {
    setError(null);
    try {
      const url = await getGoogleAuthUrl();
      window.location.href = url;
    } catch (err: unknown) {
      const msg = (err as { detail?: string })?.detail ?? "Failed to start login";
      setError(msg);
    }
  }, []);

  // ── Logout ─────────────────────────────────────────────────────────────────

  const handleLogout = useCallback(async () => {
    await logout().catch(() => {}); // ignore errors — clear anyway
    setUser(null);
    setState("unauthenticated");
  }, []);

  // ── Called by AuthCallback after exchanging code ──────────────────────────

  const setAuthenticatedUser = useCallback((u: User) => {
    setUser(u);
    setState("authenticated");
  }, []);

  return {
    state,
    user,
    error,
    isLoading: state === "loading",
    isAuthenticated: state === "authenticated",
    handleLogin,
    handleLogout,
    setAuthenticatedUser,
  };
}
