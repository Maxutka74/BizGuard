/**
 * src/api/auth.ts
 *
 * Authentication endpoints:
 *   GET  /api/accounts/google/url       → get Google OAuth consent URL
 *   POST /api/accounts/google/callback  → exchange code for JWT tokens
 *   GET  /api/accounts/me               → fetch current user profile
 *   POST /api/accounts/logout           → blacklist refresh token
 */

import { api, tokenStorage } from "./client";

export interface User {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
  picture?: string;
}

// ── Get the Google OAuth URL to redirect user to ─────────────────────────────

export async function getGoogleAuthUrl(): Promise<string> {
  const redirectUri = `${window.location.origin}/auth/callback`;
  const data = await api.get<{ url: string }>(
    `/accounts/google/url?redirect_uri=${encodeURIComponent(redirectUri)}`
  );
  return data.url;
}

// ── Exchange OAuth code → JWT tokens ─────────────────────────────────────────

export interface AuthResult {
  access: string;
  refresh: string;
  user: User;
}

export async function exchangeGoogleCode(code: string): Promise<AuthResult> {
  const redirectUri = `${window.location.origin}/auth/callback`;
  const data = await fetch("/api/accounts/google/callback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, redirect_uri: redirectUri }),
  });

  if (!data.ok) {
    const err = await data.json().catch(() => ({ detail: "Auth failed" }));
    throw err;
  }

  const result: AuthResult = await data.json();
  tokenStorage.set(result.access, result.refresh);
  return result;
}

// ── Fetch current user (also used to check if session is valid) ───────────────

export async function fetchMe(): Promise<User> {
  return api.get<User>("/accounts/me");
}

// ── Logout ────────────────────────────────────────────────────────────────────

export async function logout(): Promise<void> {
  const refresh = tokenStorage.getRefresh();
  try {
    if (refresh) {
      await api.post("/accounts/logout", { refresh });
    }
  } finally {
    tokenStorage.clear();
  }
}
