import { api, tokenStorage } from "./client";
import { licenseGateStorage, type LicenseStatus } from "./licenses";

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  picture?: string;
  license?: LicenseStatus;
}

export async function getGoogleAuthUrl(): Promise<string> {
  const redirectUri = `${window.location.origin}/auth/callback`;
  const state = createOAuthState();
  storeGoogleOAuthState(state);
  const data = await api.get<{ url: string }>(
    `/accounts/google/url?redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`
  );
  return data.url;
}

export interface AuthResult {
  user: User;
}

export async function exchangeGoogleCode(code: string): Promise<AuthResult> {
  const redirectUri = `${window.location.origin}/auth/callback`;
  const result = await api.post<AuthResult>("/accounts/google/callback", {
    code,
    redirect_uri: redirectUri,
  });
  tokenStorage.clear();
  licenseGateStorage.clear();
  return result;
}

export function verifyGoogleOAuthState(state: string | null): boolean {
  const expected = readGoogleOAuthState();
  return Boolean(expected && state && expected === state);
}

export function clearGoogleOAuthState(): void {
  sessionStorage.removeItem("google_oauth_state");
  localStorage.removeItem("google_oauth_state");
}

function createOAuthState(): string {
  if ("randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function storeGoogleOAuthState(state: string): void {
  const record = JSON.stringify({ state, expiresAt: Date.now() + 10 * 60 * 1000 });
  sessionStorage.setItem("google_oauth_state", state);
  localStorage.setItem("google_oauth_state", record);
}

function readGoogleOAuthState(): string | null {
  const sessionValue = sessionStorage.getItem("google_oauth_state");
  if (sessionValue) return sessionValue;

  const raw = localStorage.getItem("google_oauth_state");
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { state?: string; expiresAt?: number };
    if (!parsed.state || !parsed.expiresAt || parsed.expiresAt < Date.now()) {
      clearGoogleOAuthState();
      return null;
    }
    return parsed.state;
  } catch {
    clearGoogleOAuthState();
    return null;
  }
}

export async function fetchMe(): Promise<User> {
  return api.get<User>("/accounts/me");
}

export async function logout(): Promise<void> {
  try {
    await api.post("/accounts/logout");
  } finally {
    tokenStorage.clear();
    licenseGateStorage.clear();
  }
}
