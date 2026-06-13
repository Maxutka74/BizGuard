/**
 * src/api/client.ts
 *
 * Base HTTP client for BizGuard Django API.
 * - Reads JWT access token from localStorage
 * - Auto-attaches Authorization header
 * - On 401 → tries to refresh token, retries once
 * - On refresh failure → clears tokens, reloads page (forces re-login)
 */

const BASE_URL = "/api"; // proxied to Django by Vite in dev; same-origin in prod

// ── Token storage ─────────────────────────────────────────────────────────────

export const tokenStorage = {
  getAccess: (): string | null => localStorage.getItem("access_token"),
  getRefresh: (): string | null => localStorage.getItem("refresh_token"),
  set: (access: string, refresh: string) => {
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
  },
  clear: () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
  },
};

// ── Refresh logic ─────────────────────────────────────────────────────────────

let refreshPromise: Promise<string> | null = null;

async function refreshAccessToken(): Promise<string> {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const refresh = tokenStorage.getRefresh();
    if (!refresh) throw new Error("No refresh token");

    const res = await fetch(`${BASE_URL}/accounts/token/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh }),
    });

    if (!res.ok) {
      tokenStorage.clear();
      window.location.reload();
      throw new Error("Refresh failed");
    }

    const data = await res.json();
    // Django SimpleJWT returns { access, refresh } when ROTATE_REFRESH_TOKENS=True
    tokenStorage.set(data.access, data.refresh ?? refresh);
    return data.access as string;
  })().finally(() => {
    refreshPromise = null;
  });

  return refreshPromise;
}

// ── Core fetch wrapper ────────────────────────────────────────────────────────

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  retry = true
): Promise<T> {
  const access = tokenStorage.getAccess();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (access) headers["Authorization"] = `Bearer ${access}`;

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });

  if (res.status === 401 && retry) {
    try {
      const newAccess = await refreshAccessToken();
      headers["Authorization"] = `Bearer ${newAccess}`;
      const retried = await fetch(`${BASE_URL}${path}`, { ...options, headers });
      if (!retried.ok) throw await retried.json();
      return retried.json() as Promise<T>;
    } catch {
      tokenStorage.clear();
      window.location.reload();
      throw new Error("Session expired");
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw err;
  }

  // 204 No Content
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(path: string) => apiFetch<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => apiFetch<T>(path, { method: "DELETE" }),
};
