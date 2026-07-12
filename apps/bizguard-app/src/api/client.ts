/**
 * Base HTTP client for BizGuard Django API.
 * Auth uses HttpOnly cookies set by the backend. Tokens are not stored in JS.
 */

const BASE_URL = "/api";
const CSRF_ENDPOINT = `${BASE_URL}/accounts/csrf`;
export const LICENSE_REQUIRED_EVENT = "bizguard:license-required";

// Legacy facade kept so old call sites can clear stale localStorage tokens.
export const tokenStorage = {
  getAccess: (): string | null => null,
  getRefresh: (): string | null => null,
  set: (_access: string, _refresh: string) => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
  },
  clear: () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
  },
};

let refreshPromise: Promise<void> | null = null;
let csrfPromise: Promise<string> | null = null;
let csrfToken: string | null = null;

function isUnsafeMethod(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS", "TRACE"].includes(method.toUpperCase());
}

async function getCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  if (csrfPromise) return csrfPromise;

  csrfPromise = fetch(CSRF_ENDPOINT, {
    method: "GET",
    credentials: "include",
    headers: { Accept: "application/json" },
  })
    .then(async (res) => {
      if (!res.ok) throw new Error("Не вдалося отримати CSRF-токен.");
      const data = await res.json();
      csrfToken = data.csrfToken;
      return csrfToken as string;
    })
    .finally(() => {
      csrfPromise = null;
    });

  return csrfPromise;
}

async function refreshAccessToken(): Promise<void> {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const token = await getCsrfToken();
    const res = await fetch(`${BASE_URL}/accounts/token/refresh`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": token,
      },
    });

    if (!res.ok) {
      tokenStorage.clear();
      throw new Error("Не вдалося оновити сесію.");
    }
  })().finally(() => {
    refreshPromise = null;
  });

  return refreshPromise;
}

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  retry = true
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (isUnsafeMethod(method)) {
    headers["X-CSRFToken"] = await getCsrfToken();
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    method,
    headers,
    credentials: "include",
  });

  if (res.status === 401 && retry) {
    try {
      await refreshAccessToken();
    } catch {
      tokenStorage.clear();
      throw new Error("Сесія завершилася. Увійдіть ще раз.");
    }

    const retriedHeaders = { ...headers };
    if (isUnsafeMethod(method)) {
      retriedHeaders["X-CSRFToken"] = await getCsrfToken();
    }
    const retried = await fetch(`${BASE_URL}${path}`, {
      ...options,
      method,
      headers: retriedHeaders,
      credentials: "include",
    });
    if (!retried.ok) {
      const err = await retried.json().catch(() => ({ detail: retried.statusText }));
      notifyLicenseRequired(err);
      throw err;
    }
    if (retried.status === 204) return undefined as T;
    return retried.json() as Promise<T>;
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    notifyLicenseRequired(err);
    throw err;
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(path: string) => apiFetch<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => apiFetch<T>(path, { method: "DELETE" }),
};

function notifyLicenseRequired(err: unknown): void {
  const data = err as { code?: string; license?: unknown };
  if (data?.code !== "license_required") return;
  window.dispatchEvent(
    new CustomEvent(LICENSE_REQUIRED_EVENT, {
      detail: { license: data.license },
    })
  );
}
