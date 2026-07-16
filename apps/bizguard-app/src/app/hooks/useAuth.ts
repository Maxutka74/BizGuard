import { useState, useEffect, useCallback } from "react";
import { fetchMe, getGoogleAuthUrl, logout, type User } from "../../api/auth";
import { LICENSE_REQUIRED_EVENT, tokenStorage } from "../../api/client";
import {
  activateLicenseKey,
  confirmLicenseKey,
  hasActiveLicense,
  type LicenseStatus,
} from "../../api/licenses";

type AuthState = "loading" | "authenticating" | "authenticated" | "unauthenticated" | "needs_license";

function stateForUser(user: User): AuthState {
  return hasActiveLicense(user.license) ? "authenticated" : "needs_license";
}

function userMessageFromError(err: unknown): string {
  const code = (err as { code?: string })?.code;
  const detail = (err as { detail?: string })?.detail;
  if (code === "expired_license") {
    return "Строк дії цього ключа для вашого email завершився. Купіть новий ключ на сайті покупки.";
  }
  if (code === "activation_limit_reached") {
    return "Ліміт активацій цього ключа вичерпано. Увійдіть email, який уже активував ключ, або купіть більше місць.";
  }
  if (code === "key_already_used") {
    return "Цей ключ уже використовувався для іншої активації. Перевірте email або купіть новий ключ.";
  }
  return detail ?? "Не вдалося обробити ліцензійний ключ.";
}

export function useAuth() {
  const [state, setState] = useState<AuthState>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [licenseError, setLicenseError] = useState<string | null>(null);
  const [authBusy, setAuthBusy] = useState(false);
  const [licenseBusy, setLicenseBusy] = useState(false);

  useEffect(() => {
    if (window.location.pathname === "/auth/callback") {
      setState("authenticating");
      return;
    }

    fetchMe()
      .then((u) => {
        setUser(u);
        setState(stateForUser(u));
      })
      .catch(() => {
        tokenStorage.clear();
        setState("unauthenticated");
      });
  }, []);

  useEffect(() => {
    const handleLicenseRequired = (event: Event) => {
      const { license } = (event as CustomEvent<{ license?: LicenseStatus }>).detail ?? {};
      setUser((current) => (current ? { ...current, license: license ?? current.license } : current));
      setLicenseError(
        license?.status === "confirmation_required"
          ? "Потрібно щомісячне підтвердження ключа. Введіть той самий ліцензійний ключ, щоб продовжити."
          : "Ліцензія відсутня або строк дії завершився. Введіть активний ключ для цього email."
      );
      setState("needs_license");
    };

    window.addEventListener(LICENSE_REQUIRED_EVENT, handleLicenseRequired);
    return () => window.removeEventListener(LICENSE_REQUIRED_EVENT, handleLicenseRequired);
  }, []);

  const handleLogin = useCallback(async () => {
    setAuthBusy(true);
    setError(null);
    setLicenseError(null);
    try {
      const url = await getGoogleAuthUrl();
      window.location.href = url;
    } catch (err: unknown) {
      const msg = (err as { detail?: string })?.detail ?? "Не вдалося почати вхід через Google.";
      setError(msg);
    } finally {
      setAuthBusy(false);
    }
  }, []);

  const handleActivateLicenseKey = useCallback(async (key: string) => {
    setLicenseBusy(true);
    setLicenseError(null);
    try {
      const shouldConfirm = user?.license?.status === "confirmation_required";
      const license = shouldConfirm ? await confirmLicenseKey(key) : await activateLicenseKey(key);
      const refreshed = await fetchMe().catch(() => null);
      if (refreshed) {
        setUser(refreshed);
        setState(stateForUser(refreshed));
      } else {
        setUser((current) => (current ? { ...current, license } : current));
        setState(hasActiveLicense(license) ? "authenticated" : "needs_license");
      }
      return license;
    } catch (err: unknown) {
      const msg = userMessageFromError(err);
      setLicenseError(msg);
      throw err;
    } finally {
      setLicenseBusy(false);
    }
  }, [user?.license?.status]);

  const handleLogout = useCallback(async () => {
    await logout().catch(() => {});
    setUser(null);
    setLicenseError(null);
    setError(null);
    setState("unauthenticated");
  }, []);

  const setAuthenticatedUser = useCallback((u: User) => {
    setUser(u);
    setState(stateForUser(u));
  }, []);

  return {
    state,
    user,
    error,
    licenseError,
    licenseBusy,
    authBusy,
    isLoading: state === "loading" || state === "authenticating",
    isAuthenticated: state === "authenticated",
    handleActivateLicenseKey,
    handleLogin,
    handleLogout,
    setAuthenticatedUser,
  };
}
