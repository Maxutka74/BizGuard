import { useState, useEffect, useCallback } from "react";
import { fetchMe, getGoogleAuthUrl, logout, type User } from "../../api/auth";
import { LICENSE_REQUIRED_EVENT, tokenStorage } from "../../api/client";
import {
  activateLicenseKey,
  confirmLicenseKey,
  hasActiveLicense,
  validateLicenseKey,
  type LicenseGateValidation,
  type LicenseStatus,
} from "../../api/licenses";

type AuthState = "loading" | "authenticating" | "authenticated" | "unauthenticated" | "needs_license";

function stateForUser(user: User): AuthState {
  return hasActiveLicense(user.license) ? "authenticated" : "needs_license";
}

export function useAuth() {
  const [state, setState] = useState<AuthState>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [licenseError, setLicenseError] = useState<string | null>(null);
  const [licenseGate, setLicenseGate] = useState<LicenseGateValidation | null>(null);
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
          : "Ліцензія відсутня або прострочена. Введіть активний ключ, щоб продовжити."
      );
      setState("needs_license");
    };

    window.addEventListener(LICENSE_REQUIRED_EVENT, handleLicenseRequired);
    return () => window.removeEventListener(LICENSE_REQUIRED_EVENT, handleLicenseRequired);
  }, []);

  const handleValidateLicenseKey = useCallback(async (key: string) => {
    setLicenseBusy(true);
    setLicenseError(null);
    try {
      const validation = await validateLicenseKey(key);
      setLicenseGate(validation);
      return validation;
    } catch (err: unknown) {
      const msg = (err as { detail?: string })?.detail ?? "Ліцензійний ключ недійсний.";
      setLicenseGate(null);
      setLicenseError(msg);
      throw err;
    } finally {
      setLicenseBusy(false);
    }
  }, []);

  const handleLogin = useCallback(async () => {
    setError(null);
    setLicenseError(null);
    try {
      if (!licenseGate?.gateToken) {
        setLicenseError("Спочатку введіть і перевірте ліцензійний ключ.");
        return;
      }
      const url = await getGoogleAuthUrl(licenseGate.gateToken);
      window.location.href = url;
    } catch (err: unknown) {
      const msg = (err as { detail?: string })?.detail ?? "Не вдалося почати вхід через Google.";
      setError(msg);
    }
  }, [licenseGate]);

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
      const msg = (err as { detail?: string })?.detail ?? "Не вдалося обробити цей ліцензійний ключ.";
      setLicenseError(msg);
      throw err;
    } finally {
      setLicenseBusy(false);
    }
  }, [user?.license?.status]);

  const handleLogout = useCallback(async () => {
    await logout().catch(() => {});
    setUser(null);
    setLicenseGate(null);
    setLicenseError(null);
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
    licenseGate,
    licenseBusy,
    isLoading: state === "loading" || state === "authenticating",
    isAuthenticated: state === "authenticated",
    handleValidateLicenseKey,
    handleActivateLicenseKey,
    handleLogin,
    handleLogout,
    setAuthenticatedUser,
  };
}
