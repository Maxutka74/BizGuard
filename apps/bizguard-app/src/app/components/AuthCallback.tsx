import { useEffect, useRef, useState } from "react";
import { Shield } from "lucide-react";
import { clearGoogleOAuthState, exchangeGoogleCode, verifyGoogleOAuthState } from "../../api/auth";
import type { User } from "../../api/auth";

interface AuthCallbackProps {
  onSuccess: (user: User) => void;
  onError: () => void;
}

let inFlightCallback: { key: string; promise: Promise<User> } | null = null;

const CALLBACK_PROCESSING_KEY = "google_oauth_callback_processing";
const CALLBACK_SUCCESS_KEY = "google_oauth_callback_success";
const CALLBACK_TIMEOUT_MS = 20000;

function googleErrorMessage(error: string): string {
  if (error === "access_denied") {
    return "Google заблокував вхід, бо додаток BizGuard ще в тестовому режимі або не пройшов перевірку Google. Опублікуйте OAuth app у Google Cloud або тимчасово додайте цей акаунт у Test users.";
  }
  return `Google повернув помилку авторизації: ${error}`;
}

export function AuthCallback({ onSuccess, onError }: AuthCallbackProps) {
  const [status, setStatus] = useState<"loading" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState("");
  const startedRef = useRef(false);
  const onSuccessRef = useRef(onSuccess);

  useEffect(() => {
    onSuccessRef.current = onSuccess;
  }, [onSuccess]);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;

    let mounted = true;
    let fallbackTimer: number | undefined;

    const finishAtHome = (user?: User) => {
      if (user) {
        onSuccessRef.current(user);
      }
      window.history.replaceState({}, document.title, "/");

      fallbackTimer = window.setTimeout(() => {
        if (mounted && window.location.pathname === "/auth/callback") {
          window.location.assign("/");
        }
      }, 1000);
    };

    const showError = (message: string) => {
      sessionStorage.removeItem(CALLBACK_PROCESSING_KEY);
      window.setTimeout(() => {
        if (!mounted) return;
        setErrorMsg(message);
        setStatus("error");
      }, 700);
    };

    const params = new URLSearchParams(window.location.search);
    const hashParams = new URLSearchParams(window.location.hash.replace("#", ""));
    const code = params.get("code") || hashParams.get("code");
    const state = params.get("state") || hashParams.get("state");
    const googleError = params.get("error") || hashParams.get("error");
    const callbackKey = `${code ?? ""}:${state ?? ""}`;

    if (sessionStorage.getItem(CALLBACK_SUCCESS_KEY) === callbackKey) {
      finishAtHome();
      return () => {
        mounted = false;
        if (fallbackTimer) window.clearTimeout(fallbackTimer);
      };
    }

    if (googleError) {
      showError(googleErrorMessage(googleError));
      return () => {
        mounted = false;
        if (fallbackTimer) window.clearTimeout(fallbackTimer);
      };
    }

    if (!code) {
      showError("Google не повернув код авторизації. Спробуйте увійти ще раз.");
      return () => {
        mounted = false;
        if (fallbackTimer) window.clearTimeout(fallbackTimer);
      };
    }

    if (!verifyGoogleOAuthState(state)) {
      showError("Не вдалося перевірити захисний state Google. Спробуйте увійти ще раз.");
      return () => {
        mounted = false;
        if (fallbackTimer) window.clearTimeout(fallbackTimer);
      };
    }

    const activeKey = sessionStorage.getItem(CALLBACK_PROCESSING_KEY);
    sessionStorage.setItem(CALLBACK_PROCESSING_KEY, callbackKey);

    if (!inFlightCallback || inFlightCallback.key !== callbackKey) {
      if (activeKey === callbackKey) {
        showError("Цей Google callback уже оброблявся. Спробуйте увійти ще раз.");
        return () => {
          mounted = false;
          if (fallbackTimer) window.clearTimeout(fallbackTimer);
        };
      }
      inFlightCallback = {
        key: callbackKey,
        promise: withTimeout(exchangeGoogleCode(code), CALLBACK_TIMEOUT_MS).then((result) => result.user),
      };
    }

    inFlightCallback.promise
      .then((user) => {
        sessionStorage.setItem(CALLBACK_SUCCESS_KEY, callbackKey);
        clearGoogleOAuthState();
        sessionStorage.removeItem(CALLBACK_PROCESSING_KEY);
        finishAtHome(user);
      })
      .catch((err) => {
        inFlightCallback = null;
        if (err?.code === "activation_limit_reached") {
          showError("Ліміт активацій ключа вичерпано. Увійдіть тим самим Google акаунтом або попросіть додати чи звільнити місце.");
          return;
        }
        showError(err?.detail ?? "Не вдалося завершити вхід. Спробуйте ще раз.");
      });

    return () => {
      mounted = false;
      if (fallbackTimer) window.clearTimeout(fallbackTimer);
    };
  }, []);

  if (status === "error") {
    return (
      <div className="min-h-screen flex items-center justify-center px-4" style={{ background: "var(--background)" }}>
        <div className="max-w-md w-full p-6 rounded-xl border" style={{ background: "var(--card)", borderColor: "var(--border)" }}>
          <h2 className="mb-3" style={{ color: "var(--foreground)", fontWeight: 700 }}>Помилка входу</h2>
          <p className="mb-5" style={{ color: "var(--muted-foreground)", lineHeight: 1.6 }}>{errorMsg}</p>
          <button
            onClick={onError}
            className="rounded-lg px-4 py-2"
            style={{ background: "var(--primary)", color: "#fff", border: "none", cursor: "pointer" }}
          >
            Назад
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center" style={{ background: "var(--background)", color: "var(--foreground)" }}>
      <Shield />
      <p className="mt-3">Завершуємо вхід...</p>
    </div>
  );
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      reject(new Error("Час обробки входу вичерпано."));
    }, ms);

    promise
      .then(resolve)
      .catch(reject)
      .finally(() => window.clearTimeout(timer));
  });
}