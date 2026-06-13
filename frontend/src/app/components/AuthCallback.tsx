import { useEffect, useState } from "react";
import { Shield } from "lucide-react";
import { exchangeGoogleCode } from "../../api/auth";
import type { User } from "../../api/auth";

interface AuthCallbackProps {
  onSuccess: (user: User) => void;
  onError: () => void;
}

export function AuthCallback({ onSuccess, onError }: AuthCallbackProps) {
  const [status, setStatus] = useState<"loading" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const hashParams = new URLSearchParams(window.location.hash.replace("#", ""));

    const code = params.get("code") || hashParams.get("code");
    const error = params.get("error");

    if (error) {
      setErrorMsg(`Google error: ${error}`);
      setStatus("error");
      return;
    }

    if (!code) {
      setErrorMsg("No authorization code received from Google.");
      setStatus("error");
      return;
    }

    exchangeGoogleCode(code)
        .then((result) => {
          window.history.replaceState({}, document.title, "/");
          onSuccess(result.user);
        })
        .catch((err) => {
          setErrorMsg(err?.detail ?? "Authentication failed");
          setStatus("error");
        });
  }, [onSuccess]);

  if (status === "error") {
    return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="p-6 rounded-xl border">
            <h2>Login failed</h2>
            <p>{errorMsg}</p>
            <button onClick={onError}>Back</button>
          </div>
        </div>
    );
  }

  return (
      <div className="min-h-screen flex flex-col items-center justify-center">
        <Shield />
        <p>Completing login…</p>
      </div>
  );
}