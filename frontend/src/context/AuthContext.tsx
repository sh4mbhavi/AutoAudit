import React, {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  login as apiLogin,
  logout as apiLogout,
  getCurrentUser,
  refreshSession,
} from "../api/client";

export type AuthUser = {
  id?: number | string | null;
  email?: string | null;
  username?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  organization_name?: string | null;
  name?: string | null;
  role?: string | null;
  is_active?: boolean | null;
};

export type AuthContextValue = {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (
    email: string,
    password: string,
    remember?: boolean,
  ) => Promise<AuthUser>;
  completeOAuthLogin: () => Promise<AuthUser>;
  logout: () => Promise<void>;
};
const AuthContext = createContext<AuthContextValue | null>(null);

function clearLegacyStorage() {
  for (const name of ["localStorage", "sessionStorage"] as const) {
    try {
      for (const key of [
        "token",
        "user",
        "autoaudit.oauth.google.callback.params",
      ])
        window[name].removeItem(key);
    } catch {
      /* Cookie auth works when browser storage is unavailable. */
    }
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const sessionGeneration = useRef(0);
  const lastActivity = useRef(Date.now());
  const logoutInFlight = useRef<Promise<void> | null>(null);
  useEffect(() => {
    let cancelled = false;
    const generation = sessionGeneration.current;
    clearLegacyStorage();
    const expired = () => {
      sessionGeneration.current += 1;
      setUser(null);
    };
    window.addEventListener("autoaudit:session-expired", expired);
    getCurrentUser()
      .then((current: AuthUser) => {
        if (!cancelled && generation === sessionGeneration.current)
          setUser(current);
      })
      .catch(() => {
        if (!cancelled && generation === sessionGeneration.current)
          setUser(null);
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
      window.removeEventListener("autoaudit:session-expired", expired);
    };
  }, []);

  useEffect(() => {
    if (!user) return;
    // Only a currently valid session can rotate. The server enforces an absolute
    // lifetime; expired sessions always require the user to sign in again.
    const activity = () => {
      lastActivity.current = Date.now();
    };
    for (const event of ["pointerdown", "keydown", "scroll"])
      window.addEventListener(event, activity, { passive: true });
    const timer = window.setInterval(
      () => {
        if (
          document.visibilityState === "visible" &&
          Date.now() - lastActivity.current < 5 * 60 * 1000
        )
          void refreshSession().catch(() => {});
      },
      5 * 60 * 1000,
    );
    return () => {
      window.clearInterval(timer);
      for (const event of ["pointerdown", "keydown", "scroll"])
        window.removeEventListener(event, activity);
    };
  }, [user]);

  async function completeOAuthLogin(): Promise<AuthUser> {
    const generation = ++sessionGeneration.current;
    const current = (await getCurrentUser()) as AuthUser;
    if (generation === sessionGeneration.current) setUser(current);
    return current;
  }
  async function login(
    email: string,
    password: string,
    _remember?: boolean,
  ): Promise<AuthUser> {
    sessionGeneration.current += 1;
    await apiLogin(email, password);
    return completeOAuthLogin();
  }
  async function logout(): Promise<void> {
    if (logoutInFlight.current) return logoutInFlight.current;
    const pending = apiLogout().then(() => {
      sessionGeneration.current += 1;
      setUser(null);
      clearLegacyStorage();
    });
    logoutInFlight.current = pending;
    try {
      await pending;
    } finally {
      logoutInFlight.current = null;
    }
  }
  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        completeOAuthLogin,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an AuthProvider");
  return context;
}
