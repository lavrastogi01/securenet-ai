import React, { createContext, useContext, useState, useCallback } from "react";

interface AuthContextType {
  isAuthenticated: boolean;
  username: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:5000";

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(() => !!sessionStorage.getItem("auth_token"));
  const [username, setUsername] = useState<string | null>(() => sessionStorage.getItem("auth_user"));

  const login = useCallback(async (user: string, pass: string) => {
    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });
      if (res.ok) {
        const data = await res.json();
        sessionStorage.setItem("auth_token", data.token || "authenticated");
        sessionStorage.setItem("auth_user", user);
        setIsAuthenticated(true);
        setUsername(user);
        return true;
      }
      return false;
    } catch {
      // Fallback for demo when backend is unavailable
      if (user === "admin" && pass === "1234") {
        sessionStorage.setItem("auth_token", "demo-token");
        sessionStorage.setItem("auth_user", user);
        setIsAuthenticated(true);
        setUsername(user);
        return true;
      }
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem("auth_token");
    sessionStorage.removeItem("auth_user");
    setIsAuthenticated(false);
    setUsername(null);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, username, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be inside AuthProvider");
  return ctx;
};
