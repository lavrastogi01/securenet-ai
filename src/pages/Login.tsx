import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { Shield, Lock, User, AlertCircle } from "lucide-react";

const Login = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!username.trim() || !password.trim()) {
      setError("Please fill in all fields");
      return;
    }
    setLoading(true);
    const success = await login(username.trim(), password);
    setLoading(false);
    if (success) {
      navigate("/dashboard", { replace: true });
    } else {
      setError("Invalid credentials. Try admin / 1234");
    }
  };

  const orbitFeatures = [
    "Traffic Analysis",
    "Upload & Detect",
    "Threat Logs",
    "AI Model Security",
    "Adversarial Detection",
    "Model Integrity",
    "Settings",
  ];

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4 overflow-hidden relative">
      {/* Ambient background glow */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full bg-primary/5 blur-3xl" />
      </div>

      {/* Orbit rings (behind login card) */}
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <div className="relative w-[600px] h-[600px] max-w-[95vw] max-h-[95vw]">
          {/* Outer ring with feature labels */}
          <div className="absolute inset-0 rounded-full border border-primary/20 cyber-glow animate-spin-slow">
            {orbitFeatures.map((label, i) => {
              const angle = (i / orbitFeatures.length) * 360;
              return (
                <div
                  key={label}
                  className="absolute top-1/2 left-1/2"
                  style={{ transform: `rotate(${angle}deg) translateY(-300px)` }}
                >
                  <div
                    className="px-2.5 py-1 -translate-x-1/2 rounded-full bg-card/80 backdrop-blur cyber-border text-[10px] font-mono uppercase tracking-wider text-primary whitespace-nowrap"
                    style={{ transform: `translateX(-50%) rotate(-${angle}deg)` }}
                  >
                    {label}
                  </div>
                </div>
              );
            })}
          </div>
          {/* Middle ring */}
          <div className="absolute inset-12 rounded-full border border-primary/15 animate-spin-reverse" />
          {/* Inner pulsing ring */}
          <div className="absolute inset-24 rounded-full border border-primary/30 animate-pulse-glow" />
          {/* Sweeping radar arc */}
          <div className="absolute inset-0 rounded-full overflow-hidden animate-radar-sweep" style={{ background: "conic-gradient(from 0deg, transparent 0deg, hsl(var(--primary) / 0.15) 30deg, transparent 60deg)" }} />
        </div>
      </div>

      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-primary/15 cyber-border flex items-center justify-center mb-4">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-2xl font-bold text-foreground">SecureNet AI</h1>
          <p className="text-sm text-muted-foreground mt-1">AI-Powered Intrusion Detection System</p>
        </div>

        {/* Login Card */}
        <div className="section-card">
          <h2 className="text-lg font-semibold text-foreground mb-1">Sign In</h2>
          <p className="text-xs text-muted-foreground mb-6">Enter your credentials to access the dashboard</p>

          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/20 mb-4">
              <AlertCircle className="w-4 h-4 text-destructive shrink-0" />
              <p className="text-xs text-destructive">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5 block">Username</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter username"
                  className="w-full h-10 pl-10 pr-3 rounded-lg bg-secondary border border-border text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
                  maxLength={50}
                  autoComplete="username"
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5 block">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="w-full h-10 pl-10 pr-3 rounded-lg bg-secondary border border-border text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
                  maxLength={100}
                  autoComplete="current-password"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full h-10 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {loading ? "Authenticating..." : "Sign In"}
            </button>
          </form>

          <p className="text-xs text-muted-foreground text-center mt-4">
            Demo: <span className="text-primary font-mono">admin</span> / <span className="text-primary font-mono">1234</span>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
