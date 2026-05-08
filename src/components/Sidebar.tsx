import { useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  BarChart3,
  Upload,
  FileWarning,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Settings,
  LogOut,
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import SettingsDialog from "./SettingsDialog";

const navItems = [
  { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { path: "/traffic-analysis", label: "Traffic Analysis", icon: BarChart3 },
  { path: "/upload-detect", label: "Upload & Detect", icon: Upload },
  { path: "/threat-logs", label: "Threat Logs", icon: FileWarning },
  { path: "/model-security", label: "AI Model Security", icon: Shield },
  { path: "/adversarial-detection", label: "Adversarial Detection", icon: ShieldAlert },
  { path: "/model-integrity", label: "Model Integrity", icon: ShieldCheck },
];

const Sidebar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { logout, username } = useAuth();
  const [settingsOpen, setSettingsOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };
  return (
    <aside className="fixed left-0 top-0 h-screen w-60 bg-sidebar border-r border-sidebar-border flex flex-col z-50">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5">
        <div className="w-9 h-9 rounded-lg bg-primary/20 flex items-center justify-center cyber-border">
          <Shield className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-foreground font-bold text-base leading-tight">SecureNet AI</h1>
          <span className="text-xs text-primary font-medium">Enterprise Security</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? "bg-primary/15 text-primary cyber-border"
                  : "text-sidebar-foreground hover:bg-secondary hover:text-foreground"
              }`}
            >
              <item.icon className="w-4.5 h-4.5" />
              {item.label}
            </NavLink>
          );
        })}
      </nav>

      {/* Settings */}
      <div className="px-3 pb-2">
        <button onClick={() => setSettingsOpen(true)} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-sidebar-foreground hover:bg-secondary hover:text-foreground transition-all w-full">
          <Settings className="w-4.5 h-4.5" />
          Settings
        </button>
      </div>
      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />

      {/* User */}
      <div className="px-3 pb-4">
        <div className="flex items-center gap-3 px-3 py-3 rounded-lg bg-secondary/50">
          <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
            <span className="text-xs font-bold text-primary">AC</span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-foreground truncate">{username || "Admin"}</p>
            <p className="text-xs text-muted-foreground">Security Lead</p>
          </div>
          <button onClick={handleLogout} className="hover:text-destructive transition-colors">
            <LogOut className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
