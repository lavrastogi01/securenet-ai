import { useState, useMemo } from "react";
import { Search, Bell, HelpCircle, X, Radar, ChevronRight } from "lucide-react";
import { useLiveData } from "@/contexts/LiveDataContext";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from "@/components/ui/dialog";
import {
  Popover, PopoverContent, PopoverTrigger,
} from "@/components/ui/popover";

interface HeaderProps {
  title: string;
  subtitle?: string;
  badge?: string;
  actions?: React.ReactNode;
}

const Header = ({ title, subtitle, badge, actions }: HeaderProps) => {
  const { logs, notifications, unreadCount, markNotificationsRead } = useLiveData();
  const [query, setQuery] = useState("");
  const [helpOpen, setHelpOpen] = useState(false);

  const searchResults = useMemo(() => {
    if (!query.trim()) return [];
    const q = query.toLowerCase();
    return logs.filter((l) =>
      (l.source_ip || "").toLowerCase().includes(q) ||
      (l.prediction || "").toLowerCase().includes(q) ||
      (l.timestamp || "").toLowerCase().includes(q) ||
      (l.risk || "").toLowerCase().includes(q)
    ).slice(0, 8);
  }, [query, logs]);

  return (
    <header className="h-14 border-b border-border flex items-center justify-between px-6 bg-card/50">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        {badge && <span className="badge-info text-[10px] uppercase tracking-wider">{badge}</span>}
        {subtitle && <span className="text-xs text-muted-foreground">{subtitle}</span>}
      </div>

      <div className="flex items-center gap-4">
        {/* Search */}
        <Popover open={query.length > 0}>
          <PopoverTrigger asChild>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search logs, IPs, or threats..."
                className="w-64 h-8 pl-9 pr-8 rounded-lg bg-secondary border border-border text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
              />
              {query && (
                <button onClick={() => setQuery("")} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-96 p-0 bg-card border-border" onOpenAutoFocus={(e) => e.preventDefault()}>
            <div className="p-3 border-b border-border text-xs text-muted-foreground">
              {searchResults.length} match{searchResults.length === 1 ? "" : "es"} in {logs.length} logs
            </div>
            <div className="max-h-80 overflow-y-auto">
              {searchResults.length === 0 ? (
                <p className="text-sm text-muted-foreground p-4 text-center">No results</p>
              ) : (
                searchResults.map((r, i) => (
                  <div key={r.id ?? i} className="px-3 py-2 border-b border-border/50 hover:bg-secondary/40 text-xs">
                    <div className="flex justify-between">
                      <span className="font-mono text-primary">{r.source_ip}</span>
                      <span className={
                        r.risk === "CRITICAL" ? "text-destructive" :
                        r.risk === "HIGH" ? "text-warning" :
                        r.risk === "MEDIUM" ? "text-muted-foreground" : "text-success"
                      }>{r.risk}</span>
                    </div>
                    <div className="flex justify-between text-muted-foreground mt-0.5">
                      <span>{r.prediction}</span>
                      <span className="font-mono">{new Date(r.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </PopoverContent>
        </Popover>

        {actions}

        {/* Bell — radar feed */}
        <Popover onOpenChange={(open) => { if (open) markNotificationsRead(); }}>
          <PopoverTrigger asChild>
            <button className="relative text-muted-foreground hover:text-foreground transition-colors">
              <Bell className="w-5 h-5" />
              {unreadCount > 0 && (
                <>
                  <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 bg-destructive rounded-full text-[10px] font-bold text-destructive-foreground flex items-center justify-center z-10">
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </span>
                  <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-destructive/70 animate-ping-slow" />
                </>
              )}
            </button>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-[420px] p-0 bg-card border-border overflow-hidden">
            <RadarFeed notifications={notifications} />
          </PopoverContent>
        </Popover>

        {/* Help — radial menu */}
        <Popover>
          <PopoverTrigger asChild>
            <button className="text-muted-foreground hover:text-foreground transition-colors">
              <HelpCircle className="w-5 h-5" />
            </button>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-[360px] p-0 bg-card border-border overflow-hidden">
            <RadialHelp onOpenFull={() => setHelpOpen(true)} />
          </PopoverContent>
        </Popover>
      </div>

      <HelpDialog open={helpOpen} onOpenChange={setHelpOpen} />
    </header>
  );
};

/* ===================== Radar Notifications Feed ===================== */
const riskColor = (r: string) =>
  r === "CRITICAL" ? "bg-destructive" :
  r === "HIGH" ? "bg-warning" :
  r === "MEDIUM" ? "bg-yellow-500" : "bg-success";

const riskRing = (r: string) =>
  r === "CRITICAL" ? "shadow-[0_0_12px_hsl(var(--destructive))] animate-pulse" :
  r === "HIGH" ? "shadow-[0_0_10px_hsl(var(--warning))]" :
  r === "MEDIUM" ? "shadow-[0_0_8px_rgba(234,179,8,0.7)]" :
  "shadow-[0_0_6px_hsl(var(--success))]";

const RadarFeed = ({ notifications }: { notifications: import("@/services/api").NotificationItem[] }) => {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  return (
    <div>
      {/* Radar header */}
      <div className="relative h-32 bg-gradient-to-b from-primary/10 to-card overflow-hidden border-b border-border">
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="relative w-28 h-28 rounded-full border border-primary/30">
            <div className="absolute inset-2 rounded-full border border-primary/20" />
            <div className="absolute inset-6 rounded-full border border-primary/15" />
            <div
              className="absolute inset-0 rounded-full animate-radar-sweep"
              style={{ background: "conic-gradient(from 0deg, transparent 0deg, hsl(var(--primary) / 0.35) 40deg, transparent 80deg)" }}
            />
            <Radar className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-5 h-5 text-primary" />
          </div>
        </div>
        <div className="absolute top-2 left-3 text-[10px] font-mono uppercase tracking-wider text-primary">
          Threat Radar · {notifications.length} blips
        </div>
      </div>

      <div className="max-h-[360px] overflow-y-auto">
        {notifications.length === 0 ? (
          <p className="text-sm text-muted-foreground p-6 text-center">No alerts yet — radar quiet</p>
        ) : (
          notifications.map((n, idx) => {
            const expanded = expandedId === n.id;
            return (
              <div
                key={n.id}
                className="px-3 py-2 border-b border-border/50 hover:bg-secondary/40 cursor-pointer animate-blip-in"
                style={{ animationDelay: `${Math.min(idx * 40, 200)}ms` }}
                onClick={() => setExpandedId(expanded ? null : n.id)}
              >
                <div className="flex items-start gap-2.5">
                  <span className={`mt-1.5 w-2.5 h-2.5 rounded-full flex-shrink-0 ${riskColor(n.risk)} ${riskRing(n.risk)}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm text-foreground truncate">{n.message}</p>
                      <ChevronRight className={`w-3.5 h-3.5 text-muted-foreground transition-transform ${expanded ? "rotate-90" : ""}`} />
                    </div>
                    <p className="text-[11px] text-muted-foreground font-mono mt-0.5">
                      {new Date(n.timestamp).toLocaleString()}
                    </p>

                    {expanded && (
                      <div className="mt-2 grid grid-cols-2 gap-2 text-[11px] animate-fade-in">
                        <Detail k="Attack" v={n.prediction} />
                        <Detail k="Risk" v={n.risk} />
                        <Detail k="Source IP" v={n.source_ip || "—"} />
                        <Detail k="Time" v={new Date(n.timestamp).toLocaleTimeString()} />
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

const Detail = ({ k, v }: { k: string; v: string }) => (
  <div className="rounded bg-secondary/50 px-2 py-1">
    <div className="text-[9px] uppercase tracking-wider text-muted-foreground">{k}</div>
    <div className="text-foreground font-mono truncate">{v}</div>
  </div>
);

/* ===================== Radial Help Menu ===================== */
const GLOSSARY: { term: string; full: string; desc: string; risk: string }[] = [
  { term: "DoS", full: "Denial of Service", desc: "Floods a target with traffic to disrupt service (neptune, smurf, teardrop).", risk: "CRITICAL" },
  { term: "Probe", full: "Reconnaissance", desc: "Scans/enumerates hosts and services (nmap, portsweep, satan).", risk: "MEDIUM" },
  { term: "R2L", full: "Remote-to-Local", desc: "Unauthorized access from a remote host (guess_passwd, ftp_write).", risk: "HIGH" },
  { term: "U2R", full: "User-to-Root", desc: "Privilege escalation to root (buffer_overflow, rootkit).", risk: "CRITICAL" },
  { term: "Normal", full: "Benign Traffic", desc: "Legitimate, non-malicious network activity.", risk: "LOW" },
];

const RadialHelp = ({ onOpenFull }: { onOpenFull: () => void }) => {
  const [active, setActive] = useState(0);
  const radius = 110;

  return (
    <div className="relative">
      <div className="p-3 border-b border-border flex items-center justify-between">
        <h4 className="text-sm font-semibold text-foreground">Glossary</h4>
        <button onClick={onOpenFull} className="text-[11px] text-primary hover:underline">Full docs →</button>
      </div>

      <div className="relative h-[280px] flex items-center justify-center">
        {/* Rings */}
        <div className="absolute w-[240px] h-[240px] rounded-full border border-primary/20 cyber-glow animate-spin-slow" />
        <div className="absolute w-[180px] h-[180px] rounded-full border border-primary/15 animate-spin-reverse" />

        {/* Center label */}
        <div className="absolute w-24 h-24 rounded-full bg-primary/10 cyber-border flex items-center justify-center text-center">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{GLOSSARY[active].full}</div>
            <div className="text-base font-bold text-primary mt-0.5">{GLOSSARY[active].term}</div>
          </div>
        </div>

        {/* Orbiting term buttons */}
        {GLOSSARY.map((g, i) => {
          const angle = (i / GLOSSARY.length) * 2 * Math.PI - Math.PI / 2;
          const x = Math.cos(angle) * radius;
          const y = Math.sin(angle) * radius;
          const isActive = i === active;
          return (
            <button
              key={g.term}
              onClick={() => setActive(i)}
              className={`absolute w-14 h-14 rounded-full text-[11px] font-bold font-mono transition-all duration-300 flex items-center justify-center
                ${isActive ? "bg-primary text-primary-foreground scale-110 shadow-[0_0_20px_hsl(var(--primary))]" : "bg-card cyber-border text-foreground hover:scale-105 hover:border-primary"}`}
              style={{ transform: `translate(${x}px, ${y}px)` }}
            >
              {g.term}
            </button>
          );
        })}
      </div>

      <div className="p-3 border-t border-border bg-secondary/30">
        <p className="text-xs text-muted-foreground leading-relaxed animate-fade-in" key={active}>
          {GLOSSARY[active].desc}
        </p>
        <div className="flex items-center justify-between mt-2">
          <span className={`text-[10px] font-bold uppercase tracking-wider ${
            GLOSSARY[active].risk === "CRITICAL" ? "text-destructive" :
            GLOSSARY[active].risk === "HIGH" ? "text-warning" :
            GLOSSARY[active].risk === "MEDIUM" ? "text-yellow-500" : "text-success"
          }`}>Risk · {GLOSSARY[active].risk}</span>
          <button onClick={onOpenFull} className="text-[11px] text-primary hover:underline">Walkthrough mode →</button>
        </div>
      </div>
    </div>
  );
};

/* ===================== Walkthrough Dialog ===================== */
const HelpDialog = ({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) => {
  const steps = [
    { title: "Network Traffic Over Time", body: "A rolling window of byte volume per minute, updated every 5 seconds from the live capture." },
    { title: "Attack Type Distribution", body: "Counts of each ResNet-predicted class. Use this to spot trends across DoS, Probe, R2L, U2R and Normal." },
    { title: "Recent Threat Logs", body: "Newest predictions from the backend — persists across page changes; filter by risk or IP." },
    { title: "Upload & Detect", body: "Drag & drop a CSV/PCAP/LOG file. The backend runs row-by-row inference and returns a forensic JSON report." },
    { title: "AI Model Security", body: "Detects model-evasion attempts: low-confidence predictions, prediction flipping, and suspicious input frequency." },
    { title: "Model Integrity", body: "SHA-256 hash check of resnet_nslkdd.pth, with Force Re-scan and Export Certificate." },
  ];
  const [step, setStep] = useState(0);

  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (v) setStep(0); }}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Interactive Walkthrough</DialogTitle>
          <DialogDescription>Step through every dashboard panel.</DialogDescription>
        </DialogHeader>

        <div className="relative rounded-lg cyber-border p-6 bg-gradient-to-br from-primary/5 to-card overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 rounded-full bg-primary/10 blur-2xl animate-pulse-glow" />
          <div className="relative">
            <div className="text-[10px] font-mono uppercase tracking-wider text-primary mb-1">
              Step {step + 1} of {steps.length}
            </div>
            <h3 className="text-lg font-semibold text-foreground mb-2 animate-fade-in" key={`t${step}`}>
              {steps[step].title}
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed animate-fade-in" key={`b${step}`}>
              {steps[step].body}
            </p>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex gap-1">
            {steps.map((_, i) => (
              <span key={i} className={`h-1.5 rounded-full transition-all ${i === step ? "w-6 bg-primary" : "w-1.5 bg-border"}`} />
            ))}
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setStep((s) => Math.max(0, s - 1))}
              disabled={step === 0}
              className="h-8 px-3 rounded-md border border-border text-xs hover:bg-secondary disabled:opacity-40"
            >Back</button>
            <button
              onClick={() => step < steps.length - 1 ? setStep(step + 1) : onOpenChange(false)}
              className="h-8 px-3 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90"
            >{step < steps.length - 1 ? "Next" : "Finish"}</button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default Header;
