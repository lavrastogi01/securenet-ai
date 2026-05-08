import Header from "@/components/Header";
import { Download, ChevronLeft, ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { useLiveData } from "@/contexts/LiveDataContext";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";

const riskClass: Record<string, string> = {
  CRITICAL: "badge-critical", HIGH: "badge-high", MEDIUM: "badge-medium", LOW: "badge-low",
};

const STATUS_FROM_RISK: Record<string, string> = {
  CRITICAL: "Blocked", HIGH: "Mitigated", MEDIUM: "Quarantined", LOW: "Passed",
};

const statusColor: Record<string, string> = {
  Blocked: "text-destructive",      // dangerous — attack was blocked
  Mitigated: "text-warning",
  Quarantined: "text-muted-foreground",
  Passed: "text-success",           // benign traffic passed
  "Under Review": "text-foreground",
};

const ATTACK_ICONS: Record<string, string> = {
  DoS: "🛡️", Probe: "📡", R2L: "🔑", U2R: "💀", Normal: "✅",
  "SQL Injection": "🐚", XSS: "⚠️", "Brute Force": "👊",
  "Malware Callback": "🦠", "Port Scan": "📡",
};

const PAGE_SIZE = 10;

const ThreatLogs = () => {
  const { logs } = useLiveData();
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [timeFilter, setTimeFilter] = useState("24h");
  const [page, setPage] = useState(1);

  const attackTypes = useMemo(
    () => Array.from(new Set(logs.map((l) => l.prediction))).sort(),
    [logs]
  );

  const filtered = useMemo(() => {
    const now = Date.now();
    const cutoffMs = timeFilter === "1h" ? 3600_000 :
      timeFilter === "24h" ? 86_400_000 :
      timeFilter === "7d" ? 7 * 86_400_000 : Infinity;
    return logs.filter((l) => {
      if (typeFilter !== "ALL" && l.prediction !== typeFilter) return false;
      if (riskFilter !== "ALL" && l.risk !== riskFilter) return false;
      const age = now - new Date(l.timestamp).getTime();
      if (age > cutoffMs) return false;
      return true;
    });
  }, [logs, typeFilter, riskFilter, timeFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageRows = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const exportCsv = () => {
    const header = "timestamp,source_ip,destination_ip,attack_type,risk,status,confidence,protocol\n";
    const body = filtered.map((l) =>
      [l.timestamp, l.source_ip || "", l.destination_ip || "", l.prediction, l.risk,
       l.status || STATUS_FROM_RISK[l.risk] || "", l.confidence ?? "", l.protocol || ""]
       .map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")
    ).join("\n");
    const blob = new Blob([header + body], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    a.download = `securenet-threats-${Date.now()}.csv`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 100);
  };

  const reset = () => { setTypeFilter("ALL"); setRiskFilter("ALL"); setTimeFilter("24h"); setPage(1); };

  return (
    <div>
      <Header title="Threat Monitoring System" />
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="page-title">Threat Logs</h1>
            <p className="page-subtitle max-w-2xl">
              Real-time monitoring and analysis of detected cyber attacks across the entire infrastructure.
              All events are categorized by risk level and source.
            </p>
          </div>
          <button onClick={exportCsv} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium">
            <Download className="w-4 h-4" /> Export CSV
          </button>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          <FilterBlock label="TYPE">
            <Select value={typeFilter} onValueChange={(v) => { setTypeFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 min-w-[160px] bg-secondary border-border"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">All Attacks</SelectItem>
                {attackTypes.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
          </FilterBlock>

          <FilterBlock label="RISK">
            <Select value={riskFilter} onValueChange={(v) => { setRiskFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 min-w-[140px] bg-secondary border-border"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">All Levels</SelectItem>
                <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                <SelectItem value="HIGH">HIGH</SelectItem>
                <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                <SelectItem value="LOW">LOW</SelectItem>
              </SelectContent>
            </Select>
          </FilterBlock>

          <FilterBlock label="TIME">
            <Select value={timeFilter} onValueChange={(v) => { setTimeFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 min-w-[160px] bg-secondary border-border"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="1h">Last Hour</SelectItem>
                <SelectItem value="24h">Last 24 Hours</SelectItem>
                <SelectItem value="7d">Last 7 Days</SelectItem>
                <SelectItem value="all">All Time</SelectItem>
              </SelectContent>
            </Select>
          </FilterBlock>

          <button onClick={reset} className="ml-auto text-xs text-primary font-medium hover:underline">↻ Reset Filters</button>
        </div>

        {/* Table */}
        <div className="section-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th><th>Source IP</th><th>Attack Type</th>
                <th>Confidence</th><th>Risk Level</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.length === 0 && (
                <tr><td colSpan={6} className="text-center text-muted-foreground py-8">No matching threats</td></tr>
              )}
              {pageRows.map((t) => {
                const status = t.status || STATUS_FROM_RISK[t.risk] || "Under Review";
                const conf = t.confidence ?? 0;
                return (
                  <tr key={t.id ?? `${t.timestamp}-${t.source_ip}`}>
                    <td className="text-muted-foreground font-mono text-xs">
                      {new Date(t.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="font-mono font-semibold text-foreground">{t.source_ip || "—"}</span>
                      {t.origin && <span className="text-primary text-xs ml-1">({t.origin})</span>}
                    </td>
                    <td className="flex items-center gap-2">
                      <span>{ATTACK_ICONS[t.prediction] || "❗"}</span> {t.prediction}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-1.5 bg-secondary rounded-full overflow-hidden">
                          <div className="h-full bg-primary rounded-full" style={{ width: `${conf}%` }} />
                        </div>
                        <span className="text-sm font-medium">{conf}%</span>
                      </div>
                    </td>
                    <td><span className={riskClass[t.risk]}>{t.risk}</span></td>
                    <td className={statusColor[status] || "text-foreground"}>● {status}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-border">
            <p className="text-xs text-muted-foreground">
              Showing <span className="text-foreground font-semibold">
                {filtered.length === 0 ? 0 : (safePage - 1) * PAGE_SIZE + 1}-
                {Math.min(safePage * PAGE_SIZE, filtered.length)}
              </span> of {filtered.length} incidents
            </p>
            <div className="flex items-center gap-1">
              <button onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="w-8 h-8 rounded-lg flex items-center justify-center text-muted-foreground hover:bg-secondary">
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="px-3 text-sm text-foreground font-medium">{safePage} / {totalPages}</span>
              <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                className="w-8 h-8 rounded-lg flex items-center justify-center text-muted-foreground hover:bg-secondary">
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const FilterBlock = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="flex items-center gap-2">
    <span className="text-xs font-semibold text-muted-foreground">{label}</span>
    {children}
  </div>
);

export default ThreatLogs;
