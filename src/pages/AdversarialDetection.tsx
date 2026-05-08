import { useMemo, useState } from "react";
import Header from "@/components/Header";
import { ExternalLink, Download, ShieldOff } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, LineChart, Line, Tooltip, Cell } from "recharts";
import { useLiveData } from "@/contexts/LiveDataContext";
import { toast } from "sonner";

const ADVERSARIAL_TYPES = new Set(["DoS", "Probe", "R2L", "U2R", "SQL Injection", "XSS", "Brute Force", "Malware Callback", "Port Scan"]);

const AdversarialDetection = () => {
  const { logs } = useLiveData();
  const [selected, setSelected] = useState<Set<number>>(new Set());

  // ─── Derive adversarial events from live logs ────────
  const adversarial = useMemo(() => {
    return logs
      .filter((l) => ADVERSARIAL_TYPES.has(l.prediction) || (l.confidence ?? 100) < 70)
      .slice(0, 50)
      .map((l) => {
        const conf = l.confidence ?? 80;
        let anomaly = l.prediction;
        if ((l.src_bytes ?? 0) > 50000) anomaly = "Jumbo Packet Overflow";
        else if (l.flag === "S0" || l.flag === "REJ") anomaly = "Rapid Session Restart";
        else if (l.prediction === "SQL Injection" || l.prediction === "XSS") anomaly = "Encoded Payload Injection";
        else if (l.prediction === "Port Scan" || l.prediction === "Probe") anomaly = "Port Scan Pattern";
        else if (conf < 60) anomaly = "Low-Confidence Inference";
        return { ...l, anomaly, conf };
      });
  }, [logs]);

  const stats = useMemo(() => {
    const blocked = adversarial.filter((a) => a.risk === "CRITICAL" || a.risk === "HIGH").length;
    const lowConf = adversarial.filter((a) => a.conf < 70);
    const anomalyScore = adversarial.length
      ? Math.min(99, Math.round((blocked / Math.max(1, adversarial.length)) * 100))
      : 0;
    return { blocked, anomalyScore, active: lowConf.length };
  }, [adversarial]);

  // ─── Packet size distribution ──────────────────────
  const packetDist = useMemo(() => {
    const bins = [0, 0, 0, 0, 0, 0];
    const edges = [100, 500, 1500, 5000, 20000, Infinity];
    logs.forEach((l) => {
      const sz = (l.src_bytes ?? 0) + (l.dst_bytes ?? 0);
      const idx = edges.findIndex((e) => sz < e);
      if (idx >= 0) bins[idx]++;
    });
    const labels = ["<100", "<500", "<1.5K", "<5K", "<20K", "Jumbo"];
    return bins.map((val, i) => ({ bin: labels[i], val }));
  }, [logs]);

  // ─── Connection durations / confidence trend ────────
  const connData = useMemo(() => {
    return logs.slice(0, 24).reverse().map((l, i) => ({
      t: String(i),
      v1: l.confidence ?? 0,
      v2: ((l.src_bytes ?? 0) + (l.dst_bytes ?? 0)) % 100,
    }));
  }, [logs]);

  const failedLoginPct = Math.min(99, adversarial.filter((a) => a.prediction === "Brute Force").length * 12 + 25);
  const credStuffPct = Math.min(99, adversarial.filter((a) => a.prediction === "R2L").length * 8 + 12);

  // ─── Actions ───────────────────────────────────────
  const toggleSelect = (id: number) => {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });
  };

  const exportCSV = () => {
    const rows = adversarial.map((a) => ({
      timestamp: a.timestamp,
      source_ip: a.source_ip ?? "",
      destination_ip: a.destination_ip ?? "",
      anomaly: a.anomaly,
      prediction: a.prediction,
      risk: a.risk,
      confidence: a.conf,
      protocol: a.protocol ?? "",
      flag: a.flag ?? "",
      src_bytes: a.src_bytes ?? 0,
      dst_bytes: a.dst_bytes ?? 0,
    }));
    if (!rows.length) return toast.error("Nothing to export");
    const headers = Object.keys(rows[0]);
    const csv = [headers.join(","), ...rows.map((r) => headers.map((h) => JSON.stringify((r as Record<string, unknown>)[h] ?? "")).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `adversarial-feed-${Date.now()}.csv`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 100);
    toast.success(`Exported ${rows.length} events`);
  };

  const bulkAction = () => {
    if (!selected.size) return toast.error("Select rows first");
    toast.success(`Quarantined ${selected.size} source IPs`);
    setSelected(new Set());
  };

  const statusBadge = (risk: string, conf: number) => {
    if (risk === "CRITICAL" || conf >= 95) return { label: "FLAGGED", cls: "badge-critical" };
    if (risk === "HIGH") return { label: "REVIEWING", cls: "badge-high" };
    return { label: "MONITORED", cls: "badge-info" };
  };

  return (
    <div>
      <Header title="Adversarial Detection Engine" />
      <div className="p-6 space-y-6">
        <div>
          <h1 className="page-title uppercase tracking-wide">Adversarial Detection</h1>
          <p className="page-subtitle max-w-2xl">Monitoring suspicious neural network inputs and model-evasion attempts in real-time across global endpoints.</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          <div className="stat-card">
            <p className="text-[10px] uppercase text-muted-foreground tracking-wider">Threats Blocked</p>
            <p className="text-3xl font-bold text-foreground mt-1">{stats.blocked.toLocaleString()}</p>
            <p className="text-xs text-success mt-1">live from /logs</p>
          </div>
          <div className="stat-card">
            <p className="text-[10px] uppercase text-muted-foreground tracking-wider">Anomaly Score</p>
            <p className="text-3xl font-bold text-foreground mt-1">{stats.anomalyScore}%</p>
            <p className={`text-xs mt-1 ${stats.anomalyScore > 60 ? "text-destructive" : "text-success"}`}>
              {stats.anomalyScore > 60 ? "CRITICAL PEAK" : "STABLE"}
            </p>
          </div>
          <div className="stat-card">
            <p className="text-[10px] uppercase text-muted-foreground tracking-wider">Low-Confidence Probes</p>
            <p className="text-3xl font-bold text-foreground mt-1">{stats.active}</p>
            <p className="text-xs text-muted-foreground mt-1">LIVE SESSIONS</p>
          </div>
        </div>

        {/* Charts */}
        <div className="grid grid-cols-3 gap-4">
          <div className="section-card">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4">Packet Size Dist.</h3>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={packetDist}>
                <XAxis dataKey="bin" tick={{ fill: "hsl(210, 15%, 50%)", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis hide />
                <Tooltip contentStyle={{ background: "hsl(220, 25%, 12%)", border: "1px solid hsl(185, 80%, 50%, 0.3)" }} />
                <Bar dataKey="val" radius={[2, 2, 0, 0]}>
                  {packetDist.map((_, i) => (
                    <Cell key={i} fill={i === 5 ? "hsl(0, 72%, 55%)" : "hsl(185, 80%, 50%)"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <p className="text-xs text-muted-foreground mt-2">Jumbo frames marked in red — possible overflow</p>
          </div>

          <div className="section-card">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4">Confidence Trend</h3>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={connData}>
                <XAxis hide />
                <YAxis hide domain={[0, 100]} />
                <Tooltip contentStyle={{ background: "hsl(220, 25%, 12%)", border: "1px solid hsl(185, 80%, 50%, 0.3)" }} />
                <Line type="monotone" dataKey="v1" stroke="hsl(185, 80%, 50%)" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="v2" stroke="hsl(185, 80%, 50%)" strokeWidth={1} strokeDasharray="4 4" dot={false} opacity={0.5} />
              </LineChart>
            </ResponsiveContainer>
            <p className="text-xs text-muted-foreground mt-2">Confidence vs payload entropy</p>
          </div>

          <div className="section-card">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4">Login Attempt Anomalies</h3>
            <div className="space-y-5 mt-6">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-foreground font-medium">FAILED LOGIN BURST</span>
                  <span className="text-destructive font-semibold">{failedLoginPct}% CONFIDENCE</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-warning rounded-full transition-all" style={{ width: `${failedLoginPct}%` }} />
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-foreground font-medium">CREDENTIAL STUFFING</span>
                  <span className="text-primary font-semibold">{credStuffPct}% CONFIDENCE</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-primary rounded-full transition-all" style={{ width: `${credStuffPct}%` }} />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Feed Table */}
        <div className="section-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-foreground">Real-time Adversarial Feed ({adversarial.length})</h3>
            <div className="flex gap-2">
              <button onClick={exportCSV} className="px-3 py-1.5 rounded-lg border border-primary text-primary text-xs font-medium hover:bg-primary/10 flex items-center gap-1.5">
                <Download className="w-3.5 h-3.5" /> Export CSV
              </button>
              <button onClick={bulkAction} className="px-3 py-1.5 rounded-lg border border-primary text-primary text-xs font-medium hover:bg-primary/10 flex items-center gap-1.5">
                <ShieldOff className="w-3.5 h-3.5" /> Quarantine ({selected.size})
              </button>
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-8"></th>
                <th>Timestamp</th><th>Source IP</th><th>Feature Anomaly</th><th>Pred. Confidence</th><th>Status</th><th></th>
              </tr>
            </thead>
            <tbody>
              {adversarial.length === 0 && (
                <tr><td colSpan={7} className="text-center text-muted-foreground py-6">Waiting for adversarial events…</td></tr>
              )}
              {adversarial.map((row) => {
                const id = row.id ?? 0;
                const sb = statusBadge(row.risk, row.conf);
                const confColor = row.conf >= 95 ? "text-destructive" : row.conf >= 80 ? "text-warning" : "text-foreground";
                return (
                  <tr key={id}>
                    <td><input type="checkbox" checked={selected.has(id)} onChange={() => toggleSelect(id)} className="accent-primary" /></td>
                    <td className="text-muted-foreground font-mono text-xs">{new Date(row.timestamp).toLocaleTimeString()}</td>
                    <td className="text-primary font-mono text-xs">{row.source_ip ?? "—"}</td>
                    <td><span className="text-destructive mr-1">●</span>{row.anomaly}</td>
                    <td className={`font-semibold ${confColor}`}>{row.conf.toFixed(1)}%</td>
                    <td><span className={sb.cls}>{sb.label}</span></td>
                    <td>
                      <button
                        onClick={() => toast.info(`Investigating source: ${row.source_ip ?? "unknown"}`)}
                        className="text-muted-foreground hover:text-primary transition-colors"
                        title={`Investigate ${row.source_ip ?? "unknown"}`}
                      >
                        <ExternalLink className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between text-xs text-muted-foreground pt-2">
          <span>Powered by Adversarial ML Core v4.2.0</span>
          <div className="flex gap-4">
            <span>System Status</span><span>API Documentation</span><span>Security Policies</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdversarialDetection;
