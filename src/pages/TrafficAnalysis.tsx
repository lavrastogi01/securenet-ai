import Header from "@/components/Header";
import { Calendar, Shield, AlertTriangle, Download, MoreHorizontal } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts";
import { useLiveData } from "@/contexts/LiveDataContext";
import { useMemo } from "react";

const PROTO_FALLBACK = [
  { name: "TCP", pct: 0, count: 0 }, { name: "UDP", pct: 0, count: 0 },
  { name: "ICMP", pct: 0, count: 0 }, { name: "DNS", pct: 0, count: 0 },
  { name: "Other", pct: 0, count: 0 },
];

const riskColor = (risk: string) =>
  risk === "CRITICAL" ? "text-destructive" :
  risk === "HIGH" ? "text-warning" :
  risk === "MEDIUM" ? "text-muted-foreground" : "text-success";

const TrafficAnalysis = () => {
  const { logs, stats, settings } = useLiveData();

  const protocols = stats?.protocols?.length ? stats.protocols : PROTO_FALLBACK;
  const timeline = stats?.timeline?.length ? stats.timeline : [];
  const anomalies = stats?.anomalies || [];
  const origins = stats?.origins || {};
  const totalOrigin = Object.values(origins).reduce((a, b) => a + b, 0) || 1;
  const sortedOrigins = Object.entries(origins).sort((a, b) => b[1] - a[1]);

  // Heatmap from last hour buckets — count of predictions per hour over 7 days approx
  const heatmap = useMemo(() => {
    const buckets = new Array(168).fill(0);
    const now = Date.now();
    for (const l of logs) {
      const age = now - new Date(l.timestamp).getTime();
      const hourIdx = 167 - Math.min(167, Math.floor(age / 3_600_000));
      if (hourIdx >= 0) buckets[hourIdx]++;
    }
    const max = Math.max(1, ...buckets);
    return buckets.map((v) => v / max);
  }, [logs]);

  const stream = logs.slice(0, 20);
  const liveBadge = settings?.mode === "scapy" ? "LIVE SCAPY" : "DATASET MODE";

  // Total packets/sec rough estimate
  const recent = logs.slice(0, 60);
  const pktsPerSec = recent.length ? Math.round(recent.length / 5) : 0;

  return (
    <div>
      <Header title="Traffic Analysis" badge={liveBadge} />
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FilterChip icon={<Calendar className="w-3.5 h-3.5" />} label={`Mode: ${settings?.mode || "dataset"}`} />
            <FilterChip icon={<Shield className="w-3.5 h-3.5" />} label={`Protocols: ${protocols.length}`} />
            <FilterChip icon={<AlertTriangle className="w-3.5 h-3.5" />} label={`Anomalies: ${anomalies.length}`} />
          </div>
          <button
            onClick={() => exportLogs(logs)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-primary text-primary text-sm font-medium hover:bg-primary/10 transition-colors"
          >
            <Download className="w-4 h-4" /> Export Data
          </button>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div className="col-span-2 section-card">
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Network Traffic Timeline</h3>
              <span className="flex items-center gap-1 text-xs text-primary">● Bytes / minute</span>
            </div>
            <div className="flex items-baseline gap-2 mb-4">
              <span className="text-3xl font-bold text-foreground">{(logs.length).toLocaleString()}</span>
              <span className="text-sm text-muted-foreground">flows captured</span>
              <span className="text-xs text-success">~ {pktsPerSec}/sec</span>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="tlGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(185, 80%, 50%)" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="hsl(185, 80%, 50%)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill: "hsl(210, 15%, 50%)", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis hide />
                <Tooltip contentStyle={{ background: "hsl(220, 25%, 10%)", border: "1px solid hsl(220, 15%, 25%)", borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="value" stroke="hsl(185, 80%, 50%)" strokeWidth={2} fill="url(#tlGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="section-card">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4">Protocol Distribution</h3>
            <div className="space-y-4">
              {protocols.map((p) => (
                <div key={p.name} className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <span className="text-foreground font-medium">{p.name}</span>
                    <span className="text-primary font-semibold">{p.pct}%</span>
                  </div>
                  <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
                    <div className="h-full bg-primary rounded-full" style={{ width: `${p.pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
            <p className="text-xs text-muted-foreground mt-4 border-t border-border pt-3">
              {anomalies.length > 0
                ? `${anomalies.length} anomaly event(s) detected: ${anomalies[0].type}.`
                : "No anomalies detected in current window."}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="section-card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Packet Activity Heatmap</h3>
              <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                <span>LOW</span>
                <div className="flex gap-0.5">
                  <span className="w-3 h-3 rounded-sm bg-primary/10" />
                  <span className="w-3 h-3 rounded-sm bg-primary/30" />
                  <span className="w-3 h-3 rounded-sm bg-primary/60" />
                  <span className="w-3 h-3 rounded-sm bg-primary" />
                </div>
                <span>HIGH</span>
              </div>
            </div>
            <div className="grid grid-cols-[repeat(24,minmax(0,1fr))] gap-0.5">
              {heatmap.map((v, i) => (
                <div key={i} className="aspect-square rounded-sm" style={{ background: `hsl(185, 80%, 50%, ${v * 0.85 + 0.05})` }} />
              ))}
            </div>
            <div className="flex justify-between mt-2 text-[10px] text-muted-foreground">
              <span>-7D</span><span>-5D</span><span>-3D</span><span>-1D</span><span>NOW</span>
            </div>
          </div>

          <div className="section-card">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4">Traffic Source Origins</h3>
            <div className="space-y-3">
              {sortedOrigins.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">No data yet</p>
              ) : sortedOrigins.map(([name, count]) => {
                const pct = Math.round((count / totalOrigin) * 100);
                return (
                  <div key={name} className="space-y-1.5">
                    <div className="flex justify-between text-sm">
                      <span className="text-foreground font-medium">{name}</span>
                      <span className="text-muted-foreground">{count} ({pct}%)</span>
                    </div>
                    <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-primary rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
            {anomalies.length > 0 && (
              <div className="mt-4 bg-warning/10 border border-warning/30 rounded-lg p-3 text-xs">
                <p className="text-warning font-semibold">● ANOMALY</p>
                <p className="text-muted-foreground">{anomalies[0].type} from {anomalies[0].source_ip}</p>
              </div>
            )}
          </div>
        </div>

        <div className="section-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Ingress Traffic Stream</h3>
            <span className="flex items-center gap-1.5 text-xs text-success animate-pulse-glow">● CAPTURING...</span>
          </div>
          <table className="data-table">
            <thead>
              <tr><th>Timestamp</th><th>Source IP</th><th>Destination</th><th>Protocol</th><th>Status</th><th>Action</th></tr>
            </thead>
            <tbody>
              {stream.map((row, i) => (
                <tr key={row.id ?? i}>
                  <td className="text-muted-foreground font-mono text-xs">{new Date(row.timestamp).toLocaleString()}</td>
                  <td className="font-mono text-sm font-semibold text-foreground">{row.source_ip || "—"}</td>
                  <td className="text-secondary-foreground">{row.destination_ip || row.service || "—"}</td>
                  <td><span className="badge-info">{(row.protocol || "tcp").toUpperCase()}{row.dst_port ? `:${row.dst_port}` : ""}</span></td>
                  <td className={riskColor(row.risk)}>● {row.prediction}</td>
                  <td><MoreHorizontal className="w-4 h-4 text-muted-foreground" /></td>
                </tr>
              ))}
              {stream.length === 0 && (
                <tr><td colSpan={6} className="text-center text-muted-foreground py-8">Waiting for traffic…</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const FilterChip = ({ icon, label }: { icon: React.ReactNode; label: string }) => (
  <button className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-border text-sm text-secondary-foreground hover:border-primary/50 transition-colors">
    {icon} {label}
  </button>
);

function exportLogs(logs: ReturnType<typeof useLiveData>["logs"]) {
  const header = "timestamp,source_ip,prediction,risk,protocol,src_bytes,dst_bytes\n";
  const rows = logs.map((l) =>
    [l.timestamp, l.source_ip || "", l.prediction, l.risk, l.protocol || "", l.src_bytes || 0, l.dst_bytes || 0].join(",")
  ).join("\n");
  const blob = new Blob([header + rows], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `securenet-logs-${Date.now()}.csv`;
  a.click(); setTimeout(() => URL.revokeObjectURL(url), 100);
}

export default TrafficAnalysis;
