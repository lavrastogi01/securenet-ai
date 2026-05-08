import Header from "@/components/Header";
import { TrendingUp, TrendingDown, AlertTriangle, XCircle, CheckCircle } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { useLiveData } from "@/contexts/LiveDataContext";
import { useMemo } from "react";

const attackColors: Record<string, string> = {
  DoS: "hsl(0, 72%, 55%)",
  Probe: "hsl(25, 90%, 55%)",
  R2L: "hsl(185, 80%, 50%)",
  U2R: "hsl(280, 70%, 55%)",
  Normal: "hsl(155, 70%, 50%)",
};

const riskToStatus: Record<string, { label: string; color: string }> = {
  CRITICAL: { label: "Blocked", color: "text-destructive" },
  HIGH: { label: "Flagged", color: "text-warning" },
  MEDIUM: { label: "Under Review", color: "text-muted-foreground" },
  LOW: { label: "Passed", color: "text-success" },
};

const Dashboard = () => {
  const { logs, stats, settings } = useLiveData();

  const trafficData = useMemo(() => {
    if (stats?.timeline?.length) return stats.timeline;
    // fallback: derive from logs
    const buckets: Record<string, number> = {};
    [...logs].reverse().slice(-50).forEach((l) => {
      const t = new Date(l.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      buckets[t] = (buckets[t] || 0) + (l.src_bytes || 0) + (l.dst_bytes || 0);
    });
    return Object.entries(buckets).map(([time, value]) => ({ time, value })).slice(-24);
  }, [stats, logs]);

  const attackCounts = useMemo(() => {
    if (stats?.attacks && Object.keys(stats.attacks).length) return stats.attacks;
    const counts: Record<string, number> = {};
    logs.forEach((l) => { counts[l.prediction] = (counts[l.prediction] || 0) + 1; });
    return counts;
  }, [stats, logs]);
  const totalAlerts = Object.entries(attackCounts).filter(([k]) => k !== "Normal").reduce((s, [, v]) => s + v, 0);
  const blocked = (attackCounts.DoS || 0) + (attackCounts.U2R || 0);
  const totalBytes = logs.reduce((s, l) => s + (l.src_bytes || 0) + (l.dst_bytes || 0), 0);
  const trafficTB = (totalBytes / 1e12).toFixed(3);

  const pieData = Object.entries(attackCounts)
    .filter(([k]) => k !== "Normal")
    .map(([name, value]) => ({ name, value, color: attackColors[name] || "hsl(210, 15%, 40%)" }));
  const totalAttacks = pieData.reduce((s, d) => s + d.value, 0);

  return (
    <div>
      <Header
        title="SecureNet AI"
        subtitle={`Senior SOC Analyst — ${settings?.mode === "scapy" ? "LIVE CAPTURE" : "DATASET MODE"}`}
      />
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-4 gap-4">
          <StatCard icon={<TrendingUp className="w-5 h-5 text-primary" />} iconBg="bg-primary/15" label="Total Network Traffic" value={`${trafficTB} TB`} change="+5.2%" changeUp />
          <StatCard icon={<AlertTriangle className="w-5 h-5 text-warning" />} iconBg="bg-warning/15" label="Threat Alerts Today" value={String(totalAlerts)} change={`+${totalAlerts}`} changeUp={totalAlerts > 0} />
          <StatCard icon={<XCircle className="w-5 h-5 text-destructive" />} iconBg="bg-destructive/15" label="Blocked Attacks" value={String(blocked)} change={`+${blocked}`} changeUp={false} />
          <StatCard icon={<CheckCircle className="w-5 h-5 text-success" />} iconBg="bg-success/15" label="System Health" value="99.9%" badge="Stable" />
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div className="col-span-2 section-card">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-semibold text-foreground">Network Traffic Over Time</h3>
                <p className="text-xs text-muted-foreground">Live monitoring — updates every {settings?.refresh_interval || 5}s</p>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={trafficData}>
                <defs>
                  <linearGradient id="trafficGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(185, 80%, 50%)" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="hsl(185, 80%, 50%)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill: "hsl(210, 15%, 50%)", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis hide />
                <Area type="monotone" dataKey="value" stroke="hsl(185, 80%, 50%)" strokeWidth={2} fill="url(#trafficGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="section-card">
            <h3 className="text-base font-semibold text-foreground">Attack Type Distribution</h3>
            <p className="text-xs text-muted-foreground mb-2">Dynamic from predictions</p>
            {pieData.length > 0 ? (
              <>
                <div className="flex justify-center">
                  <ResponsiveContainer width={180} height={180}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} dataKey="value" strokeWidth={0}>
                        {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="text-center -mt-28 mb-20">
                  <p className="text-xs text-muted-foreground uppercase">Total</p>
                  <p className="text-2xl font-bold text-foreground">{totalAttacks}</p>
                </div>
                <div className="space-y-2">
                  {pieData.map((item) => (
                    <div key={item.name} className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ background: item.color }} />
                        <span className="text-secondary-foreground">{item.name}</span>
                      </div>
                      <span className="font-semibold text-foreground">{item.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground text-center py-12">Waiting for data...</p>
            )}
          </div>
        </div>

        <div className="section-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-foreground">Recent Threat Logs</h3>
            <span className="text-xs text-muted-foreground">{logs.length} entries</span>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th><th>Source IP</th><th>Attack Type</th><th>Risk Level</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {logs.slice(0, 10).map((log, i) => {
                const st = riskToStatus[log.risk] || riskToStatus.LOW;
                const badgeClass = log.risk === "CRITICAL" ? "badge-critical" : log.risk === "HIGH" ? "badge-high" : log.risk === "MEDIUM" ? "badge-medium" : "badge-low";
                return (
                  <tr key={log.id ?? i}>
                    <td className="text-muted-foreground font-mono text-xs">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="text-primary font-mono text-xs">{log.source_ip || "—"}</td>
                    <td>{log.prediction}</td>
                    <td><span className={badgeClass}>{log.risk}</span></td>
                    <td><span className={st.color}>● {st.label}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const StatCard = ({ icon, iconBg, label, value, change, changeUp, badge }: {
  icon: React.ReactNode; iconBg: string; label: string; value: string;
  change?: string; changeUp?: boolean; badge?: string;
}) => (
  <div className="stat-card flex flex-col gap-3">
    <div className="flex items-center justify-between">
      <div className={`w-10 h-10 rounded-lg ${iconBg} flex items-center justify-center`}>{icon}</div>
      {change && (
        <span className={`text-xs font-medium flex items-center gap-1 ${changeUp ? "text-success" : "text-destructive"}`}>
          {changeUp ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />} {change}
        </span>
      )}
      {badge && <span className="badge-success text-[10px]">● {badge}</span>}
    </div>
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-2xl font-bold text-foreground mt-1">{value}</p>
    </div>
  </div>
);

export default Dashboard;
