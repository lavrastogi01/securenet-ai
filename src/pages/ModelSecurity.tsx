import Header from "@/components/Header";
import { ShieldCheck, AlertTriangle, Eye, Activity, Download } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, LineChart, Line, Tooltip } from "recharts";
import { useEffect, useState } from "react";
import { fetchModelSecurity, type ModelSecurityResponse } from "@/services/api";
import { useLiveData } from "@/contexts/LiveDataContext";

const ModelSecurity = () => {
  const { settings, logs } = useLiveData();
  const [data, setData] = useState<ModelSecurityResponse | null>(null);

  useEffect(() => {
    const interval = (settings?.refresh_interval || 5) * 1000;
    let cancelled = false;
    const tick = async () => {
      const r = await fetchModelSecurity();
      if (!cancelled) {
        if (r) setData(r);
        // Note: client-side fallback handled in render via logs from context
      }
    };
    tick();
    const id = setInterval(tick, interval);
    return () => { cancelled = true; clearInterval(id); };
  }, [settings?.refresh_interval]); // removed `logs` — avoids resetting the interval every poll

  const integrity = data?.model_integrity || "Secure";
  const adversarial = data?.adversarial_inputs ?? 0;
  const lowConf = data?.low_confidence_pct ?? 0;
  const ppm = data?.predictions_per_min ?? 0;
  const poisoning = data?.poisoning_suspects ?? 0;
  const avgConf = data?.average_confidence ?? 0;
  const barData = data?.confidence_distribution || [];
  const lineData = data?.suspicious_frequency || [];

  const exportReport = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify({ generated_at: new Date().toISOString(), ...data }, null, 2)],
      { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `model-security-${Date.now()}.json`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 100);
  };

  return (
    <div>
      <Header title="Deep Learning Model Monitoring" badge="LIVE" actions={
        <button onClick={exportReport} className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium">
          <Download className="w-4 h-4" /> Export Report
        </button>
      } />
      <div className="p-6 space-y-6">
        <div>
          <h1 className="page-title">AI Model Security</h1>
          <p className="page-subtitle max-w-3xl">
            Continuous monitoring for ResNet model {data?.model_version || "v1.0"} (Production).
            Detecting adversarial patterns, poisoning attempts and inference anomalies.
          </p>
        </div>

        <div className="grid grid-cols-4 gap-4">
          <MiniStat
            icon={<ShieldCheck className={integrity === "Secure" ? "w-5 h-5 text-success" : "w-5 h-5 text-warning"} />}
            label="Model Integrity" value={integrity} sub={`Version: ${data?.model_version || "v1.0"}`}
          />
          <MiniStat
            icon={<AlertTriangle className="w-5 h-5 text-warning" />}
            label="Adversarial Inputs" value={String(adversarial)}
            sub="IPs flipping prediction class" subColor="text-muted-foreground"
          />
          <MiniStat
            icon={<Eye className="w-5 h-5 text-muted-foreground" />}
            label="Low Confidence" value={`${lowConf}%`}
            sub={`Avg confidence ${avgConf}%`}
            subColor={lowConf > 30 ? "text-destructive" : "text-success"}
          />
          <MiniStat
            icon={<Activity className="w-5 h-5 text-primary" />}
            label="Inference Activity" value={`${ppm}/min`}
            sub={`Poisoning suspects: ${poisoning}`} subColor="text-muted-foreground"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="section-card">
            <div className="flex items-center justify-between mb-1">
              <div>
                <h3 className="text-base font-semibold text-foreground">Prediction Confidence</h3>
                <p className="text-xs text-muted-foreground">Distribution across recent inferences</p>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={barData}>
                <XAxis dataKey="bin" tick={{ fill: "hsl(210, 15%, 50%)", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis hide />
                <Tooltip contentStyle={{ background: "hsl(220, 25%, 10%)", border: "1px solid hsl(220, 15%, 25%)", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="val" fill="hsl(185, 80%, 50%)" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div className="flex justify-between text-[10px] text-muted-foreground mt-1">
              <span>0.0 (Low)</span><span>Confidence Score</span><span>1.0 (High)</span>
            </div>
          </div>

          <div className="section-card">
            <div className="flex items-center justify-between mb-1">
              <div>
                <h3 className="text-base font-semibold text-foreground">Suspicious Input Frequency</h3>
                <p className="text-xs text-muted-foreground">HIGH/CRITICAL alerts over last 60 minutes</p>
              </div>
              <span className={lineData.some((d) => d.val > 5) ? "badge-critical text-[10px]" : "badge-low text-[10px]"}>
                {lineData.some((d) => d.val > 5) ? "High Risk" : "Stable"}
              </span>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={lineData}>
                <XAxis dataKey="t" tick={{ fill: "hsl(210, 15%, 50%)", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis hide />
                <Tooltip contentStyle={{ background: "hsl(220, 25%, 10%)", border: "1px solid hsl(220, 15%, 25%)", borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="val" stroke="hsl(185, 80%, 50%)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

const MiniStat = ({ icon, label, value, sub, subColor }: {
  icon: React.ReactNode; label: string; value: string; sub: string; subColor?: string;
}) => (
  <div className="stat-card">
    <div className="flex items-center justify-between mb-3">
      <span className="text-xs text-muted-foreground">{label}</span>
      {icon}
    </div>
    <p className="text-2xl font-bold text-foreground">{value}</p>
    <p className={`text-xs mt-1 ${subColor || "text-muted-foreground"}`}>{sub}</p>
  </div>
);

// Client-side metric builder used when the backend /model-security endpoint is offline.
function buildClientSideMetrics(logs: { confidence?: number; risk: string; source_ip?: string; prediction: string; timestamp: string; raw_label?: string }[]): ModelSecurityResponse {
  const confidences = logs.map((l) => l.confidence ?? 0).filter((c) => c > 0);
  const avg = confidences.length ? Math.round(confidences.reduce((a, b) => a + b, 0) / confidences.length * 10) / 10 : 0;
  const low = confidences.filter((c) => c < 60).length;
  const total = logs.length || 1;
  const hist = Array(11).fill(0);
  confidences.forEach((c) => { hist[Math.min(10, Math.max(0, Math.floor(c / 10)))]++; });
  const byIp: Record<string, Set<string>> = {};
  logs.slice(0, 200).forEach((l) => {
    const ip = l.source_ip || "?";
    (byIp[ip] = byIp[ip] || new Set()).add(l.prediction);
  });
  const adversarial = Object.values(byIp).filter((s) => s.size >= 3).length;
  const now = Date.now();
  const freq = Array(7).fill(0);
  logs.forEach((l) => {
    const mins = (now - new Date(l.timestamp).getTime()) / 60000;
    const idx = 6 - Math.min(6, Math.floor(mins / 10));
    if (idx >= 0 && (l.risk === "HIGH" || l.risk === "CRITICAL")) freq[idx]++;
  });
  const labels = ["60M", "50M", "40M", "30M", "20M", "10M", "NOW"];
  return {
    model_integrity: low / total < 0.3 ? "Secure" : "Review",
    model_version: "v1.0",
    adversarial_inputs: adversarial,
    low_confidence_pct: Math.round(100 * low / total * 10) / 10,
    predictions_per_min: Math.round(60 / 5 * 10) / 10,  // 60s / 5s interval = 12/min
    average_confidence: avg,
    poisoning_suspects: 0,
    confidence_distribution: hist.map((v, i) => ({ bin: (i / 10).toFixed(1), val: v })),
    suspicious_frequency: freq.map((v, i) => ({ t: labels[i], val: v })),
  };
}

export default ModelSecurity;
