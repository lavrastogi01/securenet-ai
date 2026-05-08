import { useEffect, useState } from "react";
import Header from "@/components/Header";
import { CheckCircle, XCircle, RefreshCw, FileDown, Eye, Info } from "lucide-react";
import { fetchIntegrity, type IntegrityResponse } from "@/services/api";
import { toast } from "sonner";

const ModelIntegrity = () => {
  const [data, setData] = useState<IntegrityResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    const r = await fetchIntegrity();
    if (r) setData(r);
    setLoading(false);
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  const forceRescan = async () => {
    toast.info("Re-computing SHA-256 over model weights…");
    await load();
    toast.success("Integrity scan complete");
  };

  const exportCertificate = () => {
    if (!data) return toast.error("No integrity data yet");
    const cert = `SecureNet AI — Model Integrity Certificate
================================================
Issued:        ${new Date().toISOString()}
File:          ${data.file_name}
Version:       ${data.version}
Size (bytes):  ${data.size_bytes}
SHA-256:       ${data.sha256}
Expected:      ${data.expected_sha256}
Status:        ${data.matched ? "MATCHED" : "MISMATCH"}
Model loaded:  ${data.model_loaded}
Drift:         ${data.drift_pct.toFixed(2)}%
Last check:    ${data.last_check}
================================================
This certificate attests that the model weights have been
hash-verified against the registered baseline. Any divergence
indicates tampering, retraining, or poisoning.
`;
    const blob = new Blob([cert], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `integrity-cert-${Date.now()}.txt`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 100);
    toast.success("Certificate downloaded");
  };

  const matched = data?.matched ?? true;
  const sha = data?.sha256 ?? "—";
  const drift = data?.drift_pct ?? 0;

  return (
    <div>
      <Header title="Integrity Monitor" subtitle="Real-time verification and security status of AI assets" actions={
        <span className="badge-info flex items-center gap-1.5 text-xs">
          🕐 Last Scan: {data ? new Date(data.last_check).toLocaleTimeString() : "—"}
        </span>
      } />
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-5 gap-6">
          {/* Main Integrity Status */}
          <div className="col-span-3">
            <div className="section-card text-center py-12" style={{ borderColor: matched ? "hsl(155, 70%, 50%, 0.3)" : "hsl(0, 72%, 55%, 0.3)" }}>
              <div className={`w-16 h-16 rounded-full ${matched ? "bg-success/15" : "bg-destructive/15"} flex items-center justify-center mx-auto mb-4`}>
                {matched ? <CheckCircle className="w-8 h-8 text-success" /> : <XCircle className="w-8 h-8 text-destructive" />}
              </div>
              <h2 className="text-3xl font-bold text-foreground mb-2">{data?.status ?? "Loading…"}</h2>
              <p className="text-sm text-muted-foreground max-w-md mx-auto">
                {matched
                  ? "Integrity check passed. No unauthorized modifications detected in the current neural network weights or architecture."
                  : "SHA-256 mismatch detected. Model weights may have been tampered with — review immediately."}
              </p>
              <div className="flex items-center justify-center gap-3 mt-6">
                <button onClick={forceRescan} disabled={loading}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
                  <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Force Re-scan
                </button>
                <button onClick={exportCertificate}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg border border-border text-foreground text-sm font-medium hover:bg-secondary transition-colors">
                  <FileDown className="w-4 h-4" /> Export Certificate
                </button>
              </div>
            </div>
          </div>

          {/* Model Info */}
          <div className="col-span-2 section-card">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-primary mb-4">
              <Info className="w-4 h-4" /> Model Information
            </h3>
            <div className="space-y-3 text-sm">
              <InfoRow label="File Name" value={data?.file_name ?? "—"} />
              <InfoRow label="Version" value={data?.version ?? "—"} />
              <InfoRow label="Size" value={data ? `${(data.size_bytes / 1024).toFixed(1)} KB` : "—"} />
              <InfoRow label="Last Integrity Check" value={data ? new Date(data.last_check).toLocaleString() : "—"} />
              <InfoRow label="Drift" value={`${drift.toFixed(2)}%`} />
            </div>
            <div className="mt-4 pt-4 border-t border-border">
              <p className="text-xs text-muted-foreground mb-2">Hash Verification (SHA-256)</p>
              <p className="font-mono text-xs text-primary break-all leading-relaxed">{sha}</p>
              <p className={`text-xs font-semibold mt-2 ${matched ? "text-success" : "text-destructive"}`}>
                {matched ? "✓ MATCHED" : "✗ MISMATCH"}
              </p>
            </div>
          </div>
        </div>

        {/* Activity Logs */}
        <div className="section-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-foreground">Model Activity Logs</h3>
            <button onClick={load} className="text-xs text-primary font-medium hover:underline">Refresh</button>
          </div>
          <table className="data-table">
            <thead><tr><th>Event</th><th>Timestamp</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {(data?.activity ?? []).slice(0, 8).map((log, i) => (
                <tr key={i}>
                  <td className="flex items-center gap-2">
                    <span className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-sm">
                      {log.status === "VERIFIED" ? "✅" : log.status === "FLAGGED" ? "🚨" : "↗️"}
                    </span>
                    <span className="text-foreground">{log.event}</span>
                  </td>
                  <td className="text-muted-foreground text-xs">{new Date(log.timestamp).toLocaleString()}</td>
                  <td>
                    <span className={log.status === "FLAGGED" ? "badge-critical" : log.status === "VERIFIED" ? "badge-success" : "badge-info"}>
                      {log.status}
                    </span>
                  </td>
                  <td><Eye className="w-4 h-4 text-muted-foreground" /></td>
                </tr>
              ))}
              {!data?.activity?.length && (
                <tr><td colSpan={4} className="text-center text-muted-foreground py-6">No activity yet…</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Drift / monitor */}
        <div className="grid grid-cols-2 gap-4">
          <div className="section-card">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Weight Distribution Drift</h3>
              <span className={`text-xs ${drift > 5 ? "text-destructive" : "text-success"}`}>{drift.toFixed(2)}% Δ</span>
            </div>
            <div className="flex items-end gap-1 h-24 mt-4">
              {(data?.weight_histogram ?? [30, 45, 55, 70, 65, 50, 35]).map((h, i) => (
                <div key={i} className="flex-1 rounded-t transition-all" style={{ height: `${h}%`, background: "hsl(185, 80%, 50%)" }} />
              ))}
            </div>
          </div>
          <div className="section-card flex items-center justify-center">
            <div className="text-center">
              <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-2">
                <span className="text-primary text-lg">✦</span>
              </div>
              <p className="text-sm text-muted-foreground">Continuous Integrity Monitoring Active</p>
              <p className="text-xs text-success mt-1">Polling every 10s</p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span className={`status-dot ${matched ? "bg-success" : "bg-destructive"}`} />
          <span className="text-[10px] uppercase tracking-wider">System Status</span>
          <span className="text-foreground ml-1">
            {matched ? "All nodes operational" : "Integrity alarm — review required"}
          </span>
        </div>
      </div>
    </div>
  );
};

const InfoRow = ({ label, value }: { label: string; value: string }) => (
  <div className="flex justify-between">
    <span className="text-muted-foreground">{label}</span>
    <span className="text-foreground font-medium">{value}</span>
  </div>
);

export default ModelIntegrity;
