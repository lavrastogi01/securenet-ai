import Header from "@/components/Header";
import { Upload as UploadIcon, FileText, X, Zap } from "lucide-react";
import { useRef, useState } from "react";
import { uploadDetect, type UploadResult } from "@/services/api";
import { toast } from "sonner";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";

const CATEGORY_COLORS: Record<string, string> = {
  Normal: "hsl(var(--success))",
  DoS: "hsl(var(--destructive))",
  Probe: "hsl(var(--warning))",
  R2L: "hsl(var(--primary))",
  U2R: "hsl(280 80% 60%)",
  Uncertain: "hsl(var(--muted-foreground))",
};

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "text-destructive", HIGH: "text-warning", MEDIUM: "text-foreground", LOW: "text-success",
};

const STATUS_BADGE: Record<string, string> = {
  Blocked: "badge-critical", Mitigated: "badge-high",
  Quarantined: "badge-medium", Passed: "badge-success",
};

const UploadDetect = () => {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [history, setHistory] = useState<UploadResult[]>([]);
  const [running, setRunning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const onFile = (f: File | null) => { setFile(f); setResult(null); };

  const run = async () => {
    if (!file) { toast.error("Select a file first"); return; }
    setRunning(true);
    const r = await uploadDetect(file);
    setRunning(false);
    if (r) {
      setResult(r);
      setHistory((prev) => [r, ...prev].slice(0, 20));
      toast.success(`Detected: ${r.primary_attack}`);
    } else {
      toast.error("Detection failed");
    }
  };

  const downloadReport = () => {
    if (!result) return;
    const report = {
      generated_at: new Date().toISOString(),
      ...result,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `forensic-report-${result.file}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <Header title="Upload & Detect" subtitle="Session: SN-AI-8832-X" />
      <div className="p-6 space-y-6">
        <div>
          <h1 className="page-title flex items-center gap-2">
            <UploadIcon className="w-6 h-6 text-primary" /> Upload & Detect
          </h1>
          <p className="page-subtitle max-w-2xl">
            Deep packet inspection and behavioral analysis. Upload network logs for instantaneous intrusion identification across enterprise nodes.
          </p>
        </div>

        <div className="grid grid-cols-5 gap-6">
          <div className="col-span-3 space-y-4">
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => { e.preventDefault(); if (e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0]); }}
              onClick={() => inputRef.current?.click()}
              className="border-2 border-dashed border-primary/30 rounded-xl p-12 flex flex-col items-center justify-center hover:border-primary/50 transition-colors cursor-pointer"
            >
              <div className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center mb-4">
                <UploadIcon className="w-7 h-7 text-primary" />
              </div>
              <p className="text-lg font-semibold text-foreground">Drop your file here</p>
              <p className="text-sm text-muted-foreground mt-1">
                Accepting <span className="text-primary">CSV</span>, <span className="text-primary">PCAP</span>, <span className="text-primary">LOG</span> formats
              </p>
              <button className="mt-4 px-6 py-2 rounded-lg border border-primary text-primary text-sm font-medium hover:bg-primary/10 transition-colors">
                Select File
              </button>
              <input
                ref={inputRef}
                type="file"
                accept=".csv,.pcap,.pcapng,.log,.txt"
                onChange={(e) => onFile(e.target.files?.[0] || null)}
                className="hidden"
              />
            </div>

            {file && (
              <div className="section-card flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <FileText className="w-5 h-5 text-primary" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">{file.name}</p>
                  <p className="text-xs text-muted-foreground">
                    SIZE: <span className="text-foreground">{(file.size / 1024).toFixed(1)} KB</span>
                  </p>
                </div>
                <button onClick={() => onFile(null)} className="text-muted-foreground hover:text-foreground">
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}

            <div className="flex gap-3">
              <button onClick={() => onFile(null)} className="px-6 py-2.5 rounded-lg bg-secondary text-secondary-foreground text-sm font-medium">
                Clear Selection
              </button>
              <button
                onClick={run}
                disabled={!file || running}
                className="flex-1 flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-bold uppercase tracking-wider disabled:opacity-50"
              >
                <Zap className="w-4 h-4" /> {running ? "Analyzing…" : "Run Intrusion Detection"}
              </button>
            </div>
          </div>

          <div className="col-span-2 section-card cyber-glow">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-primary">Detection Results</h3>
              {result && (
                <span className={STATUS_BADGE[result.status] || "badge-info"}>
                  {result.primary_attack === "Normal" ? "No Threat" : "Threat Detected"}
                </span>
              )}
            </div>
            {result ? (
              <>
                <div className="text-center py-4">
                  <p className={`text-4xl font-black ${RISK_COLOR[result.risk] || "text-foreground"}`}>
                    {result.primary_attack}
                  </p>
                  <p className="text-xs uppercase tracking-widest text-muted-foreground mt-1">Identified Attack Type</p>
                </div>
                <div className="grid grid-cols-2 gap-3 my-4">
                  <div className="bg-secondary rounded-lg p-3 text-center">
                    <p className="text-[10px] uppercase text-muted-foreground">Confidence</p>
                    <p className="text-xl font-bold text-foreground font-mono">{result.confidence}%</p>
                  </div>
                  <div className="bg-secondary rounded-lg p-3 text-center">
                    <p className="text-[10px] uppercase text-muted-foreground">Risk Level</p>
                    <p className={`text-xl font-bold ${RISK_COLOR[result.risk]}`}>{result.risk}</p>
                  </div>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between"><span className="text-muted-foreground">Source IP</span><span className="font-mono text-foreground">{result.source_ip}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Destination</span><span className="font-mono text-foreground">{result.destination_ip}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Rows analyzed</span><span className="text-foreground">{result.rows_analyzed}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Time to Detect</span><span className="text-foreground">{result.time_to_detect}s</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Status</span><span className="text-foreground">{result.status}</span></div>
                </div>
                <button onClick={downloadReport} className="w-full mt-5 py-2.5 rounded-lg border border-primary text-primary text-sm font-medium hover:bg-primary/10 transition-colors">
                  Download Full Forensic Report
                </button>
              </>
            ) : (
              <p className="text-sm text-muted-foreground text-center py-12">Upload a file and run detection to see results.</p>
            )}
          </div>
        </div>

        {result && result.category_counts && Object.keys(result.category_counts).length > 0 && (
          <div className="grid grid-cols-5 gap-6">
            <div className="col-span-2 section-card">
              <h3 className="text-base font-semibold text-foreground mb-4">Attack Distribution</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={Object.entries(result.category_counts).map(([name, value]) => ({ name, value }))}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={50}
                      outerRadius={90}
                      paddingAngle={2}
                    >
                      {Object.keys(result.category_counts).map((k) => (
                        <Cell key={k} fill={CATEGORY_COLORS[k] || "hsl(var(--muted))"} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }} />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="col-span-3 section-card">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-semibold text-foreground">Per-Row Detections</h3>
                <span className="text-xs text-muted-foreground">{result.per_row?.length || 0} rows</span>
              </div>
              <div className="max-h-64 overflow-auto">
                <table className="data-table">
                  <thead><tr><th>#</th><th>Attack</th><th>Confidence</th><th>Risk</th><th>Source</th><th>Destination</th></tr></thead>
                  <tbody>
                    {(result.per_row || []).slice(0, 200).map((r, i) => (
                      <tr key={i}>
                        <td className="text-muted-foreground font-mono text-xs">{i + 1}</td>
                        <td><span className="font-medium" style={{ color: CATEGORY_COLORS[r.label] }}>{r.label}</span></td>
                        <td className="font-mono">{r.confidence}%</td>
                        <td className={RISK_COLOR[r.risk]}>{r.risk}</td>
                        <td className="font-mono text-xs">{r.source_ip}</td>
                        <td className="font-mono text-xs">{r.destination_ip}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        <div className="section-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-foreground">Scan History</h3>
            <span className="text-xs text-muted-foreground">{history.length} scans</span>
          </div>
          <table className="data-table">
            <thead><tr><th>Timestamp</th><th>File Name</th><th>Aggregated Counts</th><th>Primary</th><th>Risk</th></tr></thead>
            <tbody>
              {history.length === 0 && (
                <tr><td colSpan={5} className="text-center text-muted-foreground py-6">No scans yet</td></tr>
              )}
              {history.map((row, i) => (
                <tr key={i}>
                  <td className="text-muted-foreground font-mono text-xs">{new Date(row.timestamp).toLocaleString()}</td>
                  <td className="text-foreground font-medium">{row.file}</td>
                  <td className="text-xs">
                    {Object.entries(row.category_counts || {}).map(([k, v]) => (
                      <span key={k} className="mr-2" style={{ color: CATEGORY_COLORS[k] }}>{v} {k}</span>
                    ))}
                  </td>
                  <td><span className={STATUS_BADGE[row.status] || "badge-info"}>{row.primary_attack}</span></td>
                  <td className={RISK_COLOR[row.risk]}>{row.risk}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UploadDetect;
