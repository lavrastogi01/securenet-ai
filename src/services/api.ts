const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:5000";

export interface PredictionResult {
  id?: number;
  prediction: string;
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  timestamp: string;
  source_ip?: string;
  destination_ip?: string;
  confidence?: number;
  raw_label?: string;
  src_bytes?: number;
  dst_bytes?: number;
  protocol?: string;
  service?: string;
  flag?: string;
  dst_port?: number;
  origin?: string;
  source?: string;
  status?: string;
}

export interface UploadRowDetection {
  label: string;
  confidence: number;
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  source_ip: string;
  destination_ip: string;
}

export interface UploadResult {
  file: string;
  size_bytes: number;
  rows_analyzed: number;
  primary_attack: string;
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: string;
  confidence: number;
  source_ip: string;
  destination_ip: string;
  time_to_detect: number;
  category_counts: Record<string, number>;
  per_row?: UploadRowDetection[];
  timestamp: string;
}

export interface ModelSecurityResponse {
  model_integrity: string;
  model_version: string;
  adversarial_inputs: number;
  low_confidence_pct: number;
  predictions_per_min: number;
  average_confidence: number;
  poisoning_suspects: number;
  confidence_distribution: { bin: string; val: number }[];
  suspicious_frequency: { t: string; val: number }[];
}

export interface NotificationItem {
  id: number;
  timestamp: string;
  source_ip?: string;
  prediction: string;
  risk: string;
  message: string;
}

export interface StatsResponse {
  total_predictions: number;
  protocols: { name: string; pct: number; count: number }[];
  attacks: Record<string, number>;
  origins: Record<string, number>;
  anomalies: { id: number; type: string; source_ip?: string; timestamp: string }[];
  timeline: { time: string; value: number }[];
  mode: "dataset" | "scapy";
  scapy_available: boolean;
}

export interface AppSettings {
  mode: "dataset" | "scapy";
  refresh_interval: number;
  alert_threshold: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  username: string;
  scapy_available: boolean;
}

export async function login(username: string, password: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (res.ok) {
      const data = await res.json();
      return data.success;
    }
  } catch { /* ignore */ }
  return false;
}

export async function fetchPrediction(): Promise<PredictionResult> {
  try {
    const res = await fetch(`${API_BASE}/predict`);
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  return generateDemoPrediction();
}

export async function fetchLogs(sinceId = 0, limit = 100): Promise<{ logs: PredictionResult[]; last_id: number }> {
  try {
    const res = await fetch(`${API_BASE}/logs?since_id=${sinceId}&limit=${limit}`);
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  // Fallback: synthesize one prediction
  const demo = generateDemoPrediction();
  demo.id = sinceId + 1;
  return { logs: [demo], last_id: demo.id! };
}

export async function fetchNotifications(sinceId = 0): Promise<{ notifications: NotificationItem[]; last_id: number }> {
  try {
    const res = await fetch(`${API_BASE}/notifications?since_id=${sinceId}`);
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  return { notifications: [], last_id: sinceId };
}

export async function fetchStats(): Promise<StatsResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  return null;
}

export async function fetchSettings(): Promise<AppSettings | null> {
  try {
    const res = await fetch(`${API_BASE}/settings`);
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  return null;
}

export async function updateSettings(patch: Partial<AppSettings>): Promise<AppSettings | null> {
  try {
    const res = await fetch(`${API_BASE}/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  return null;
}

// ─── Demo fallback (backend offline) ─────────────────
const attackTypes = ["Normal", "DoS", "Probe", "R2L", "U2R", "Uncertain"];
const riskMap: Record<string, PredictionResult["risk"]> = {
  Normal: "LOW", DoS: "CRITICAL", Probe: "MEDIUM", R2L: "HIGH", U2R: "CRITICAL", Uncertain: "MEDIUM",
};
const ips = ["192.168.1.44", "45.233.12.102", "10.0.0.12", "172.16.254.1", "88.192.4.15", "203.0.113.50"];
const protos = ["tcp", "udp", "icmp"];

let _demoCursor = 0;
function generateDemoPrediction(): PredictionResult {
  // Rotate deterministically through all 5 categories so every one appears,
  // then add some randomness so it doesn't feel scripted.
  const rotation = ["Normal", "Normal", "DoS", "Probe", "Normal", "R2L", "Normal", "DoS", "U2R", "Probe"];
  const type = Math.random() < 0.7
    ? rotation[_demoCursor++ % rotation.length]
    : attackTypes[Math.floor(Math.random() * attackTypes.length)];
  return {
    prediction: type,
    risk: riskMap[type],
    timestamp: new Date().toISOString(),
    source_ip: ips[Math.floor(Math.random() * ips.length)],
    confidence: Math.floor(Math.random() * 25) + 75,
    src_bytes: Math.floor(Math.random() * 50000),
    dst_bytes: Math.floor(Math.random() * 50000),
    protocol: protos[Math.floor(Math.random() * protos.length)],
    service: "http",
    flag: "SF",
  };
}

export async function uploadDetect(file: File): Promise<UploadResult | null> {
  try {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${API_BASE}/upload`, { method: "POST", body: fd });
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  // Demo fallback
  const types = ["DoS", "Probe", "SQL Injection", "XSS", "Brute Force", "Port Scan"];
  const primary = types[Math.floor(Math.random() * types.length)];
  return {
    file: file.name,
    size_bytes: file.size,
    rows_analyzed: 1,
    primary_attack: primary,
    risk: "HIGH",
    status: "Mitigated",
    confidence: 90 + Math.random() * 9,
    source_ip: "192.168.1.104",
    destination_ip: "10.0.0.5",
    time_to_detect: 1.2,
    category_counts: { [primary]: 1 },
    timestamp: new Date().toISOString(),
  };
}

export async function fetchModelSecurity(): Promise<ModelSecurityResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/model-security`);
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  return null;
}

export interface IntegrityResponse {
  file_name: string;
  version: string;
  size_bytes: number;
  sha256: string;
  expected_sha256: string;
  matched: boolean;
  status: string;
  last_check: string;
  drift_pct: number;
  weight_histogram: number[];
  activity: { event: string; timestamp: string; status: string }[];
  model_loaded: boolean;
}

export async function fetchIntegrity(): Promise<IntegrityResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/integrity`);
    if (res.ok) return res.json();
  } catch { /* ignore */ }
  return null;
}
