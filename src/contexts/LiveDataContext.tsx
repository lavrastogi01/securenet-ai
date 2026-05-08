import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from "react";
import {
  fetchLogs, fetchNotifications, fetchStats, fetchSettings, updateSettings,
  type PredictionResult, type NotificationItem, type StatsResponse, type AppSettings,
} from "@/services/api";

// Negative counter for client-generated notification IDs so they never
// collide with the server's positive integer IDs.
let _clientNotifSeq = -1;

interface LiveDataContextType {
  logs: PredictionResult[];
  stats: StatsResponse | null;
  settings: AppSettings | null;
  notifications: NotificationItem[];
  unreadCount: number;
  markNotificationsRead: () => void;
  saveSettings: (patch: Partial<AppSettings>) => Promise<void>;
}

const LiveDataContext = createContext<LiveDataContextType | null>(null);

const DEFAULT_INTERVAL = 5000;

export const LiveDataProvider = ({ children }: { children: React.ReactNode }) => {
  const [logs, setLogs] = useState<PredictionResult[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [readUntil, setReadUntil] = useState<number>(0);

  const lastLogIdRef = useRef(0);
  const lastNotifIdRef = useRef(0);

  const tick = useCallback(async () => {
    const [logsRes, notifRes, statsRes] = await Promise.all([
      fetchLogs(lastLogIdRef.current, 200),
      fetchNotifications(lastNotifIdRef.current),
      fetchStats(),
    ]);
    const RISK_LEVEL: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    const threshold = RISK_LEVEL[settings?.alert_threshold || "HIGH"] ?? 2;

    if (logsRes.logs.length) {
      lastLogIdRef.current = Math.max(lastLogIdRef.current, logsRes.last_id);
      // Client-side notification fallback (works even if /notifications fails)
      const derivedNotifs: NotificationItem[] = logsRes.logs
        .filter((l) => (RISK_LEVEL[l.risk] ?? 0) >= threshold)
        .map((l) => ({
          id: l.id ?? _clientNotifSeq--,
          timestamp: l.timestamp,
          source_ip: l.source_ip,
          prediction: l.prediction,
          risk: l.risk,
          message: `${l.risk} ${l.prediction} from ${l.source_ip || "unknown"}`,
        }));
      setLogs((prev) => {
        const merged = [...logsRes.logs, ...prev];
        const seen = new Set<number>();
        const out: PredictionResult[] = [];
        for (const l of merged) {
          const key = l.id ?? -1;
          if (key >= 0 && seen.has(key)) continue;
          if (key >= 0) seen.add(key);
          out.push(l);
          if (out.length >= 500) break;
        }
        return out;
      });
      if (derivedNotifs.length) {
        setNotifications((prev) => {
          const seen = new Set(prev.map((n) => n.id));
          const fresh = derivedNotifs.filter((n) => !seen.has(n.id));
          return [...fresh, ...prev].slice(0, 50);
        });
      }
    }
    if (notifRes.notifications.length) {
      lastNotifIdRef.current = Math.max(lastNotifIdRef.current, notifRes.last_id);
      setNotifications((prev) => {
        const seen = new Set(prev.map((n) => n.id));
        const fresh = notifRes.notifications.reverse().filter((n) => !seen.has(n.id));
        return [...fresh, ...prev].slice(0, 50);
      });
    }
    if (statsRes) setStats(statsRes);
  }, [settings?.alert_threshold]);

  // Keep a stable ref to the latest tick so the polling interval does NOT
  // restart every time alert_threshold changes (which would cause a spurious
  // immediate double-poll on settings load).
  const tickRef = useRef(tick);
  useEffect(() => { tickRef.current = tick; }, [tick]);

  // Poll using current refresh_interval — only restarts when the interval value changes
  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (!cancelled) await tickRef.current();
    };
    run();
    const interval = (settings?.refresh_interval || 5) * 1000 || DEFAULT_INTERVAL;
    const id = setInterval(run, interval);
    return () => { cancelled = true; clearInterval(id); };
  }, [settings?.refresh_interval]);

  // Load settings once
  useEffect(() => {
    fetchSettings().then((s) => s && setSettings(s));
  }, []);

  const saveSettings = useCallback(async (patch: Partial<AppSettings>) => {
    const updated = await updateSettings(patch);
    if (updated) setSettings(updated);
  }, []);

  const markNotificationsRead = useCallback(() => {
    setReadUntil(notifications[0]?.id ?? lastNotifIdRef.current);
  }, [notifications]);

  const unreadCount = notifications.filter((n) => n.id > readUntil || n.id < 0).length;

  return (
    <LiveDataContext.Provider value={{
      logs, stats, settings, notifications, unreadCount,
      markNotificationsRead, saveSettings,
    }}>
      {children}
    </LiveDataContext.Provider>
  );
};

export const useLiveData = () => {
  const ctx = useContext(LiveDataContext);
  if (!ctx) throw new Error("useLiveData must be inside LiveDataProvider");
  return ctx;
};
