import { useEffect, useState } from "react";
import { useLiveData } from "@/contexts/LiveDataContext";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";

interface Props { open: boolean; onOpenChange: (v: boolean) => void; }

const SettingsDialog = ({ open, onOpenChange }: Props) => {
  const { settings, saveSettings } = useLiveData();
  const [mode, setMode] = useState<"dataset" | "scapy">("dataset");
  const [refresh, setRefresh] = useState(5);
  const [threshold, setThreshold] = useState<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">("HIGH");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (settings) {
      setMode(settings.mode);
      setRefresh(settings.refresh_interval);
      setThreshold(settings.alert_threshold);
      setUsername(settings.username);
    }
  }, [settings, open]);

  const onSave = async () => {
    setSaving(true);
    const patch: Record<string, unknown> = {
      mode, refresh_interval: refresh, alert_threshold: threshold, username,
    };
    if (password) patch.password = password;
    await saveSettings(patch);
    setSaving(false);
    setPassword("");
    toast.success("Settings updated");
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>Configure capture mode, alerts and credentials.</DialogDescription>
        </DialogHeader>
        <div className="space-y-5 py-2">
          <div className="flex items-center justify-between">
            <div>
              <Label htmlFor="mode-toggle" className="text-sm font-medium">Live Scapy capture</Label>
              <p className="text-xs text-muted-foreground">Off = NSL-KDD dataset simulation</p>
              {settings && !settings.scapy_available && (
                <p className="text-xs text-destructive mt-1">Scapy not available on backend</p>
              )}
            </div>
            <Switch
              id="mode-toggle"
              checked={mode === "scapy"}
              onCheckedChange={(v) => setMode(v ? "scapy" : "dataset")}
              disabled={!!settings && !settings.scapy_available}
            />
          </div>

          <div>
            <Label className="text-sm">Refresh interval (seconds)</Label>
            <Input type="number" min={1} max={60} value={refresh}
              onChange={(e) => setRefresh(Number(e.target.value))} className="mt-1.5" />
          </div>

          <div>
            <Label className="text-sm">Alert threshold</Label>
            <Select value={threshold} onValueChange={(v) => setThreshold(v as typeof threshold)}>
              <SelectTrigger className="mt-1.5"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="LOW">LOW (notify all)</SelectItem>
                <SelectItem value="MEDIUM">MEDIUM and above</SelectItem>
                <SelectItem value="HIGH">HIGH and above</SelectItem>
                <SelectItem value="CRITICAL">CRITICAL only</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-sm">Username</Label>
              <Input value={username} onChange={(e) => setUsername(e.target.value)} className="mt-1.5" />
            </div>
            <div>
              <Label className="text-sm">New password</Label>
              <Input type="password" placeholder="leave blank to keep" value={password}
                onChange={(e) => setPassword(e.target.value)} className="mt-1.5" />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={onSave} disabled={saving}>{saving ? "Saving…" : "Save changes"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default SettingsDialog;
