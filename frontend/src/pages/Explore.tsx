import { useState, useEffect, useCallback, useRef } from "react";
import {
  Card,
  Stack,
  Text,
  TextInput,
  NumberInput,
  Select,
  Button,
  Group,
  Badge,
  ScrollArea,
  Divider,
  Loader,
  Code,
} from "@mantine/core";
import { IconRadar, IconTarget, IconPlayerPlay, IconRefresh } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api, ExploreRequest, Mission } from "../api";

const SCOPES = [
  { value: "surface", label: "Surface Web" },
  { value: "deep", label: "Deep Web" },
  { value: "darknet", label: "Darknet" },
  { value: "full", label: "Full Spectrum" },
];

export default function ExplorePage() {
  const [target, setTarget] = useState("");
  const [depth, setDepth] = useState(2);
  const [scope, setScope] = useState("surface");
  const [rateLimit, setRateLimit] = useState(500);
  const [missions, setMissions] = useState<Mission[]>([]);
  const [activeMission, setActiveMission] = useState<Mission | null>(null);
  const [starting, setStarting] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const refreshMissions = useCallback(async () => {
    try {
      const data = await api.listMissions();
      setMissions(data.missions);
      if (data.missions.length > 0) {
        const latest = data.missions[0];
        setActiveMission(await api.getMission(latest.id));
      }
    } catch {}
  }, []);

  useEffect(() => { refreshMissions(); }, [refreshMissions]);

  useEffect(() => {
    if (!activeMission || activeMission.status !== "running") return;
    const evtSource = new EventSource(`/api/v1/sse/mission/${activeMission.id}`);
    evtSource.addEventListener("log", (e) => {
      const data = JSON.parse(e.data);
      setActiveMission((prev) => prev ? { ...prev, logs: prev.logs.includes(data.message) ? prev.logs : [...prev.logs, data.message] } : prev);
    });
    evtSource.addEventListener("status", (e) => {
      const data = JSON.parse(e.data);
      setActiveMission((prev) => prev ? { ...prev, status: data.status, discoveries: data.discoveries } : prev);
    });
    evtSource.addEventListener("done", (e) => {
      const data = JSON.parse(e.data);
      setActiveMission((prev) => prev ? { ...prev, status: data.status } : prev);
      evtSource.close();
    });
    evtSource.addEventListener("error", () => { evtSource.close(); });
    return () => evtSource.close();
  }, [activeMission?.id]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [activeMission?.logs]);

  const handleStart = async () => {
    if (!target.trim()) {
      notifications.show({ message: "Enter a target domain", color: "red" });
      return;
    }
    setStarting(true);
    try {
      const req: ExploreRequest = { target: target.trim(), depth, scope, rate_limit_ms: rateLimit };
      const res = await api.startExploration(req);
      notifications.show({ title: "Mission Launched", message: res.message, color: "cyan", icon: <IconPlayerPlay size={18} /> });
      setTarget("");
      await refreshMissions();
      const mission = await api.getMission(res.exploration_id);
      setActiveMission(mission);
    } catch { notifications.show({ message: "Failed to start mission", color: "red" }); }
    setStarting(false);
  };

  const statusColor = (status: string) => status === "running" ? "cyan" : status === "completed" ? "green" : status === "failed" ? "red" : "gray";

  return (
    <Stack gap="lg" className="pitbull-fade-in">
      {/* Mission Control */}
      <Card withBorder padding="xl" radius="md" className="pitbull-stat-card">
        <Group mb="md">
          <IconRadar size={24} style={{ color: "var(--pitbull-cyan)", filter: "drop-shadow(0 0 8px var(--pitbull-cyan-glow))" }} />
          <Text fw={700} size="lg" className="pitbull-display" c="cyan.4">MISSION CONTROL</Text>
        </Group>
        <Group gap="md" align="flex-end">
          <TextInput
            label={<Text size="xs" c="dimmed" className="pitbull-display">TARGET DOMAIN</Text>}
            placeholder="example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            style={{ flex: 1 }}
            leftSection={<IconTarget size={16} />}
            onKeyDown={(e) => e.key === "Enter" && handleStart()}
            className="pitbull-mono"
          />
          <Select label={<Text size="xs" c="dimmed" className="pitbull-display">SCOPE</Text>} data={SCOPES} value={scope} onChange={(v) => v && setScope(v)} w={160} />
          <NumberInput label={<Text size="xs" c="dimmed" className="pitbull-display">DEPTH</Text>} value={depth} onChange={(v) => setDepth(Number(v) || 2)} min={1} max={5} w={80} />
          <NumberInput label={<Text size="xs" c="dimmed" className="pitbull-display">RATE</Text>} value={rateLimit} onChange={(v) => setRateLimit(Number(v) || 500)} min={100} max={5000} step={100} w={100} />
          <Button loading={starting} onClick={handleStart} leftSection={<IconPlayerPlay size={16} />} size="md" radius="md" className="pitbull-display">
            LAUNCH
          </Button>
        </Group>
      </Card>

      {/* Missions + Logs */}
      <Group gap="md" align="flex-start">
        {/* Mission List */}
        <Card withBorder padding="md" radius="md" style={{ width: 280 }} className="pitbull-stat-card">
          <Group justify="space-between" mb="sm">
            <Text fw={700} size="sm" className="pitbull-display" c="cyan.4">MISSIONS</Text>
            <Button size="xs" variant="subtle" onClick={refreshMissions} leftSection={<IconRefresh size={12} />}>Refresh</Button>
          </Group>
          <ScrollArea.Autosize mah={450}>
            <Stack gap="xs">
              {missions.length === 0 && <Text size="xs" c="dimmed" ta="center" py="lg">No missions yet</Text>}
              {missions.map((m) => (
                <Card key={m.id} withBorder padding="sm" radius="sm" onClick={() => setActiveMission(m)}
                  style={{ cursor: "pointer", background: activeMission?.id === m.id ? "rgba(34,211,238,0.08)" : "transparent", transition: "all 0.2s ease" }}>
                  <Group justify="space-between" mb={4}>
                    <Text size="xs" fw={600} className="pitbull-mono">{m.target}</Text>
                    <Badge size="xs" color={statusColor(m.status)} variant="light">{m.status}</Badge>
                  </Group>
                  <Text size="xs" c="dimmed" className="pitbull-mono">{m.discoveries} discoveries · {m.scope}</Text>
                </Card>
              ))}
            </Stack>
          </ScrollArea.Autosize>
        </Card>

        {/* Terminal Logs */}
        <Card withBorder padding="lg" radius="md" style={{ flex: 1 }} className="pitbull-stat-card">
          {!activeMission ? (
            <Stack align="center" justify="center" h={450} gap="sm">
              <IconRadar size={48} style={{ color: "var(--pitbull-text-dim)", opacity: 0.4 }} />
              <Text c="dimmed" size="sm">No mission selected</Text>
              <Text size="xs" c="dimmed" style={{ opacity: 0.6 }}>Launch an exploration or select a mission</Text>
            </Stack>
          ) : (
            <Stack gap="sm">
              <Group justify="space-between">
                <Stack gap={2}>
                  <Text fw={700} className="pitbull-mono" c="cyan.4">{activeMission.target}</Text>
                  <Group gap="xs">
                    <Badge size="xs" color={statusColor(activeMission.status)} variant="light">{activeMission.status}</Badge>
                    <Badge size="xs" variant="light">{activeMission.scope}</Badge>
                    <Badge size="xs" variant="light" color="cyan">{activeMission.depth} depth</Badge>
                    <Text size="xs" c="dimmed" className="pitbull-mono">{activeMission.discoveries} discoveries</Text>
                  </Group>
                </Stack>
                {activeMission.status === "running" && <Loader size="sm" color="cyan" />}
              </Group>

              <div className="pitbull-divider" />

              <Text size="xs" c="dimmed" className="pitbull-display">MISSION LOG</Text>
              <div className="pitbull-terminal" ref={logRef} style={{ maxHeight: 400 }}>
                <Stack gap={1}>
                  {activeMission.logs.map((log, i) => (
                    <Text key={i} size="xs" className="pitbull-mono" style={{
                      color: log.includes("❌") ? "var(--pitbull-red)" :
                             log.includes("✅") ? "var(--pitbull-green)" :
                             log.includes("🧠") || log.includes("💭") ? "var(--pitbull-violet)" :
                             log.includes("🔍") || log.includes("🧭") ? "var(--pitbull-cyan)" :
                             log.includes("⚠️") ? "var(--pitbull-amber)" :
                             log.includes("🔮") ? "var(--pitbull-blue)" :
                             log.includes("🚨") ? "var(--pitbull-red)" :
                             "var(--pitbull-text-dim)",
                      lineHeight: 1.6, whiteSpace: "pre-wrap",
                    }}>
                      {log}
                    </Text>
                  ))}
                  {activeMission.logs.length === 0 && <Text size="xs" c="dimmed" className="pitbull-mono">Waiting for logs...</Text>}
                </Stack>
              </div>
            </Stack>
          )}
        </Card>
      </Group>
    </Stack>
  );
}