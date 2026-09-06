import { useState, useEffect, useCallback, useRef } from "react";
import {
  Card,
  Group,
  Text,
  Badge,
  Stack,
  Table,
  ScrollArea,
  Button,
  ActionIcon,
  Code,
  SimpleGrid,
  ThemeIcon,
  Progress,
  Switch,
  Alert,
  Modal,
  TextInput,
  Divider,
} from "@mantine/core";
import {
  IconGhost,
  IconShield,
  IconRadar,
  IconBrain,
  IconAlertTriangle,
  IconRefresh,
  IconEye,
  IconBolt,
  IconSkull,
  IconActivity,
  IconEyeOff,
} from "@tabler/icons-react";
import { labyrinthApi, type LabyrinthStatus } from "../api-sentinel";

const STATE_COLORS: Record<string, string> = {
  idle: "gray",
  arming: "blue",
  active: "green",
  engaged: "orange",
  eroding: "red",
  post_incident: "violet",
};

const STATE_LABELS: Record<string, string> = {
  idle: "IDLE",
  arming: "ARMING",
  active: "ARMED",
  engaged: "ENGAGED",
  eroding: "ERODING",
  post_incident: "POST-INCIDENT",
};

export default function LabyrinthPage() {
  const [status, setStatus] = useState<LabyrinthStatus | null>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [attackers, setAttackers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [arming, setArming] = useState(false);
  const [feedConnected, setFeedConnected] = useState(false);
  const [liveLog, setLiveLog] = useState<string[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, l, a] = await Promise.all([
        labyrinthApi.status(),
        labyrinthApi.logs(30),
        labyrinthApi.attackers(),
      ]);
      // API returns {labyrinth: {...}, attackers: [...], ...} — extract the nested status
      const sData = s as any;
      setStatus((sData.labyrinth || sData) as LabyrinthStatus);
      setLogs((l as any).logs || []);
      setAttackers((a as any).attackers || []);
    } catch (e) {
      console.error("Labyrinth refresh failed:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 10000);

    // SSE feed
    const es = new EventSource(labyrinthApi.feedUrl);
    es.onopen = () => setFeedConnected(true);
    es.onerror = () => setFeedConnected(false);
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === "log") {
          setLiveLog((prev) => [data.message, ...prev].slice(0, 30));
        }
      } catch {}
    };
    eventSourceRef.current = es;

    return () => {
      clearInterval(interval);
      es.close();
    };
  }, [refresh]);

  const handleArm = async () => {
    setArming(true);
    try {
      await labyrinthApi.arm(1.0);
      refresh();
    } catch (e) {
      console.error("Arm failed:", e);
    } finally {
      setArming(false);
    }
  };

  const handleDisarm = async () => {
    try {
      await labyrinthApi.disarm();
      refresh();
    } catch (e) {
      console.error("Disarm failed:", e);
    }
  };

  const state = status?.state || "idle";
  const stateColor = STATE_COLORS[state] || "gray";
  const isArmed = state === "active" || state === "engaged" || state === "eroding";

  return (
    <Stack gap="md">
      {/* ── Header ── */}
      <Group justify="space-between" align="center">
        <Group gap="md">
          <ThemeIcon size={42} radius="md" color={stateColor} variant="light">
            <IconGhost size={26} />
          </ThemeIcon>
          <div>
            <Text size="xl" fw={900} className="pitbull-display" c={stateColor}>
              LABYRINTH
            </Text>
            <Text size="xs" c="dimmed">Ephemeral cognitive deception architecture</Text>
          </div>
        </Group>
        <Group gap="md">
          <Badge
            size="lg"
            color={feedConnected ? "green" : "gray"}
            variant="dot"
            styles={{ root: { background: "transparent", border: `1px solid var(--pitbull-border)` } }}
          >
            {feedConnected ? "LIVE" : "OFFLINE"}
          </Badge>
          <Badge size="lg" color={stateColor} variant="filled">
            {STATE_LABELS[state] || state.toUpperCase()}
          </Badge>
          <ActionIcon onClick={refresh} variant="subtle" color="cyan" size="lg">
            <IconRefresh size={18} />
          </ActionIcon>
        </Group>
      </Group>

      {/* ── Control Panel ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group justify="space-between" align="center">
          <Group gap="md">
            <Switch
              checked={isArmed}
              onChange={(e) => e.target.checked ? handleArm() : handleDisarm()}
              disabled={arming || state === "arming"}
              label={isArmed ? "System Armed" : "System Disarmed"}
              color={isArmed ? "green" : "gray"}
              size="md"
            />
            {arming && <Text size="xs" c="blue">Generating MirrorGraph...</Text>}
          </Group>
          <Group gap="sm">
            {!isArmed ? (
              <Button
                leftSection={<IconShield size={16} />}
                color="green"
                variant="light"
                onClick={handleArm}
                loading={arming}
              >
                Arm Labyrinth
              </Button>
            ) : (
              <Button
                leftSection={<IconBolt size={16} />}
                color="red"
                variant="light"
                onClick={handleDisarm}
              >
                Disarm
              </Button>
            )}
          </Group>
        </Group>
      </Card>

      {/* ── Stats Grid ── */}
      <SimpleGrid cols={5} spacing="sm">
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconRadar size={18} color="var(--pitbull-cyan)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">MIRROR NODES</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.mirror_nodes || 0}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconActivity size={18} color="var(--pitbull-amber)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">TRACKED</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.attackers_tracked || 0}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconSkull size={18} color="var(--pitbull-red)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">FAKE SUCCESSES</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.fake_successes_served || 0}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconEyeOff size={18} color="var(--pitbull-violet)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">DEAD ENDS</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.dead_ends_served || 0}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconBrain size={18} color="var(--pitbull-red)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">CONFIDENCE CRISES</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.confidence_crises_detected || 0}</Text>
            </div>
          </Group>
        </Card>
      </SimpleGrid>

      {/* ── Engagement Alert ── */}
      {state === "engaged" && (
        <Alert color="orange" variant="light" icon={<IconAlertTriangle size={18} />}>
          <Text size="sm" fw={600}>ATTACKER ENGAGED WITH MIRROR GRAPH</Text>
          <Text size="xs" c="dimmed">
            {status?.active_attackers || 0} attacker(s) interacting with fake infrastructure.
            Epistemic erosion engine active.
          </Text>
        </Alert>
      )}

      {state === "eroding" && (
        <Alert color="red" variant="light" icon={<IconBrain size={18} />}>
          <Text size="sm" fw={600}>EPISTEMIC EROSION IN PROGRESS</Text>
          <Text size="xs" c="dimmed">
            Attacker confidence being systematically degraded. Dead-end cascades deployed.
          </Text>
        </Alert>
      )}

      {/* ── Live Log Stream ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group gap="xs" mb="sm">
          <span className="pitbull-pulse-dot" style={{ color: isArmed ? "var(--pitbull-green)" : "var(--pitbull-dimmed)" }} />
          <Text size="sm" fw={700} c="cyan" className="pitbull-display">SYSTEM LOG</Text>
        </Group>
        <ScrollArea h={200}>
          <Stack gap={2}>
            {liveLog.length > 0 ? liveLog.map((line, i) => (
              <Text key={i} size="xs" className="pitbull-mono" c="dimmed">
                {line}
              </Text>
            )) : logs.map((log, i) => (
              <Text key={i} size="xs" className="pitbull-mono" c="dimmed">
                [{log.timestamp}] {log.level}: {log.message}
              </Text>
            ))}
            {!liveLog.length && logs.length === 0 && (
              <Text size="xs" c="dimmed" ta="center" py="md">System idle — arm to begin</Text>
            )}
          </Stack>
        </ScrollArea>
      </Card>

      {/* ── Tracked Attackers ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group justify="space-between" mb="sm">
          <Text size="sm" fw={700} c="red" className="pitbull-display">TRACKED ATTACKERS</Text>
          <Badge size="xs" variant="light">{attackers.length}</Badge>
        </Group>
        <ScrollArea h={250}>
          <Table striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>IP</Table.Th>
                <Table.Th>First Seen</Table.Th>
                <Table.Th>Confidence</Table.Th>
                <Table.Th>Phase</Table.Th>
                <Table.Th>Recon Types</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {attackers.map((a, i) => (
                <Table.Tr key={i}>
                  <Table.Td>
                    <Text size="xs" className="pitbull-mono" c="red">{a.source_ip || a.ip}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed">{a.first_seen ? new Date(a.first_seen).toLocaleTimeString() : "—"}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      <Progress
                        value={(a.estimated_confidence || a.confidence || 0) * 100}
                        color={(a.estimated_confidence || a.confidence || 0) > 0.7 ? "green" : (a.estimated_confidence || a.confidence || 0) > 0.4 ? "yellow" : "red"}
                        size="sm"
                        style={{ width: 80 }}
                      />
                      <Text size="xs" className="pitbull-mono">{((a.estimated_confidence || a.confidence || 0) * 100).toFixed(0)}%</Text>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Badge size="xs" color={a.threat_level === "critical" ? "red" : a.threat_level === "suspicious" ? "yellow" : "blue"} variant="light">
                      {a.threat_level || "normal"}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {(a.tools_detected || a.recon_types || []).map((r: string) => (
                        <Badge key={r} size="xs" variant="light" color="orange">{r}</Badge>
                      ))}
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
              {attackers.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text size="xs" c="dimmed" ta="center" py="md">No attackers tracked</Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Card>

      {/* ── 5 Pillars Overview ── */}
      <SimpleGrid cols={5} spacing="sm">
        {[
          { icon: IconRadar, name: "MirrorGraph", desc: "Fake infrastructure", color: "cyan" },
          { icon: IconShield, name: "Validator", desc: "Consistency check", color: "green" },
          { icon: IconEye, name: "Recon Detector", desc: "Attack detection", color: "yellow" },
          { icon: IconBrain, name: "Erosion Engine", desc: "Confidence drain", color: "red" },
          { icon: IconGhost, name: "Hypergame", desc: "Path steering", color: "violet" },
        ].map((p) => (
          <Card key={p.name} withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)", textAlign: "center" }}>
            <Stack gap={4} align="center">
              <ThemeIcon size={32} radius="md" color={p.color} variant="light">
                <p.icon size={18} />
              </ThemeIcon>
              <Text size="xs" fw={600}>{p.name}</Text>
              <Text size="xs" c="dimmed">{p.desc}</Text>
            </Stack>
          </Card>
        ))}
      </SimpleGrid>
    </Stack>
  );
}