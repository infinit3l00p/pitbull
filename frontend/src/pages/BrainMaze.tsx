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
  Alert,
  Modal,
  TextInput,
  Select,
  Textarea,
  Divider,
  RingProgress,
  Center,
} from "@mantine/core";
import {
  IconBrain,
  IconAlertTriangle,
  IconRefresh,
  IconGhost,
  IconSkull,
  IconClock,
  IconEyeOff,
  IconUserBolt,
  IconBug,
  IconDatabase,
  IconFileInfo,
  IconGitBranch,
  IconNetwork,
  IconTerminal,
  IconCalendarClock,
  IconBolt,
  IconWaveSine,
} from "@tabler/icons-react";
import { brainmazeApi, type BrainMazeStatus, type ConfusionHistory, type BrainMazeAnalytics } from "../api-brainmaze";

const PHASE_COLORS: Record<string, string> = {
  passive: "gray",
  trails: "cyan",
  wasters: "blue",
  paranoia: "violet",
  personas: "orange",
  max_confusion: "red",
};

const PHASE_LABELS: Record<string, string> = {
  passive: "PASSIVE",
  trails: "FALSE TRAILS",
  wasters: "TIME WASTERS",
  paranoia: "PARANOIA",
  personas: "PERSONAS",
  max_confusion: "MAX CONFUSION",
};

const TRAIL_TYPES = [
  { value: "dns", label: "DNS Records" },
  { value: "credentials", label: "Credentials" },
  { value: "history", label: "Bash History" },
  { value: "config", label: "Config Files" },
  { value: "users", label: "Users (/etc/passwd)" },
];

const PARANOIA_TYPES = [
  { value: "logs", label: "Attacker Logs" },
  { value: "sessions", label: "Session Indicators" },
  { value: "network", label: "Network Connections" },
  { value: "processes", label: "Process List" },
  { value: "crontab", label: "Crontab (Persistence)" },
];

const WASTER_TYPES = [
  { value: "database", label: "Database Dump" },
  { value: "filesystem", label: "Filesystem Listing" },
  { value: "api_docs", label: "API Documentation" },
  { value: "source_code", label: "Source Code" },
  { value: "git_repo", label: "Git Repository" },
];

const PERSONA_TYPES = [
  { value: "confused_sysadmin", label: "Confused Sysadmin (Dave)" },
  { value: "panicked_helpdesk", label: "Panicked Helpdesk (Sarah)" },
  { value: "incompetent_developer", label: "Incompetent Dev (Mike)" },
  { value: "another_hacker", label: "Another Hacker (r00t)" },
];

export default function BrainMazePage() {
  const [status, setStatus] = useState<BrainMazeStatus | null>(null);
  const [analytics, setAnalytics] = useState<BrainMazeAnalytics | null>(null);
  const [history, setHistory] = useState<ConfusionHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [feedConnected, setFeedConnected] = useState(false);
  const [liveLog, setLiveLog] = useState<string[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Modal state
  const [trailModalOpen, setTrailModalOpen] = useState(false);
  const [paranoiaModalOpen, setParanoiaModalOpen] = useState(false);
  const [wasterModalOpen, setWasterModalOpen] = useState(false);
  const [personaModalOpen, setPersonaModalOpen] = useState(false);
  const [chatModalOpen, setChatModalOpen] = useState(false);

  // Form state
  const [attackerIp, setAttackerIp] = useState("");
  const [trailType, setTrailType] = useState("credentials");
  const [paranoiaType, setParanoiaType] = useState("logs");
  const [wasterType, setWasterType] = useState("filesystem");
  const [personaType, setPersonaType] = useState("confused_sysadmin");
  const [personaInput, setPersonaInput] = useState("");
  const [personaResponse, setPersonaResponse] = useState("");
  const [personaLoading, setPersonaLoading] = useState(false);
  const [selectedAttackerIp, setSelectedAttackerIp] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([
        brainmazeApi.status(),
        brainmazeApi.analytics(),
      ]);
      setStatus(s as any);
      setAnalytics(a as any);
      if (selectedAttackerIp) {
        const h = await brainmazeApi.attackerHistory(selectedAttackerIp);
        setHistory(h as any);
      }
    } catch (e) {
      console.error("BrainMaze refresh failed:", e);
    } finally {
      setLoading(false);
    }
  }, [selectedAttackerIp]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 10000);

    // SSE feed
    const es = new EventSource(brainmazeApi.feedUrl);
    es.onopen = () => setFeedConnected(true);
    es.onerror = () => setFeedConnected(false);
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.message) {
          setLiveLog((prev) => [`[${data.level || "INFO"}] ${data.message}`, ...prev].slice(0, 30));
        }
      } catch {}
    };
    eventSourceRef.current = es;

    return () => {
      clearInterval(interval);
      es.close();
    };
  }, [refresh]);

  // ── Actions ──

  const handleGenerateTrail = async () => {
    if (!attackerIp) return;
    try {
      await brainmazeApi.trailsGenerate(attackerIp, trailType);
      setTrailModalOpen(false);
      refresh();
    } catch (e) {
      console.error("Trail generation failed:", e);
    }
  };

  const handleInjectParanoia = async () => {
    if (!attackerIp) return;
    try {
      await brainmazeApi.paranoiaInject(attackerIp, paranoiaType);
      setParanoiaModalOpen(false);
      refresh();
    } catch (e) {
      console.error("Paranoia injection failed:", e);
    }
  };

  const handleGenerateWaster = async () => {
    if (!attackerIp) return;
    try {
      await brainmazeApi.wastersGenerate(attackerIp, wasterType);
      setWasterModalOpen(false);
      refresh();
    } catch (e) {
      console.error("Time waster generation failed:", e);
    }
  };

  const handleSelectPersona = async () => {
    if (!attackerIp) return;
    try {
      await brainmazeApi.personaSelect(attackerIp, personaType);
      setPersonaModalOpen(false);
      refresh();
    } catch (e) {
      console.error("Persona selection failed:", e);
    }
  };

  const handlePersonaChat = async () => {
    if (!attackerIp || !personaInput) return;
    setPersonaLoading(true);
    try {
      const result = await brainmazeApi.personaRespond(attackerIp, personaInput);
      setPersonaResponse((result as any).response || "No response");
    } catch (e) {
      setPersonaResponse("Error generating response");
    } finally {
      setPersonaLoading(false);
    }
  };

  const confusionScore = status?.avg_confusion_score || 0;
  const scoreColor = confusionScore >= 81 ? "red" : confusionScore >= 61 ? "orange" : confusionScore >= 41 ? "blue" : confusionScore >= 21 ? "cyan" : "gray";

  return (
    <Stack gap="md">
      {/* ── Header ── */}
      <Group justify="space-between" align="center">
        <Group gap="md">
          <ThemeIcon size={42} radius="md" color="red" variant="light">
            <IconBrain size={26} />
          </ThemeIcon>
          <div>
            <Text size="xl" fw={900} className="pitbull-display" c="red">
              BRAINMAZE
            </Text>
            <Text size="xs" c="dimmed">Cognitive confusion engine — Red Team level deception</Text>
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
          <ActionIcon onClick={refresh} variant="subtle" color="cyan" size="lg">
            <IconRefresh size={18} />
          </ActionIcon>
        </Group>
      </Group>

      {/* ── Confusion Score Gauge ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group justify="space-between" align="center">
          <div>
            <Text size="sm" fw={700} c="red" className="pitbull-display">AVERAGE CONFUSION SCORE</Text>
            <Text size="xs" c="dimmed">Across all tracked attackers</Text>
          </div>
          <RingProgress
            size={120}
            thickness={8}
            sections={[{ value: confusionScore, color: scoreColor }]}
            label={
              <Center>
                <div style={{ textAlign: "center" }}>
                  <Text size="xl" fw={900} className="pitbull-mono" c={scoreColor}>
                    {confusionScore.toFixed(0)}
                  </Text>
                  <Text size="xs" c="dimmed">/ 100</Text>
                </div>
              </Center>
            }
          />
          <SimpleGrid cols={2} spacing="xs" style={{ minWidth: 200 }}>
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">TRACKED</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.total_attackers || 0}</Text>
            </div>
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">ACTIVE</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.active_attackers || 0}</Text>
            </div>
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">PERSONAS</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.active_personas || 0}</Text>
            </div>
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">TECHNIQUES</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{analytics?.total_techniques_deployed || 0}</Text>
            </div>
          </SimpleGrid>
        </Group>
      </Card>

      {/* ── Stats Grid ── */}
      <SimpleGrid cols={4} spacing="sm">
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconEyeOff size={18} color="var(--pitbull-cyan)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">FALSE TRAILS</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.trails_deployed || 0}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconClock size={18} color="var(--pitbull-amber)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">TIME WASTERS</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.wasters_deployed || 0}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconGhost size={18} color="var(--pitbull-violet)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">PARANOIA INJECTIONS</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.paranoia_injections || 0}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <IconUserBolt size={18} color="var(--pitbull-red)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">ACTIVE PERSONAS</Text>
              <Text size="lg" fw={700} className="pitbull-mono">{status?.active_personas || 0}</Text>
            </div>
          </Group>
        </Card>
      </SimpleGrid>

      {/* ── Action Buttons ── */}
      <SimpleGrid cols={4} spacing="sm">
        <Button
          leftSection={<IconEyeOff size={16} />}
          color="cyan"
          variant="light"
          onClick={() => setTrailModalOpen(true)}
        >
          Deploy False Trail
        </Button>
        <Button
          leftSection={<IconClock size={16} />}
          color="blue"
          variant="light"
          onClick={() => setWasterModalOpen(true)}
        >
          Generate Time Waster
        </Button>
        <Button
          leftSection={<IconGhost size={16} />}
          color="violet"
          variant="light"
          onClick={() => setParanoiaModalOpen(true)}
        >
          Inject Paranoia
        </Button>
        <Button
          leftSection={<IconUserBolt size={16} />}
          color="orange"
          variant="light"
          onClick={() => setPersonaModalOpen(true)}
        >
          Deploy Persona
        </Button>
      </SimpleGrid>

      {/* ── Phase Distribution ── */}
      {analytics?.phase_distribution && (
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Text size="sm" fw={700} c="red" className="pitbull-display" mb="sm">CONFUSION PHASE DISTRIBUTION</Text>
          <SimpleGrid cols={6} spacing="xs">
            {Object.entries(analytics.phase_distribution).map(([phase, count]) => (
              <div key={phase} style={{ textAlign: "center" }}>
                <Badge size="sm" color={PHASE_COLORS[phase] || "gray"} variant="light" mb={4}>
                  {PHASE_LABELS[phase] || phase}
                </Badge>
                <div>
                  <Text size="xl" fw={700} className="pitbull-mono" c={PHASE_COLORS[phase] || "gray"}>
                    {count as number}
                  </Text>
                </div>
              </div>
            ))}
          </SimpleGrid>
        </Card>
      )}

      {/* ── Max Confusion Alert ── */}
      {status?.attackers?.some((a) => a.phase === "max_confusion") && (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size={18} />}>
          <Text size="sm" fw={600}>MAXIMUM CONFUSION ACHIEVED</Text>
          <Text size="xs" c="dimmed">
            "Another hacker" persona deployed for attacker(s). Full cognitive disorientation in effect.
          </Text>
        </Alert>
      )}

      {/* ── Tracked Attackers ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group justify="space-between" mb="sm">
          <Text size="sm" fw={700} c="red" className="pitbull-display">TRACKED ATTACKERS</Text>
          <Badge size="xs" variant="light">{status?.total_attackers || 0}</Badge>
        </Group>
        <ScrollArea h={300}>
          <Table striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>IP</Table.Th>
                <Table.Th>Confusion</Table.Th>
                <Table.Th>Phase</Table.Th>
                <Table.Th>Techniques</Table.Th>
                <Table.Th>Time</Table.Th>
                <Table.Th>Persona</Table.Th>
                <Table.Th></Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(status?.attackers || []).map((a, i) => (
                <Table.Tr key={i}>
                  <Table.Td>
                    <Text size="xs" className="pitbull-mono" c="red">{a.attacker_ip}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      <Progress
                        value={a.confusion_score}
                        color={a.confusion_score >= 81 ? "red" : a.confusion_score >= 61 ? "orange" : a.confusion_score >= 41 ? "blue" : "cyan"}
                        size="sm"
                        style={{ width: 60 }}
                      />
                      <Text size="xs" className="pitbull-mono">{a.confusion_score}</Text>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Badge size="xs" color={PHASE_COLORS[a.phase] || "gray"} variant="light">
                      {PHASE_LABELS[a.phase] || a.phase}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {a.active_techniques.map((t, j) => (
                        <Badge key={j} size="xs" variant="light" color="violet">{t}</Badge>
                      ))}
                      {a.active_techniques.length === 0 && (
                        <Text size="xs" c="dimmed">—</Text>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed" className="pitbull-mono">{Math.floor(a.time_in_system / 60)}m</Text>
                  </Table.Td>
                  <Table.Td>
                    {a.persona_active ? (
                      <Badge size="xs" color="orange" variant="filled">{a.persona_type || "active"}</Badge>
                    ) : (
                      <Text size="xs" c="dimmed">—</Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <ActionIcon
                      size="sm"
                      variant="subtle"
                      color="cyan"
                      onClick={() => {
                        setSelectedAttackerIp(a.attacker_ip);
                        setAttackerIp(a.attacker_ip);
                      }}
                    >
                      <IconBolt size={14} />
                    </ActionIcon>
                  </Table.Td>
                </Table.Tr>
              ))}
              {(status?.attackers || []).length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={7}>
                    <Text size="xs" c="dimmed" ta="center" py="md">No attackers tracked</Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Card>

      {/* ── Active Personas ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group justify="space-between" mb="sm">
          <Text size="sm" fw={700} c="orange" className="pitbull-display">ACTIVE PERSONAS</Text>
          <Button
            size="xs"
            variant="light"
            color="orange"
            leftSection={<IconUserBolt size={14} />}
            onClick={() => setPersonaModalOpen(true)}
          >
            Deploy New
          </Button>
        </Group>
        <ScrollArea h={150}>
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Persona</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Attacker</Table.Th>
                <Table.Th>Interactions</Table.Th>
                <Table.Th>Active Since</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(status?.personas || []).map((p, i) => (
                <Table.Tr key={i}>
                  <Table.Td>
                    <Text size="xs" fw={600}>{p.persona_name}</Text>
                    <Text size="xs" c="dimmed">{p.role}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge size="xs" color="orange" variant="light">{p.persona_type}</Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" className="pitbull-mono" c="red">{p.attacker_ip}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" className="pitbull-mono">{p.interactions}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed">{p.created_at ? new Date(p.created_at).toLocaleTimeString() : "—"}</Text>
                  </Table.Td>
                </Table.Tr>
              ))}
              {(status?.personas || []).length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text size="xs" c="dimmed" ta="center" py="md">No active personas</Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Card>

      {/* ── Persona Chat ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group justify="space-between" mb="sm">
          <Text size="sm" fw={700} c="orange" className="pitbull-display">PERSONA INTERACTION TEST</Text>
          <Button
            size="xs"
            variant="light"
            color="orange"
            leftSection={<IconTerminal size={14} />}
            onClick={() => setChatModalOpen(true)}
            disabled={!attackerIp}
          >
            Test Chat
          </Button>
        </Group>
        {personaResponse && (
          <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)", background: "rgba(0,0,0,0.3)" }}>
            <Text size="xs" c="dimmed" mb="xs">Last Response:</Text>
            <Text size="sm" className="pitbull-mono" style={{ whiteSpace: "pre-wrap" }}>{personaResponse}</Text>
          </Card>
        )}
      </Card>

      {/* ── Confusion Technique Timeline ── */}
      {history && history.history.length > 0 && (
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group justify="space-between" mb="sm">
            <Text size="sm" fw={700} c="red" className="pitbull-display">
              CONFUSION TIMELINE — {history.attacker_ip}
            </Text>
            <Badge size="xs" variant="light">{history.technique_count} events</Badge>
          </Group>
          <ScrollArea h={250}>
            <Stack gap={4}>
              {history.history.map((event, i) => (
                <Group key={i} gap="sm" align="flex-start">
                  <Badge size="xs" color={PHASE_COLORS[event.phase] || "gray"} variant="light" style={{ minWidth: 100 }}>
                    {event.technique}
                  </Badge>
                  <Text size="xs" c="dimmed" className="pitbull-mono">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </Text>
                  <Text size="xs" c="dimmed">
                    score: {event.confusion_score} | phase: {event.phase}
                  </Text>
                </Group>
              ))}
            </Stack>
          </ScrollArea>
        </Card>
      )}

      {/* ── Live Log Stream ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group gap="xs" mb="sm">
          <span className="pitbull-pulse-dot" style={{ color: "var(--pitbull-red)" }} />
          <Text size="sm" fw={700} c="red" className="pitbull-display">BRAINMAZE EVENTS</Text>
        </Group>
        <ScrollArea h={200}>
          <Stack gap={2}>
            {liveLog.length > 0 ? liveLog.map((line, i) => (
              <Text key={i} size="xs" className="pitbull-mono" c="dimmed">
                {line}
              </Text>
            )) : (
              <Text size="xs" c="dimmed" ta="center" py="md">Waiting for events...</Text>
            )}
          </Stack>
        </ScrollArea>
      </Card>

      {/* ── 4 Pillars Overview ── */}
      <SimpleGrid cols={4} spacing="sm">
        {[
          { icon: IconEyeOff, name: "False Trails", desc: "Fake DNS, creds, configs", color: "cyan" },
          { icon: IconGhost, name: "Paranoia", desc: "Make them think someone else is here", color: "violet" },
          { icon: IconClock, name: "Time Wasters", desc: "Decoy content to burn time", color: "blue" },
          { icon: IconUserBolt, name: "Personas", desc: "LLM-powered fake characters", color: "orange" },
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

      {/* ── Modals ── */}

      {/* False Trail Modal */}
      <Modal opened={trailModalOpen} onClose={() => setTrailModalOpen(false)} title="Deploy False Trail" size="md">
        <Stack gap="sm">
          <TextInput label="Attacker IP" value={attackerIp} onChange={(e) => setAttackerIp(e.target.value)} placeholder="e.g., 10.0.0.5" />
          <Select label="Trail Type" data={TRAIL_TYPES} value={trailType} onChange={(v) => setTrailType(v || "credentials")} />
          <Button leftSection={<IconEyeOff size={16} />} color="cyan" onClick={handleGenerateTrail} disabled={!attackerIp}>
            Generate & Deploy
          </Button>
        </Stack>
      </Modal>

      {/* Paranoia Modal */}
      <Modal opened={paranoiaModalOpen} onClose={() => setParanoiaModalOpen(false)} title="Inject Paranoia Indicator" size="md">
        <Stack gap="sm">
          <TextInput label="Attacker IP" value={attackerIp} onChange={(e) => setAttackerIp(e.target.value)} placeholder="e.g., 10.0.0.5" />
          <Select label="Paranoia Type" data={PARANOIA_TYPES} value={paranoiaType} onChange={(v) => setParanoiaType(v || "logs")} />
          <Alert color="violet" variant="light" icon={<IconAlertTriangle size={16} />}>
            Paranoia indicators escalate over time: subtle → moderate → obvious → extreme
          </Alert>
          <Button leftSection={<IconGhost size={16} />} color="violet" onClick={handleInjectParanoia} disabled={!attackerIp}>
            Inject
          </Button>
        </Stack>
      </Modal>

      {/* Time Waster Modal */}
      <Modal opened={wasterModalOpen} onClose={() => setWasterModalOpen(false)} title="Generate Time Waster" size="md">
        <Stack gap="sm">
          <TextInput label="Attacker IP" value={attackerIp} onChange={(e) => setAttackerIp(e.target.value)} placeholder="e.g., 10.0.0.5" />
          <Select label="Waster Type" data={WASTER_TYPES} value={wasterType} onChange={(v) => setWasterType(v || "filesystem")} />
          <Button leftSection={<IconClock size={16} />} color="blue" onClick={handleGenerateWaster} disabled={!attackerIp}>
            Generate
          </Button>
        </Stack>
      </Modal>

      {/* Persona Modal */}
      <Modal opened={personaModalOpen} onClose={() => setPersonaModalOpen(false)} title="Deploy Persona" size="md">
        <Stack gap="sm">
          <TextInput label="Attacker IP" value={attackerIp} onChange={(e) => setAttackerIp(e.target.value)} placeholder="e.g., 10.0.0.5" />
          <Select label="Persona Type" data={PERSONA_TYPES} value={personaType} onChange={(v) => setPersonaType(v || "confused_sysadmin")} />
          <Alert color="orange" variant="light" icon={<IconUserBolt size={16} />}>
            Personas use LLM to generate in-character responses. The "Another Hacker" persona creates maximum paranoia.
          </Alert>
          <Button leftSection={<IconUserBolt size={16} />} color="orange" onClick={handleSelectPersona} disabled={!attackerIp}>
            Deploy Persona
          </Button>
        </Stack>
      </Modal>

      {/* Persona Chat Modal */}
      <Modal opened={chatModalOpen} onClose={() => setChatModalOpen(false)} title="Persona Interaction Test" size="lg">
        <Stack gap="sm">
          <TextInput label="Attacker IP" value={attackerIp} onChange={(e) => setAttackerIp(e.target.value)} placeholder="e.g., 10.0.0.5" />
          <Textarea label="Attacker Input" value={personaInput} onChange={(e) => setPersonaInput(e.target.value)} placeholder="What the attacker says..." rows={3} />
          <Button leftSection={<IconTerminal size={16} />} color="orange" onClick={handlePersonaChat} loading={personaLoading} disabled={!attackerIp || !personaInput}>
            Generate Persona Response
          </Button>
          {personaResponse && (
            <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)", background: "rgba(0,0,0,0.3)" }}>
              <Text size="xs" c="dimmed" mb="xs">Persona Response:</Text>
              <Text size="sm" className="pitbull-mono" style={{ whiteSpace: "pre-wrap" }}>{personaResponse}</Text>
            </Card>
          )}
        </Stack>
      </Modal>
    </Stack>
  );
}