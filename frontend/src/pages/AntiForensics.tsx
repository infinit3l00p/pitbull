import { useState } from "react";
import {
  AppShell,
  Box,
  Button,
  Card,
  Code,
  Group,
  Modal,
  Progress,
  ScrollArea,
  Stack,
  Text,
  TextInput,
  Title,
  Alert,
  Badge,
  Divider,
  Table,
  ActionIcon,
  Tooltip,
} from "@mantine/core";
import {
  IconGhost,
  IconTrash,
  IconClock,
  IconEyeOff,
  IconBolt,
  IconDatabase,
  IconNetwork,
  IconShield,
  IconAlertTriangle,
  IconCheck,
  IconX,
  IconRefresh,
} from "@tabler/icons-react";
import { api } from "../api";

// ── Types ──────────────────────────────────────────────────────────

interface OpResult {
  module: string;
  status?: string;
  wiped?: string[];
  total?: number;
  error?: string;
  purged?: number;
  [key: string]: any;
}

interface SanitizeResult {
  timestamp: string;
  target?: string;
  operations: OpResult[];
  total_operations: number;
  status: string;
}

// ── Module Cards ───────────────────────────────────────────────────

const MODULES = [
  { id: "log_wiper", name: "Log Wiper", icon: IconTrash, color: "red", desc: "System logs, auth, syslog, journalctl" },
  { id: "timestamp", name: "Timestomp", icon: IconClock, color: "orange", desc: "Copy timestamps from legit files" },
  { id: "process", name: "Process Hider", icon: IconEyeOff, color: "grape", desc: "Hide/rename processes, bind mounts" },
  { id: "memory", name: "Memory Executor", icon: IconBolt, color: "blue", desc: "memfd_create — zero disk footprint" },
  { id: "network", name: "Network Cleaner", icon: IconNetwork, color: "teal", desc: "conntrack, iptables, MAC spoof, Tor" },
  { id: "file_wiper", name: "File Wiper", icon: IconShield, color: "red", desc: "Secure delete — multi-pass overwrite" },
  { id: "neo4j", name: "Neo4j Cleaner", icon: IconDatabase, color: "indigo", desc: "Purge episodic memory, exploits, missions" },
  { id: "opsec", name: "OpSec Manager", icon: IconGhost, color: "dark", desc: "Quick wipe, full sanitize, ghost mode" },
];

// ── ATT&CK Techniques ──────────────────────────────────────────────

const ATTACK_TECHNIQUES = [
  { id: "T1070", name: "Indicator Removal", sub: ["T1070.002 Linux Logs", "T1070.004 File Deletion", "T1070.006 Timestomp"] },
  { id: "T1562", name: "Impair Defenses", sub: ["T1562.001 Disable Tools", "T1562.006 Clear Event Logs"] },
  { id: "T1027", name: "Obfuscated Files", sub: ["T1027.002 Binary Padding", "T1027.007 Dynamic API Resolution"] },
  { id: "T1620", name: "Reflective Code Loading", sub: ["memfd_create", "In-memory PE/ELF"] },
  { id: "T1059.004", name: "Unix Shell", sub: ["Fileless execution", "LOLBin abuse"] },
];

// ── Threat Intel Sources ───────────────────────────────────────────

const THREAT_INTEL = [
  { country: "🇰🇵 DPRK", group: "Lazarus / Kimsuky", techniques: "Memory-only RAT, timestomping, prefetch wiping, LKM rootkit, EtherHiding" },
  { country: "🇷🇺 Russia", group: "APT28 / Turla", techniques: "ETW patching, EventLog suppression, AMSI bypass, fileless PowerShell" },
  { country: "🇨🇳 China", group: "APT41 / APT10", techniques: "Real-time event silencing, log spoofing, SIEM correlation breaking, decoy events" },
  { country: "🇷🇴 Romania", group: "DefCamp / RomHack", techniques: "EDR bypass, MalOpSec, memory forensics evasion" },
  { country: "🇮🇳 India", group: "SideWinder / Patchwork", techniques: "LOLBin abuse, .NET reflection, fileless PowerShell" },
];

export default function AntiForensics() {
  const [loading, setLoading] = useState<string | null>(null);
  const [results, setResults] = useState<SanitizeResult | OpResult | null>(null);
  const [ghostMode, setGhostMode] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalContent, setModalContent] = useState<any>(null);
  const [timestompTarget, setTimestompTarget] = useState("");
  const [timestompRef, setTimestompRef] = useState("");
  const [deletePath, setDeletePath] = useState("");
  const [deletePasses, setDeletePasses] = useState(3);
  const [sanitizeTarget, setSanitizeTarget] = useState("");
  const [log, setLog] = useState<string[]>([]);

  const addLog = (msg: string) => {
    const ts = new Date().toLocaleTimeString();
    setLog((prev) => [`[${ts}] ${msg}`, ...prev].slice(0, 50));
  };

  const handleAction = async (name: string, fn: () => Promise<any>) => {
    setLoading(name);
    addLog(`>> Executing: ${name}`);
    try {
      const result = await fn();
      setResults(result);
      setModalContent(result);
      setModalOpen(true);
      addLog(`<< ${name} completed`);
    } catch (e: any) {
      addLog(`<< ${name} FAILED: ${e.message}`);
    } finally {
      setLoading(null);
    }
  };

  // ── Operations ───────────────────────────────────────────────────

  const quickWipe = () => handleAction("Quick Wipe", () => api.post("/antiforensics/quick-wipe"));
  const fullSanitize = () => handleAction("Full Sanitize", () =>
    api.post("/antiforensics/full-sanitize", { target: sanitizeTarget || null }));
  const toggleGhost = async () => {
    const endpoint = ghostMode ? "/antiforensics/ghost-mode/disable" : "/antiforensics/ghost-mode/enable";
    setLoading("ghost");
    addLog(`>> ${ghostMode ? "Disabling" : "Enabling"} Ghost Mode`);
    try {
      const result = await api.post(endpoint);
      setGhostMode(!ghostMode);
      addLog(`<< Ghost Mode ${ghostMode ? "disabled" : "enabled"}`);
      setModalContent(result);
      setModalOpen(true);
    } catch (e: any) {
      addLog(`<< Ghost Mode FAILED: ${e.message}`);
    } finally {
      setLoading(null);
    }
  };

  const wipeLogs = () => handleAction("Wipe System Logs", () => api.post("/antiforensics/wipe/logs?aggressive=true"));
  const wipeHistory = () => handleAction("Wipe History", () => api.post("/antiforensics/wipe/history"));
  const wipePitbullLogs = () => handleAction("Wipe PITBULL Logs", () => api.post("/antiforensics/wipe/pitbull-logs"));
  const purgeEpisodic = () => handleAction("Purge Episodic Memory", () => api.post("/antiforensics/neo4j/purge-episodic"));
  const purgeExploits = () => handleAction("Purge Exploit Attempts", () => api.post("/antiforensics/neo4j/purge-exploits"));
  const purgeMissions = () => handleAction("Purge Mission History", () => api.post("/antiforensics/neo4j/purge-missions"));
  const purgeOpinions = () => handleAction("Purge Opinions", () => api.post("/antiforensics/neo4j/purge-opinions"));
  const clearNetwork = () => handleAction("Clear Network State", () => api.post("/antiforensics/network/clear-all"));
  const rotateTor = () => handleAction("Rotate Tor Circuit", () => api.post("/antiforensics/network/rotate-tor"));
  const spoofMac = () => handleAction("Spoof MAC Address", () => api.post("/antiforensics/network/spoof-mac", {}));

  const doTimestomp = () => {
    if (!timestompTarget) return;
    handleAction("Timestomp", () =>
      api.post("/antiforensics/timestomp", { target: timestompTarget, reference: timestompRef || null }));
  };

  const doSecureDelete = () => {
    if (!deletePath) return;
    handleAction("Secure Delete", () =>
      api.post("/antiforensics/file/secure-delete", { path: deletePath, passes: deletePasses }));
  };

  // ── Render ───────────────────────────────────────────────────────

  return (
    <Box p="md">
      {/* Header */}
      <Group justify="space-between" mb="md">
        <div>
          <Title order={2}>
            <IconGhost size={28} style={{ marginRight: 8, verticalAlign: "middle" }} />
            Anti-Forensics 🔱
          </Title>
          <Text c="dimmed" size="sm">
            Trace wiping · Timestomping · Ghost Mode · Memory Execution — Inspired by Lazarus, Turla, APT41
          </Text>
        </div>
        <Group gap="xs">
          <Button
            color={ghostMode ? "green" : "dark"}
            variant={ghostMode ? "filled" : "outline"}
            leftSection={<IconGhost size={16} />}
            loading={loading === "ghost"}
            onClick={toggleGhost}
          >
            {ghostMode ? "GHOST MODE ON" : "Enable Ghost Mode"}
          </Button>
          <Button
            color="orange"
            variant="outline"
            leftSection={<IconBolt size={16} />}
            loading={loading === "Quick Wipe"}
            onClick={quickWipe}
          >
            Quick Wipe
          </Button>
          <Button
            color="red"
            variant="filled"
            leftSection={<IconTrash size={16} />}
            loading={loading === "Full Sanitize"}
            onClick={fullSanitize}
          >
            Full Sanitize
          </Button>
        </Group>
      </Group>

      {/* Sanitize target input */}
      <Group gap="xs" mb="md">
        <TextInput
          placeholder="Target (optional, e.g. fraudgpt.org)"
          value={sanitizeTarget}
          onChange={(e) => setSanitizeTarget(e.target.value)}
          style={{ width: 300 }}
          size="xs"
        />
        <Text size="xs" c="dimmed">Full sanitize will wipe all traces for this target (or all if empty)</Text>
      </Group>

      {/* Module Cards Grid */}
      <Title order={4} mb="xs">Modules</Title>
      <Group gap="sm" mb="lg">
        {MODULES.map((mod) => (
          <Card key={mod.id} withBorder padding="sm" style={{ width: 220 }}>
            <Group gap="xs" mb="xs">
              <mod.icon size={20} color={`var(--mantine-color-${mod.color}-6)`} />
              <Text fw={600} size="sm">{mod.name}</Text>
            </Group>
            <Text size="xs" c="dimmed">{mod.desc}</Text>
          </Card>
        ))}
      </Group>

      {/* Quick Actions */}
      <Title order={4} mb="xs">Quick Actions</Title>
      <Card withBorder padding="md" mb="lg">
        <Group gap="xs" wrap="wrap">
          <Button size="xs" variant="light" color="red" leftSection={<IconTrash size={14} />} loading={loading === "Wipe System Logs"} onClick={wipeLogs}>Wipe System Logs</Button>
          <Button size="xs" variant="light" color="red" leftSection={<IconTrash size={14} />} loading={loading === "Wipe History"} onClick={wipeHistory}>Wipe History</Button>
          <Button size="xs" variant="light" color="red" leftSection={<IconTrash size={14} />} loading={loading === "Wipe PITBULL Logs"} onClick={wipePitbullLogs}>Wipe PITBULL Logs</Button>
          <Button size="xs" variant="light" color="indigo" leftSection={<IconDatabase size={14} />} loading={loading === "Purge Episodic Memory"} onClick={purgeEpisodic}>Purge Episodic</Button>
          <Button size="xs" variant="light" color="indigo" leftSection={<IconDatabase size={14} />} loading={loading === "Purge Exploit Attempts"} onClick={purgeExploits}>Purge Exploits</Button>
          <Button size="xs" variant="light" color="indigo" leftSection={<IconDatabase size={14} />} loading={loading === "Purge Mission History"} onClick={purgeMissions}>Purge Missions</Button>
          <Button size="xs" variant="light" color="indigo" leftSection={<IconDatabase size={14} />} loading={loading === "Purge Opinions"} onClick={purgeOpinions}>Purge Opinions</Button>
          <Button size="xs" variant="light" color="teal" leftSection={<IconNetwork size={14} />} loading={loading === "Clear Network State"} onClick={clearNetwork}>Clear Network</Button>
          <Button size="xs" variant="light" color="teal" leftSection={<IconRefresh size={14} />} loading={loading === "Rotate Tor Circuit"} onClick={rotateTor}>Rotate Tor</Button>
          <Button size="xs" variant="light" color="teal" leftSection={<IconNetwork size={14} />} loading={loading === "Spoof MAC Address"} onClick={spoofMac}>Spoof MAC</Button>
        </Group>
      </Card>

      {/* Timestomp Section */}
      <Title order={4} mb="xs">Timestomp</Title>
      <Card withBorder padding="md" mb="lg">
        <Group gap="xs" align="flex-end">
          <TextInput
            label="Target file"
            placeholder="/path/to/file"
            value={timestompTarget}
            onChange={(e) => setTimestompTarget(e.target.value)}
            style={{ flex: 1 }}
            size="xs"
          />
          <TextInput
            label="Reference (optional)"
            placeholder="/bin/ls"
            value={timestompRef}
            onChange={(e) => setTimestompRef(e.target.value)}
            style={{ flex: 1 }}
            size="xs"
          />
          <Button size="xs" color="orange" leftSection={<IconClock size={14} />} loading={loading === "Timestomp"} onClick={doTimestomp}>
            Timestomp
          </Button>
        </Group>
        <Text size="xs" c="dimmed" mt="xs">Copies timestamps from a legitimate file (default: /bin/ls) to hide the target file's real creation time</Text>
      </Card>

      {/* Secure Delete Section */}
      <Title order={4} mb="xs">Secure File Deletion</Title>
      <Card withBorder padding="md" mb="lg">
        <Group gap="xs" align="flex-end">
          <TextInput
            label="File/directory path"
            placeholder="/path/to/delete"
            value={deletePath}
            onChange={(e) => setDeletePath(e.target.value)}
            style={{ flex: 1 }}
            size="xs"
          />
          <TextInput
            label="Passes"
            placeholder="3"
            value={String(deletePasses)}
            onChange={(e) => setDeletePasses(parseInt(e.target.value) || 3)}
            style={{ width: 80 }}
            size="xs"
          />
          <Button size="xs" color="red" leftSection={<IconTrash size={14} />} loading={loading === "Secure Delete"} onClick={doSecureDelete}>
            Secure Delete
          </Button>
        </Group>
        <Text size="xs" c="dimmed" mt="xs">Overwrites file with random data + zeros, then deletes. Unrecoverable.</Text>
      </Card>

      {/* ATT&CK Techniques */}
      <Title order={4} mb="xs">MITRE ATT&CK Techniques</Title>
      <Card withBorder padding="md" mb="lg">
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>ID</Table.Th>
              <Table.Th>Technique</Table.Th>
              <Table.Th>Sub-techniques</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {ATTACK_TECHNIQUES.map((tech) => (
              <Table.Tr key={tech.id}>
                <Table.Td><Badge size="sm" variant="light" color="red">{tech.id}</Badge></Table.Td>
                <Table.Td><Text size="sm" fw={500}>{tech.name}</Text></Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {tech.sub.map((s) => (
                      <Badge key={s} size="xs" variant="dot" color="orange">{s}</Badge>
                    ))}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Card>

      {/* Threat Intel Sources */}
      <Title order={4} mb="xs">Threat Intelligence Sources</Title>
      <Card withBorder padding="md" mb="lg">
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Country</Table.Th>
              <Table.Th>APT Group</Table.Th>
              <Table.Th>Techniques Researched</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {THREAT_INTEL.map((ti) => (
              <Table.Tr key={ti.country}>
                <Table.Td><Text size="sm" fw={600}>{ti.country}</Text></Table.Td>
                <Table.Td><Text size="sm">{ti.group}</Text></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{ti.techniques}</Text></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Card>

      {/* Operation Log */}
      <Title order={4} mb="xs">Operation Log</Title>
      <Card withBorder padding="sm" style={{ background: "#0a0a0a" }}>
        <ScrollArea h={200} type="auto">
          <Stack gap={2}>
            {log.length === 0 ? (
              <Text c="dimmed" size="xs" ta="center" py="xl">No operations yet. Run an action above.</Text>
            ) : (
              log.map((entry, i) => (
                <Text key={i} size="xs" ff="monospace" c={entry.includes("FAILED") ? "red" : entry.includes("<<") ? "green" : "blue"}>
                  {entry}
                </Text>
              ))
            )}
          </Stack>
        </ScrollArea>
      </Card>

      {/* Result Modal */}
      <Modal opened={modalOpen} onClose={() => setModalOpen(false)} title="Operation Result" size="lg">
        <ScrollArea h={400}>
          <pre style={{ fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {JSON.stringify(modalContent, null, 2)}
          </pre>
        </ScrollArea>
      </Modal>
    </Box>
  );
}