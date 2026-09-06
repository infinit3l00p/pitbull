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
  TextInput,
  Code,
  Progress,
  SimpleGrid,
  ThemeIcon,
  Box,
  Alert,
  Modal,
  Tabs,
  Skeleton,
  Divider,
} from "@mantine/core";
import {
  IconShield,
  IconAlertTriangle,
  IconBan,
  IconEye,
  IconEyeOff,
  IconRefresh,
  IconFlame,
  IconBug,
  IconLock,
  IconActivity,
  IconSearch,
  IconNetwork,
  IconDatabase,
  IconWorld,
  IconChevronRight,
  IconUserX,
} from "@tabler/icons-react";
import {
  sentinelApi,
  type SentinelStatus,
  type AttackEvent,
  type AttackerProfile,
  type BlockedIP,
} from "../api-sentinel";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "red",
  HIGH: "orange",
  MEDIUM: "yellow",
  LOW: "blue",
};

const THREAT_COLORS: Record<string, string> = {
  NORMAL: "green",
  SUSPICIOUS: "blue",
  ELEVATED: "yellow",
  HIGH: "orange",
  CRITICAL: "red",
};

export default function SentinelPage() {
  const [status, setStatus] = useState<SentinelStatus | null>(null);
  const [attacks, setAttacks] = useState<AttackEvent[]>([]);
  const [attackers, setAttackers] = useState<AttackerProfile[]>([]);
  const [blocked, setBlocked] = useState<BlockedIP[]>([]);
  const [loading, setLoading] = useState(true);
  const [blockIp, setBlockIp] = useState("");
  const [feedConnected, setFeedConnected] = useState(false);
  const [liveAttacks, setLiveAttacks] = useState<AttackEvent[]>([]);
  const [investigateIp, setInvestigateIp] = useState<string | null>(null);
  const [investigateData, setInvestigateData] = useState<any>(null);
  const [investigateLoading, setInvestigateLoading] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ ip: string; x: number; y: number } | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, a, at, b] = await Promise.all([
        sentinelApi.status(),
        sentinelApi.attacks(50),
        sentinelApi.attackers(),
        sentinelApi.blocked(),
      ]);
      setStatus(s as any);
      setAttacks((a as any).attacks || []);
      setAttackers((at as any).attackers || []);
      setBlocked((b as any).blocked || []);
    } catch (e) {
      console.error("Sentinel refresh failed:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 10000);

    const es = new EventSource(sentinelApi.feedUrl);
    es.onopen = () => setFeedConnected(true);
    es.onerror = () => setFeedConnected(false);
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (!data) return;
        if (data.type === "attack" && data.attack) {
          const attack = data.attack;
          // Ensure required fields exist to prevent crash
          if (attack && attack.severity && attack.source_ip) {
            setLiveAttacks((prev) => [attack, ...prev].slice(0, 20));
          }
        } else if (data.type === "vigil_alert" && data.severity) {
          // Convert vigil alert to attack-like object for live feed
          const attack = {
            id: `vigil-${Date.now()}`,
            timestamp: data.timestamp || new Date().toISOString(),
            source_ip: data.source_ip || "unknown",
            attack_type: data.alert_type || "vigil_alert",
            technique_id: "T0000",
            technique_name: "VIGIL",
            severity: data.severity || "MEDIUM",
            evidence: data.description || "",
            details: "",
            blocked: false,
          };
          setLiveAttacks((prev) => [attack, ...prev].slice(0, 20));
        }
        // Ignore other event types (connected, event, etc.)
      } catch {}
    };
    eventSourceRef.current = es;

    return () => {
      clearInterval(interval);
      es.close();
    };
  }, [refresh]);

  const handleBlock = async () => {
    if (!blockIp.trim()) return;
    try {
      await sentinelApi.block(blockIp.trim());
      setBlockIp("");
      refresh();
    } catch (e) {
      console.error("Block failed:", e);
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      await sentinelApi.unblock(ip);
      refresh();
    } catch (e) {
      console.error("Unblock failed:", e);
    }
  };

  const handleInvestigate = async (ip: string) => {
    setInvestigateIp(ip);
    setInvestigateLoading(true);
    setInvestigateData(null);
    try {
      const data = await sentinelApi.investigate(ip);
      setInvestigateData(data);
    } catch (e) {
      console.error("Investigation failed:", e);
      setInvestigateData({ error: String(e) });
    } finally {
      setInvestigateLoading(false);
    }
  };

  const handleBlockAttacker = async (ip: string) => {
    try {
      await sentinelApi.block(ip);
      refresh();
    } catch (e) {
      console.error("Block failed:", e);
    }
  };

  const threatLevel = status?.threat_level || "NORMAL";
  const threatColor = THREAT_COLORS[threatLevel] || "gray";
  const stats = status?.stats || { total_events: 0, total_attacks: 0, blocked_ips: 0, active_attackers: 0 };

  return (
    <Stack gap="md">
      {/* ── Header ── */}
      <Group justify="space-between" align="center">
        <Group gap="md">
          <ThemeIcon size={42} radius="md" color={threatColor} variant="light">
            <IconShield size={26} />
          </ThemeIcon>
          <div>
            <Text size="xl" fw={900} className="pitbull-display" c={threatColor}>
              SENTINEL
            </Text>
            <Text size="xs" c="dimmed">Real-time attack detection & auto-blocking</Text>
          </div>
        </Group>
        <Group gap="md">
          <Badge
            size="lg"
            color={feedConnected ? "green" : "gray"}
            variant="dot"
            styles={{ root: { background: "transparent", border: `1px solid var(--pitbull-border)` } }}
          >
            {feedConnected ? "LIVE FEED" : "DISCONNECTED"}
          </Badge>
          <Badge size="lg" color={threatColor} variant="filled">
            THREAT: {threatLevel}
          </Badge>
          <ActionIcon onClick={refresh} variant="subtle" color="cyan" size="lg">
            <IconRefresh size={18} />
          </ActionIcon>
        </Group>
      </Group>

      {/* ── Stats Grid ── */}
      <SimpleGrid cols={4} spacing="sm">
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="sm" align="center">
            <IconActivity size={20} color="var(--pitbull-cyan)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">EVENTS</Text>
              <Text size="xl" fw={700} className="pitbull-mono">{stats.total_events}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="sm" align="center">
            <IconFlame size={20} color="var(--pitbull-red)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">ATTACKS</Text>
              <Text size="xl" fw={700} className="pitbull-mono">{stats.total_attacks}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="sm" align="center">
            <IconBug size={20} color="var(--pitbull-amber)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">ACTIVE</Text>
              <Text size="xl" fw={700} className="pitbull-mono">{stats.active_attackers}</Text>
            </div>
          </Group>
        </Card>
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="sm" align="center">
            <IconBan size={20} color="var(--pitbull-red)" />
            <div>
              <Text size="xs" c="dimmed" className="pitbull-mono">BLOCKED</Text>
              <Text size="xl" fw={700} className="pitbull-mono">{stats.blocked_ips}</Text>
            </div>
          </Group>
        </Card>
      </SimpleGrid>

      {/* ── Threat Level Bar ── */}
      {threatLevel !== "NORMAL" && (
        <Alert color={threatColor} variant="light" icon={<IconAlertTriangle size={18} />}>
          <Text size="sm" fw={600}>Threat Level: {threatLevel}</Text>
          <Text size="xs" c="dimmed">
            {stats.active_attackers} active attacker(s) detected — {stats.blocked_ips} IPs blocked
          </Text>
          <Progress
            value={
              threatLevel === "SUSPICIOUS" ? 25 :
              threatLevel === "ELEVATED" ? 50 :
              threatLevel === "HIGH" ? 75 : 100
            }
            color={threatColor}
            size="sm"
            mt="xs"
          />
        </Alert>
      )}

      {/* ── Live Feed ── */}
      {liveAttacks.length > 0 && (
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-red)", borderWidth: 1 }}>
          <Group gap="xs" mb="xs">
            <span className="pitbull-pulse-dot" style={{ color: "var(--pitbull-red)" }} />
            <Text size="xs" fw={700} c="red" className="pitbull-display">LIVE ATTACK FEED</Text>
          </Group>
          <ScrollArea h={120}>
            <Stack gap="xs">
              {liveAttacks.map((a, i) => (
                <Group key={i} gap="sm" align="center">
                  <Badge size="xs" color={SEVERITY_COLORS[a.severity] || "gray"} variant="filled">
                    {a.severity}
                  </Badge>
                  <Text size="xs" c="cyan" className="pitbull-mono">{a.source_ip}</Text>
                  <Text size="xs" c="dimmed">→</Text>
                  <Text size="xs" fw={500}>{a.attack_type}</Text>
                  <Text size="xs" c="dimmed" className="pitbull-mono">[{a.technique_id}]</Text>
                </Group>
              ))}
            </Stack>
          </ScrollArea>
        </Card>
      )}

      {/* ── Manual Block ── */}
      <Group gap="sm">
        <TextInput
          placeholder="IP address to block..."
          value={blockIp}
          onChange={(e) => setBlockIp(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleBlock()}
          style={{ flex: 1 }}
          className="pitbull-mono"
        />
        <Button leftSection={<IconBan size={16} />} color="red" variant="light" onClick={handleBlock}>
          Block IP
        </Button>
      </Group>

      {/* ── Two Column: Attackers + Blocked ── */}
      <SimpleGrid cols={2} spacing="md">
        {/* Attackers — with right-click context menu */}
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group justify="space-between" mb="sm">
            <Text size="sm" fw={700} c="cyan" className="pitbull-display">KNOWN ATTACKERS</Text>
            <Group gap={4}>
              <Text size="xs" c="dimmed" fs="italic">right-click for options</Text>
              <Badge size="xs" variant="light">{attackers.length}</Badge>
            </Group>
          </Group>
          <ScrollArea h={300}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>IP</Table.Th>
                  <Table.Th>Attacks</Table.Th>
                  <Table.Th>Techniques</Table.Th>
                  <Table.Th>Status</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {attackers.map((a) => (
                  <Table.Tr
                    key={a.ip}
                    style={{ cursor: "context-menu" }}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setContextMenu({ ip: a.ip, x: e.clientX, y: e.clientY });
                    }}
                    onClick={() => handleInvestigate(a.ip)}
                  >
                    <Table.Td>
                      <Text size="xs" className="pitbull-mono" c="cyan">{a.ip}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" className="pitbull-mono">{a.attack_count}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {a.techniques_used?.slice(0, 2).map((t) => (
                          <Badge key={t} size="xs" variant="light" color="blue">{t}</Badge>
                        ))}
                        {a.techniques_used?.length > 2 && (
                          <Text size="xs" c="dimmed">+{a.techniques_used.length - 2}</Text>
                        )}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Badge size="xs" color={a.is_blocked ? "red" : "yellow"} variant={a.is_blocked ? "filled" : "light"}>
                        {a.is_blocked ? "BLOCKED" : "ACTIVE"}
                      </Badge>
                    </Table.Td>
                  </Table.Tr>
                ))}
                {attackers.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={4}>
                      <Text size="xs" c="dimmed" ta="center" py="md">No attackers detected</Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Card>

        {/* Blocked IPs */}
        <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group justify="space-between" mb="sm">
            <Text size="sm" fw={700} c="red" className="pitbull-display">BLOCKED IPs</Text>
            <Badge size="xs" color="red" variant="light">{blocked.length}</Badge>
          </Group>
          <ScrollArea h={300}>
            <Stack gap="xs">
              {blocked.map((b) => (
                <Group key={b.ip} justify="space-between" align="center"
                  style={{
                    padding: "8px 12px",
                    borderRadius: 6,
                    background: "rgba(255,0,0,0.05)",
                    border: "1px solid rgba(255,0,0,0.1)",
                  }}>
                  <Group gap="sm">
                    <IconLock size={14} color="var(--pitbull-red)" />
                    <Text size="xs" className="pitbull-mono" c="red">{b.ip}</Text>
                  </Group>
                  <Group gap="xs">
                    <Text size="xs" c="dimmed">{b.attack_type || b.reason}</Text>
                    <ActionIcon
                      size="sm"
                      variant="subtle"
                      color="green"
                      onClick={() => handleUnblock(b.ip)}
                      title="Unblock"
                    >
                      <IconEyeOff size={14} />
                    </ActionIcon>
                  </Group>
                </Group>
              ))}
              {blocked.length === 0 && (
                <Text size="xs" c="dimmed" ta="center" py="xl">No IPs blocked</Text>
              )}
            </Stack>
          </ScrollArea>
        </Card>
      </SimpleGrid>

      {/* ── Recent Attacks Table ── */}
      <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
        <Group justify="space-between" mb="sm">
          <Text size="sm" fw={700} c="cyan" className="pitbull-display">RECENT ATTACKS</Text>
          <Badge size="xs" variant="light">{attacks.length}</Badge>
        </Group>
        <ScrollArea h={350}>
          <Table striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Time</Table.Th>
                <Table.Th>Severity</Table.Th>
                <Table.Th>Source IP</Table.Th>
                <Table.Th>Attack Type</Table.Th>
                <Table.Th>ATT&CK</Table.Th>
                <Table.Th>Evidence</Table.Th>
                <Table.Th>Blocked</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {attacks.map((a) => (
                <Table.Tr key={a.id} style={{ cursor: "pointer" }} onContextMenu={(e) => { e.preventDefault(); handleInvestigate(a.source_ip); }}>
                  <Table.Td>
                    <Text size="xs" c="dimmed" className="pitbull-mono">
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge size="xs" color={SEVERITY_COLORS[a.severity] || "gray"} variant="filled">
                      {a.severity}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" className="pitbull-mono" c={a.blocked ? "red" : "cyan"}>
                      {a.source_ip}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" fw={500}>{a.attack_type}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Code fz="xs">{a.technique_id}</Code>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed" lineClamp={1}>
                      {typeof a.evidence === "string"
                        ? a.evidence
                        : Array.isArray(a.evidence)
                        ? (a.evidence as any[]).map((e: any) => typeof e === "string" ? e : e?.event_type || e?.details?.raw || "").join(" ")
                        : JSON.stringify(a.evidence || "")}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {a.blocked ? (
                      <IconBan size={14} color="var(--pitbull-red)" />
                    ) : (
                      <IconEye size={14} color="var(--pitbull-dimmed)" />
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
              {attacks.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={7}>
                    <Text size="xs" c="dimmed" ta="center" py="md">No attacks detected</Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Card>

      {/* ── Custom Right-Click Context Menu ── */}
      {contextMenu && (
        <>
          <div
            style={{ position: "fixed", inset: 0, zIndex: 1000 }}
            onClick={() => setContextMenu(null)}
            onContextMenu={(e) => { e.preventDefault(); setContextMenu(null); }}
          />
          <Card
            withBorder
            padding="xs"
            shadow="md"
            style={{
              position: "fixed",
              left: contextMenu.x,
              top: contextMenu.y,
              zIndex: 1001,
              width: 260,
              borderColor: "var(--pitbull-border)",
              background: "var(--pitbull-dark)",
            }}
          >
            <Stack gap={2}>
              <Text size="xs" c="dimmed" fw={600} mb={2} className="pitbull-mono">
                Investigate {contextMenu.ip}
              </Text>
              <Divider mb={4} />
              <Group
                gap="sm"
                style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 4 }}
                onClick={() => { handleInvestigate(contextMenu.ip); setContextMenu(null); }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(0,255,255,0.05)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "")}
              >
                <IconSearch size={14} color="var(--pitbull-cyan)" />
                <Text size="xs">Full Investigation</Text>
                <IconChevronRight size={12} style={{ marginLeft: "auto" }} />
              </Group>
              <Group
                gap="sm"
                style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 4 }}
                onClick={() => { handleInvestigate(contextMenu.ip); setContextMenu(null); }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(0,255,255,0.05)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "")}
              >
                <IconNetwork size={14} color="var(--pitbull-cyan)" />
                <Text size="xs">Shodan Host Lookup</Text>
              </Group>
              <Group
                gap="sm"
                style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 4 }}
                onClick={() => { handleInvestigate(contextMenu.ip); setContextMenu(null); }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(0,255,255,0.05)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "")}
              >
                <IconDatabase size={14} color="var(--pitbull-cyan)" />
                <Text size="xs">Neo4j Graph Query</Text>
              </Group>
              <Group
                gap="sm"
                style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 4 }}
                onClick={() => { handleInvestigate(contextMenu.ip); setContextMenu(null); }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(0,255,255,0.05)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "")}
              >
                <IconWorld size={14} color="var(--pitbull-cyan)" />
                <Text size="xs">Attack History</Text>
              </Group>
              <Divider my={4} />
              <Text size="xs" c="dimmed" fw={600} mb={2} className="pitbull-mono">Actions</Text>
              <Group
                gap="sm"
                style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 4 }}
                onClick={() => { handleBlockAttacker(contextMenu.ip); setContextMenu(null); }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,0,0,0.05)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "")}
              >
                <IconBan size={14} color="var(--pitbull-red)" />
                <Text size="xs" c="red">Block IP</Text>
              </Group>
              <Group
                gap="sm"
                style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 4 }}
                onClick={() => { handleUnblock(contextMenu.ip); setContextMenu(null); }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(0,255,0,0.05)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "")}
              >
                <IconEyeOff size={14} color="green" />
                <Text size="xs" c="green">Unblock IP</Text>
              </Group>
              <Divider my={4} />
              <Group
                gap="sm"
                style={{ cursor: "pointer", padding: "6px 8px", borderRadius: 4 }}
                onClick={() => { navigator.clipboard?.writeText(contextMenu.ip); setContextMenu(null); }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "")}
              >
                <IconUserX size={14} />
                <Text size="xs" c="dimmed">Copy IP Address</Text>
              </Group>
            </Stack>
          </Card>
        </>
      )}

      {/* ── Investigation Modal ── */}
      <Modal
        opened={investigateIp !== null}
        onClose={() => { setInvestigateIp(null); setInvestigateData(null); }}
        title={
          <Group gap="sm">
            <IconSearch size={20} color="var(--pitbull-cyan)" />
            <Text fw={700} className="pitbull-display">Investigate: {investigateIp}</Text>
          </Group>
        }
        size="xl"
        styles={{ body: { padding: 0 } }}
      >
        {investigateLoading ? (
          <Stack gap="sm" p="md">
            <Skeleton height={20} width="60%" />
            <Skeleton height={12} width="100%" />
            <Skeleton height={12} width="90%" />
            <Skeleton height={200} />
            <Skeleton height={12} width="80%" />
            <Skeleton height={12} width="70%" />
          </Stack>
        ) : investigateData?.error ? (
          <Stack p="md">
            <Alert color="red" icon={<IconAlertTriangle size={18} />}>
              Investigation failed: {investigateData.error}
            </Alert>
          </Stack>
        ) : investigateData ? (
          <Tabs defaultValue="summary">
            <Tabs.List style={{ paddingLeft: 16, paddingRight: 16 }}>
              <Tabs.Tab value="summary" leftSection={<IconShield size={14} />}>Summary</Tabs.Tab>
              <Tabs.Tab value="sentinel" leftSection={<IconActivity size={14} />}>Sentinel</Tabs.Tab>
              <Tabs.Tab value="shodan" leftSection={<IconNetwork size={14} />}>Shodan</Tabs.Tab>
              <Tabs.Tab value="neo4j" leftSection={<IconDatabase size={14} />}>Neo4j</Tabs.Tab>
              <Tabs.Tab value="attacks" leftSection={<IconFlame size={14} />}>Attacks</Tabs.Tab>
            </Tabs.List>

            <ScrollArea h={500} p="md">
              {/* Summary Tab */}
              <Tabs.Panel value="summary">
                <Stack gap="sm">
                  {investigateData.summary && (
                    <>
                      <Group gap="md">
                        <Box>
                          <Text size="xs" c="dimmed" className="pitbull-mono">IP ADDRESS</Text>
                          <Text size="lg" fw={700} c="cyan" className="pitbull-mono">{investigateData.summary.ip}</Text>
                        </Box>
                        <Box>
                          <Text size="xs" c="dimmed" className="pitbull-mono">TOTAL ATTACKS</Text>
                          <Text size="lg" fw={700} className="pitbull-mono">{investigateData.summary.total_attacks}</Text>
                        </Box>
                        <Box>
                          <Text size="xs" c="dimmed" className="pitbull-mono">BLOCKED</Text>
                          <Badge color={investigateData.summary.is_blocked ? "red" : "gray"} variant="filled">
                            {investigateData.summary.is_blocked ? "YES" : "NO"}
                          </Badge>
                        </Box>
                      </Group>
                      <Divider />
                      <Box>
                        <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>ATTACK TYPES</Text>
                        <Group gap={6}>
                          {(investigateData.summary.attack_types || []).map((t: string) => (
                            <Badge key={t} size="sm" variant="light" color="orange">{t}</Badge>
                          ))}
                          {(!investigateData.summary.attack_types || investigateData.summary.attack_types.length === 0) && (
                            <Text size="xs" c="dimmed">None</Text>
                          )}
                        </Group>
                      </Box>
                      <Box>
                        <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>MITRE ATT&CK TECHNIQUES</Text>
                        <Group gap={6}>
                          {(investigateData.summary.techniques_used || []).map((t: string) => (
                            <Badge key={t} size="sm" variant="light" color="blue">{t}</Badge>
                          ))}
                          {(!investigateData.summary.techniques_used || investigateData.summary.techniques_used.length === 0) && (
                            <Text size="xs" c="dimmed">None</Text>
                          )}
                        </Group>
                      </Box>
                      {(investigateData.sources?.shodan && !investigateData.sources.shodan.error) && (
                        <>
                          <Divider />
                          <Box>
                            <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>SHODAN SUMMARY</Text>
                            <Stack gap={4}>
                              {investigateData.sources.shodan.country_names && (
                                <Text size="xs">Country: {investigateData.sources.shodan.country_names.join(", ")}</Text>
                              )}
                              {investigateData.sources.shodan.org && (
                                <Text size="xs">Org: {investigateData.sources.shodan.org}</Text>
                              )}
                              {investigateData.sources.shodan.os && (
                                <Text size="xs">OS: {investigateData.sources.shodan.os}</Text>
                              )}
                              {investigateData.sources.shodan.ports && (
                                <Text size="xs">Open ports: {investigateData.sources.shodan.ports.join(", ")}</Text>
                              )}
                            </Stack>
                          </Box>
                        </>
                      )}
                    </>
                  )}
                </Stack>
              </Tabs.Panel>

              {/* Sentinel Tab */}
              <Tabs.Panel value="sentinel">
                <Stack gap="sm">
                  {investigateData.sources?.sentinel ? (
                    <>
                      <Group gap="md">
                        <Box>
                          <Text size="xs" c="dimmed" className="pitbull-mono">FIRST SEEN</Text>
                          <Text size="sm">{investigateData.sources.sentinel.first_seen ? new Date(investigateData.sources.sentinel.first_seen * 1000).toLocaleString() : "—"}</Text>
                        </Box>
                        <Box>
                          <Text size="xs" c="dimmed" className="pitbull-mono">LAST SEEN</Text>
                          <Text size="sm">{investigateData.sources.sentinel.last_seen ? new Date(investigateData.sources.sentinel.last_seen * 1000).toLocaleString() : "—"}</Text>
                        </Box>
                      </Group>
                      <Box>
                        <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>DETECTION COUNT: {investigateData.sources.sentinel.detection_count}</Text>
                      </Box>
                      <Box>
                        <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>ATTACK TYPES</Text>
                        <Group gap={6}>
                          {(investigateData.sources.sentinel.attack_types || []).map((t: string) => (
                            <Badge key={t} size="sm" color="orange" variant="light">{t}</Badge>
                          ))}
                        </Group>
                      </Box>
                      <Box>
                        <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>TECHNIQUES</Text>
                        <Group gap={6}>
                          {(investigateData.sources.sentinel.techniques_used || []).map((t: string) => (
                            <Badge key={t} size="sm" color="blue" variant="light">{t}</Badge>
                          ))}
                        </Group>
                      </Box>
                    </>
                  ) : (
                    <Text size="xs" c="dimmed">No Sentinel profile data</Text>
                  )}
                </Stack>
              </Tabs.Panel>

              {/* Shodan Tab */}
              <Tabs.Panel value="shodan">
                <Stack gap="sm">
                  {investigateData.sources?.shodan ? (
                    investigateData.sources.shodan.error ? (
                      <Alert color="orange" icon={<IconAlertTriangle size={16} />}>
                        {investigateData.sources.shodan.error}
                      </Alert>
                    ) : (
                      <>
                        <Group gap="md">
                          {investigateData.sources.shodan.country_names && (
                            <Box>
                              <Text size="xs" c="dimmed" className="pitbull-mono">COUNTRY</Text>
                              <Text size="sm">{investigateData.sources.shodan.country_names.join(", ")}</Text>
                            </Box>
                          )}
                          {investigateData.sources.shodan.org && (
                            <Box>
                              <Text size="xs" c="dimmed" className="pitbull-mono">ORGANIZATION</Text>
                              <Text size="sm">{investigateData.sources.shodan.org}</Text>
                            </Box>
                          )}
                          {investigateData.sources.shodan.os && (
                            <Box>
                              <Text size="xs" c="dimmed" className="pitbull-mono">OS</Text>
                              <Text size="sm">{investigateData.sources.shodan.os}</Text>
                            </Box>
                          )}
                        </Group>
                        {investigateData.sources.shodan.ports && (
                          <Box>
                            <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>OPEN PORTS</Text>
                            <Group gap={6}>
                              {investigateData.sources.shodan.ports.map((p: number) => (
                                <Badge key={p} size="sm" color="red" variant="filled">{p}</Badge>
                              ))}
                            </Group>
                          </Box>
                        )}
                        {investigateData.sources.shodan.services && (
                          <Box>
                            <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>SERVICES</Text>
                            <Stack gap={4}>
                              {(Array.isArray(investigateData.sources.shodan.services) ? investigateData.sources.shodan.services : []).map((svc: any, i: number) => (
                                <Group key={i} gap="sm">
                                  <Badge size="xs" variant="light" color="cyan">{svc.port}/{svc.transport || "tcp"}</Badge>
                                  <Text size="xs">{svc.product || svc.service || "unknown"}</Text>
                                </Group>
                              ))}
                            </Stack>
                          </Box>
                        )}
                        {investigateData.sources.shodan.hostnames && (
                          <Box>
                            <Text size="xs" c="dimmed" className="pitbull-mono" mb={4}>HOSTNAMES</Text>
                            <Stack gap={2}>
                              {investigateData.sources.shodan.hostnames.map((h: string) => (
                                <Text key={h} size="xs" c="cyan" className="pitbull-mono">{h}</Text>
                              ))}
                            </Stack>
                          </Box>
                        )}
                      </>
                    )
                  ) : (
                    <Text size="xs" c="dimmed">No Shodan data available</Text>
                  )}
                </Stack>
              </Tabs.Panel>

              {/* Neo4j Tab */}
              <Tabs.Panel value="neo4j">
                <Stack gap="sm">
                  {investigateData.sources?.neo4j && investigateData.sources.neo4j.length > 0 ? (
                    investigateData.sources.neo4j.map((node: any, i: number) => (
                      <Card key={i} withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
                        <Group gap="sm" justify="space-between">
                          <Group gap="sm">
                            <Badge size="xs" color="blue" variant="light">{node.labels?.join(", ")}</Badge>
                            <Text size="xs" c="cyan" className="pitbull-mono">
                              {Object.entries(node.props || {}).slice(0, 3).map(([k, v]) => `${k}=${String(v).slice(0, 30)}`).join("  ")}
                            </Text>
                          </Group>
                        </Group>
                      </Card>
                    ))
                  ) : (
                    <Text size="xs" c="dimmed">No Neo4j nodes found for this IP</Text>
                  )}
                  {investigateData.sources?.neo4j_events && investigateData.sources.neo4j_events.length > 0 && (
                    <>
                      <Divider />
                      <Text size="xs" c="dimmed" className="pitbull-mono">STORED ATTACK EVENTS ({investigateData.sources.neo4j_events.length})</Text>
                      <Stack gap={4}>
                        {investigateData.sources.neo4j_events.map((e: any, i: number) => (
                          <Group key={i} gap="sm">
                            <Badge size="xs" color={SEVERITY_COLORS[e.severity] || "gray"} variant="filled">{e.severity}</Badge>
                            <Text size="xs">{e.attack_type}</Text>
                            <Text size="xs" c="dimmed" className="pitbull-mono">{e.technique_id}</Text>
                          </Group>
                        ))}
                      </Stack>
                    </>
                  )}
                </Stack>
              </Tabs.Panel>

              {/* Attacks Tab */}
              <Tabs.Panel value="attacks">
                <Stack gap="sm">
                  {investigateData.sources?.attacks && investigateData.sources.attacks.length > 0 ? (
                    <Table striped highlightOnHover>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>Severity</Table.Th>
                          <Table.Th>Type</Table.Th>
                          <Table.Th>ATT&CK</Table.Th>
                          <Table.Th>Time</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {investigateData.sources.attacks.map((a: any, i: number) => (
                          <Table.Tr key={i}>
                            <Table.Td>
                              <Badge size="xs" color={SEVERITY_COLORS[a.severity] || "gray"} variant="filled">
                                {a.severity}
                              </Badge>
                            </Table.Td>
                            <Table.Td><Text size="xs">{a.attack_type}</Text></Table.Td>
                            <Table.Td><Code fz="xs">{a.technique_id}</Code></Table.Td>
                            <Table.Td>
                              <Text size="xs" c="dimmed" className="pitbull-mono">
                                {typeof a.timestamp === "number" ? new Date(a.timestamp * 1000).toLocaleTimeString() : new Date(a.timestamp).toLocaleTimeString()}
                              </Text>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  ) : (
                    <Text size="xs" c="dimmed">No attacks recorded from this IP</Text>
                  )}
                </Stack>
              </Tabs.Panel>
            </ScrollArea>
          </Tabs>
        ) : (
          <Stack p="md">
            <Text size="sm" c="dimmed">No data available</Text>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}