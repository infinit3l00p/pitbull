import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Text,
  Group,
  Stack,
  Table,
  Badge,
  Title,
  Progress,
  SimpleGrid,
  Alert,
  ScrollArea,
  Skeleton,
  ActionIcon,
  Tooltip,
} from "@mantine/core";
import {
  IconActivity,
  IconAlertTriangle,
  IconNetwork,
  IconRefresh,
  IconShield,
} from "@tabler/icons-react";

const API_KEY = localStorage.getItem("pitbull_api_key") || "pitbull-explorer-dev-key-2026";
const API_BASE = "http://127.0.0.1:8001";

interface NtopngStatus {
  running: boolean;
  total_flows: number;
  total_alerts: number;
  total_hosts: number;
  base_url: string;
}

interface NetworkAlert {
  id: string;
  type: string;
  severity: string;
  description: string;
  timestamp: number;
  source_ip?: string;
  dest_ip?: string;
  protocol?: string;
  score?: number;
  bytes_sent?: number;
  bytes_recv?: number;
  cli_port?: number;
  srv_port?: number;
  info?: string;
  concerned_hosts?: string[];
}

interface TopTalker {
  ip: string;
  name: string;
  country: string;
  total_bytes: number;
  connections: number;
}

interface SuspiciousHost {
  ip: string;
  name: string;
  alert_count: number;
  alert_types: string[];
}

const SEVERITY_COLORS: Record<string, string> = {
  EMERGENCY: "red",
  CRITICAL: "red",
  ERROR: "orange",
  WARNING: "yellow",
  NOTICE: "blue",
  INFO: "gray",
};

const ALERT_TYPE_LABELS: Record<string, string> = {
  ndpi_suspicious_entropy: "Suspicious Entropy",
  ndpi_unidirectional_traffic: "Unidirectional Traffic",
  known_proto_on_non_std_port: "Known Protocol on Non-Standard Port",
  remote_access: "Remote Access Detected",
  unexpected_dns: "Unexpected DNS Server",
  unexpected_dhcp: "Unexpected DHCP Server",
  unexpected_ntp: "Unexpected NTP Server",
  unexpected_smtp: "Unexpected SMTP Server",
  "http_suspicious_content": "HTTP Suspicious Content",
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function NtopngPage() {
  const [status, setStatus] = useState<NtopngStatus | null>(null);
  const [alerts, setAlerts] = useState<NetworkAlert[]>([]);
  const [talkers, setTalkers] = useState<TopTalker[]>([]);
  const [suspicious, setSuspicious] = useState<SuspiciousHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = useCallback(async () => {
    setRefreshing(true);
    try {
      const headers = { "X-API-Key": API_KEY };
      const [statusRes, alertsRes, talkersRes, suspiciousRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/ntopng/status`, { headers }),
        fetch(`${API_BASE}/api/v1/ntopng/alerts?limit=50`, { headers }),
        fetch(`${API_BASE}/api/v1/ntopng/top-talkers?limit=20`, { headers }),
        fetch(`${API_BASE}/api/v1/ntopng/suspicious`, { headers }),
      ]);

      if (statusRes.ok) setStatus(await statusRes.json());
      if (alertsRes.ok) {
        const data = await alertsRes.json();
        setAlerts(data.alerts || []);
      }
      if (talkersRes.ok) {
        const data = await talkersRes.json();
        setTalkers(data.hosts || []);
      }
      if (suspiciousRes.ok) {
        const data = await suspiciousRes.json();
        setSuspicious(data.hosts || []);
      }
    } catch (err) {
      console.error("ntopng data fetch error:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const criticalAlerts = alerts.filter((a) => ["EMERGENCY", "CRITICAL", "ERROR"].includes(a.severity));
  const warningAlerts = alerts.filter((a) => a.severity === "WARNING" || a.severity === "NOTICE");

  return (
    <Stack gap="md">
      {/* Header */}
      <Group justify="space-between" align="center">
        <Group gap="md">
          <IconNetwork size={32} color="#22d3ee" />
          <div>
            <Title order={3} className="pitbull-display" c="cyan.4">
              NETWORK TRAFFIC INTELLIGENCE
            </Title>
            <Text size="xs" c="dimmed" className="pitbull-mono">
              Live data from ntopng → PITBULL Neo4j graph
            </Text>
          </div>
        </Group>
        <Group gap="sm">
          <Badge
            size="lg"
            variant="dot"
            color={status?.running ? "green" : "red"}
            styles={{ root: { background: "transparent", border: `1px solid ${status?.running ? "rgba(52,211,153,0.3)" : "rgba(239,68,68,0.3)"}` } }}
          >
            {status?.running ? "COLLECTOR ACTIVE" : "COLLECTOR OFFLINE"}
          </Badge>
          <Tooltip label="Refresh">
            <ActionIcon variant="subtle" color="cyan" onClick={fetchData} loading={refreshing}>
              <IconRefresh size={18} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Stats Cards */}
      <SimpleGrid cols={4} spacing="md">
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">TOTAL ALERTS</Text>
            <IconAlertTriangle size={20} color="#f59e0b" />
          </Group>
          <Text size="xl" fw={900} c="orange.4" className="pitbull-mono">
            {status?.total_alerts ?? 0}
          </Text>
        </Card>
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">FLOWS TRACKED</Text>
            <IconActivity size={20} color="#22d3ee" />
          </Group>
          <Text size="xl" fw={900} c="cyan.4" className="pitbull-mono">
            {status?.total_flows ?? 0}
          </Text>
        </Card>
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">HOSTS SEEN</Text>
            <IconNetwork size={20} color="#34d399" />
          </Group>
          <Text size="xl" fw={900} c="green.4" className="pitbull-mono">
            {status?.total_hosts ?? 0}
          </Text>
        </Card>
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">CRITICAL</Text>
            <IconShield size={20} color="#ef4444" />
          </Group>
          <Text size="xl" fw={900} c="red.4" className="pitbull-mono">
            {criticalAlerts.length}
          </Text>
        </Card>
      </SimpleGrid>

      {/* Alert Severity Bar */}
      {alerts.length > 0 && (
        <Card withBorder style={{ background: "var(--pitbull-card)" }} p="sm">
          <Group gap="xs" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">ALERT SEVERITY DISTRIBUTION</Text>
          </Group>
          <Group gap="xs" grow>
            {[
              { label: "Critical", count: criticalAlerts.length, color: "red" },
              { label: "Warning", count: warningAlerts.length, color: "orange" },
              { label: "Info", count: alerts.length - criticalAlerts.length - warningAlerts.length, color: "blue" },
            ].map((s) => (
              <div key={s.label}>
                <Group justify="space-between" mb={4}>
                  <Text size="xs" c="dimmed">{s.label}</Text>
                  <Text size="xs" fw={700} c={s.color}>{s.count}</Text>
                </Group>
                <Progress
                  value={alerts.length > 0 ? (s.count / alerts.length) * 100 : 0}
                  color={s.color}
                  size="sm"
                  radius="xs"
                />
              </div>
            ))}
          </Group>
        </Card>
      )}

      {/* Alerts Table */}
      <Card withBorder style={{ background: "var(--pitbull-card)" }}>
        <Group justify="space-between" mb="md">
          <Title order={5} c="cyan.4" className="pitbull-display">
            📡 NETWORK ALERTS (from ntopng)
          </Title>
          <Badge size="sm" variant="light" color="cyan">{alerts.length} alerts</Badge>
        </Group>

        {loading ? (
          <Stack gap="xs">
            {[...Array(5)].map((_, i) => <Skeleton key={i} height={40} />)}
          </Stack>
        ) : alerts.length === 0 ? (
          <Text c="dimmed" ta="center" py="xl">No alerts detected</Text>
        ) : (
          <ScrollArea h={450}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Time</Table.Th>
                  <Table.Th>Severity</Table.Th>
                  <Table.Th>Alert Type</Table.Th>
                  <Table.Th>Source → Dest</Table.Th>
                  <Table.Th>Proto</Table.Th>
                  <Table.Th>Bytes</Table.Th>
                  <Table.Th>Score</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {alerts.map((alert, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>
                      <Text size="xs" className="pitbull-mono" c="dimmed">
                        {formatTime(alert.timestamp)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge
                        size="xs"
                        color={SEVERITY_COLORS[alert.severity] || "gray"}
                        variant="light"
                      >
                        {alert.severity}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">
                        {ALERT_TYPE_LABELS[alert.type] || alert.type}
                      </Text>
                      {alert.description && (
                        <Text size="xs" c="dimmed">{alert.description}</Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4} wrap="nowrap" align="center">
                        <Text size="xs" className="pitbull-mono" c="cyan.4" style={{ whiteSpace: "nowrap" }}>
                          {alert.source_ip || "—"}
                        </Text>
                        <Text size="xs" c="dimmed" className="pitbull-mono" style={{ flexShrink: 0 }}>
                          →
                        </Text>
                        <Text size="xs" className="pitbull-mono" c="orange.4" style={{ whiteSpace: "nowrap" }}>
                          {alert.dest_ip || "—"}
                        </Text>
                        {(alert.cli_port || alert.srv_port) ? (
                          <Text size="xs" c="dimmed" className="pitbull-mono" style={{ flexShrink: 0 }}>
                            :{alert.srv_port || "?"}
                          </Text>
                        ) : null}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Badge size="xs" variant="dot" color="cyan">{alert.protocol || "?"}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" className="pitbull-mono">
                        {alert.bytes_sent ? formatBytes(alert.bytes_sent) : "—"}
                      </Text>
                      {alert.bytes_recv ? (
                        <Text size="xs" c="dimmed" className="pitbull-mono">
                          ↓ {formatBytes(alert.bytes_recv)}
                        </Text>
                      ) : null}
                    </Table.Td>
                    <Table.Td>
                      <Badge size="xs" variant="light" color="orange">{alert.score || 0}</Badge>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        )}
      </Card>

      {/* Suspicious Hosts */}
      {suspicious.length > 0 && (
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Title order={5} c="red.4" className="pitbull-display" mb="md">
            ⚠️ SUSPICIOUS HOSTS
          </Title>
          <ScrollArea h={200}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>IP</Table.Th>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Alerts</Table.Th>
                  <Table.Th>Types</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {suspicious.map((host, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Text size="xs" className="pitbull-mono">{host.ip}</Text></Table.Td>
                    <Table.Td><Text size="xs">{host.name || "—"}</Text></Table.Td>
                    <Table.Td><Badge size="xs" color="red" variant="light">{host.alert_count}</Badge></Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {(host.alert_types || []).slice(0, 3).map((t, j) => (
                          <Badge key={j} size="xs" variant="dot" color="orange">
                            {ALERT_TYPE_LABELS[t] || t}
                          </Badge>
                        ))}
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Card>
      )}

      {/* Top Talkers */}
      {talkers.length > 0 && (
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Title order={5} c="green.4" className="pitbull-display" mb="md">
            📊 TOP TALKERS (by traffic volume)
          </Title>
          <ScrollArea h={200}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>IP</Table.Th>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Country</Table.Th>
                  <Table.Th>Traffic</Table.Th>
                  <Table.Th>Connections</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {talkers.map((host, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Text size="xs" className="pitbull-mono">{host.ip}</Text></Table.Td>
                    <Table.Td><Text size="xs">{host.name || "—"}</Text></Table.Td>
                    <Table.Td><Text size="xs">{host.country || "—"}</Text></Table.Td>
                    <Table.Td><Text size="xs" className="pitbull-mono">{formatBytes(host.total_bytes)}</Text></Table.Td>
                    <Table.Td><Badge size="xs" variant="light" color="cyan">{host.connections}</Badge></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Card>
      )}

      {/* Info Alert */}
      <Alert icon={<IconNetwork size={16} />} color="cyan" variant="light">
        <Text size="xs">
          Data sourced from ntopng (port 3000) via SQLite alert database + Neo4j graph.
          Collector polls every 15s for alerts, 30s for flows and hosts.
          Alerts feed directly into PITBULL's Sentinel attack detection engine.
        </Text>
      </Alert>
    </Stack>
  );
}