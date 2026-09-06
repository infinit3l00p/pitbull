import { useState, useEffect, useCallback } from "react";
import {
  Card, Text, Group, Stack, Table, Badge, Title, Progress,
  SimpleGrid, ScrollArea, Skeleton, ActionIcon, Tooltip, RingProgress,
} from "@mantine/core";
import {
  IconShield, IconAlertTriangle, IconActivity, IconNetwork,
  IconRefresh, IconRadar,
} from "@tabler/icons-react";

const API_KEY = localStorage.getItem("pitbull_api_key") || "pitbull-explorer-dev-key-2026";
const API_BASE = "http://127.0.0.1:8001";

interface SuricataStatus {
  running: boolean;
  total_alerts: number;
  total_flows: number;
  total_http: number;
  total_dns: number;
  total_tls: number;
  total_drops: number;
  total_stats: number;
  eve_json_path: string;
  suricata_version: string;
  last_stats: any;
}

interface SuriAlert {
  id: string;
  signature: string;
  category: string;
  severity: string;
  action: string;
  protocol: string;
  timestamp: string;
}

interface AlertedHost {
  src_ip: string;
  dst_ip: string;
  alert_count: number;
  severity: string;
}

interface RuleSummary {
  signature_id: string;
  signature: string;
  category: string;
  severity: number;
  action: string;
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "red", WARNING: "orange", INFO: "blue",
};
const SEV_NUM_COLORS: Record<number, string> = {
  1: "red", 2: "orange", 3: "blue",
};

export default function SuricataPage() {
  const [status, setStatus] = useState<SuricataStatus | null>(null);
  const [alerts, setAlerts] = useState<SuriAlert[]>([]);
  const [topAlerted, setTopAlerted] = useState<AlertedHost[]>([]);
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = useCallback(async () => {
    setRefreshing(true);
    try {
      const headers = { "X-API-Key": API_KEY };
      const [st, al, ta, ru] = await Promise.all([
        fetch(`${API_BASE}/api/v1/suricata/status`, { headers }),
        fetch(`${API_BASE}/api/v1/suricata/alerts?limit=50`, { headers }),
        fetch(`${API_BASE}/api/v1/suricata/top-alerted?limit=20`, { headers }),
        fetch(`${API_BASE}/api/v1/suricata/rules?limit=20`, { headers }),
      ]);
      if (st.ok) setStatus(await st.json());
      if (al.ok) { const d = await al.json(); setAlerts(d.alerts || []); }
      if (ta.ok) { const d = await ta.json(); setTopAlerted(d.hosts || []); }
      if (ru.ok) { const d = await ru.json(); setRules(d.rules || []); }
    } catch (e) { console.error("suricata fetch error:", e); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const criticalAlerts = alerts.filter(a => a.severity === "CRITICAL");
  const warningAlerts = alerts.filter(a => a.severity === "WARNING");

  return (
    <Stack gap="md">
      <Group justify="space-between" align="center">
        <Group gap="md">
          <IconShield size={32} color="#ef4444" />
          <div>
            <Title order={3} className="pitbull-display" c="red.4">
              IDS / IPS — SURICATA
            </Title>
            <Text size="xs" c="dimmed" className="pitbull-mono">
              Intrusion Detection & Prevention System v{status?.suricata_version || "8.0.6"}
            </Text>
          </div>
        </Group>
        <Group gap="sm">
          <Badge size="lg" variant="dot" color={status?.running ? "green" : "red"}
            styles={{ root: { background: "transparent", border: `1px solid ${status?.running ? "rgba(52,211,153,0.3)" : "rgba(239,68,68,0.3)"}` } }}>
            {status?.running ? "SURICATA ACTIVE" : "SURICATA OFFLINE"}
          </Badge>
          <Tooltip label="Refresh"><ActionIcon variant="subtle" color="red" onClick={fetchData} loading={refreshing}>
            <IconRefresh size={18} />
          </ActionIcon></Tooltip>
        </Group>
      </Group>

      {/* Stats Grid */}
      <SimpleGrid cols={4} spacing="md">
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">TOTAL ALERTS</Text>
            <IconAlertTriangle size={20} color="#ef4444" />
          </Group>
          <Text size="xl" fw={900} c="red.4" className="pitbull-mono">{status?.total_alerts ?? 0}</Text>
        </Card>
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">FLOWS TRACKED</Text>
            <IconActivity size={20} color="#22d3ee" />
          </Group>
          <Text size="xl" fw={900} c="cyan.4" className="pitbull-mono">{status?.total_flows ?? 0}</Text>
        </Card>
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">PACKETS DROPPED</Text>
            <IconAlertTriangle size={20} color="#f59e0b" />
          </Group>
          <Text size="xl" fw={900} c="orange.4" className="pitbull-mono">{status?.total_drops ?? 0}</Text>
        </Card>
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" className="pitbull-mono">DNS / HTTP / TLS</Text>
            <IconRadar size={20} color="#34d399" />
          </Group>
          <Text size="lg" fw={700} c="green.4" className="pitbull-mono">
            {status?.total_dns ?? 0} / {status?.total_http ?? 0} / {status?.total_tls ?? 0}
          </Text>
        </Card>
      </SimpleGrid>

      {/* Severity Distribution */}
      {alerts.length > 0 && (
        <Card withBorder style={{ background: "var(--pitbull-card)" }} p="sm">
          <Group gap="xs" grow>
            {[
              { label: "Critical", count: criticalAlerts.length, color: "red" },
              { label: "Warning", count: warningAlerts.length, color: "orange" },
              { label: "Info", count: alerts.length - criticalAlerts.length - warningAlerts.length, color: "blue" },
            ].map(s => (
              <div key={s.label}>
                <Group justify="space-between" mb={4}>
                  <Text size="xs" c="dimmed">{s.label}</Text>
                  <Text size="xs" fw={700} c={s.color}>{s.count}</Text>
                </Group>
                <Progress value={alerts.length > 0 ? (s.count / alerts.length) * 100 : 0} color={s.color} size="sm" radius="xs" />
              </div>
            ))}
          </Group>
        </Card>
      )}

      {/* Alerts Table */}
      <Card withBorder style={{ background: "var(--pitbull-card)" }}>
        <Group justify="space-between" mb="md">
          <Title order={5} c="red.4" className="pitbull-display">🛡️ SURICATA ALERTS</Title>
          <Badge size="sm" variant="light" color="red">{alerts.length} alerts</Badge>
        </Group>
        {loading ? (
          <Stack gap="xs">{[...Array(5)].map((_, i) => <Skeleton key={i} height={40} />)}</Stack>
        ) : alerts.length === 0 ? (
          <Text c="dimmed" ta="center" py="xl">No IDS alerts detected</Text>
        ) : (
          <ScrollArea h={400}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Timestamp</Table.Th>
                  <Table.Th>Severity</Table.Th>
                  <Table.Th>Signature</Table.Th>
                  <Table.Th>Category</Table.Th>
                  <Table.Th>Proto</Table.Th>
                  <Table.Th>Action</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {alerts.map((a, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Text size="xs" className="pitbull-mono" c="dimmed">{a.timestamp?.slice(11, 19) || ""}</Text></Table.Td>
                    <Table.Td><Badge size="xs" color={SEV_COLORS[a.severity] || "gray"} variant="light">{a.severity}</Badge></Table.Td>
                    <Table.Td><Text size="xs">{a.signature}</Text></Table.Td>
                    <Table.Td><Badge size="xs" variant="dot" color="cyan">{a.category}</Badge></Table.Td>
                    <Table.Td><Text size="xs" className="pitbull-mono">{a.protocol}</Text></Table.Td>
                    <Table.Td><Badge size="xs" color={a.action === "blocked" ? "red" : "gray"} variant="light">{a.action}</Badge></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        )}
      </Card>

      {/* Top Alerted Hosts */}
      {topAlerted.length > 0 && (
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Title order={5} c="orange.4" className="pitbull-display" mb="md">⚠️ TOP ALERTED HOST PAIRS</Title>
          <ScrollArea h={200}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Source IP</Table.Th>
                  <Table.Th>Dest IP</Table.Th>
                  <Table.Th>Alerts</Table.Th>
                  <Table.Th>Severity</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {topAlerted.map((h, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Text size="xs" className="pitbull-mono">{h.src_ip}</Text></Table.Td>
                    <Table.Td><Text size="xs" className="pitbull-mono">{h.dst_ip}</Text></Table.Td>
                    <Table.Td><Badge size="xs" color="red" variant="light">{h.alert_count}</Badge></Table.Td>
                    <Table.Td><Badge size="xs" color={SEV_COLORS[h.severity] || "gray"} variant="dot">{h.severity}</Badge></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Card>
      )}

      {/* Rule Summary */}
      {rules.length > 0 && (
        <Card withBorder style={{ background: "var(--pitbull-card)" }}>
          <Title order={5} c="cyan.4" className="pitbull-display" mb="md">📋 ACTIVE RULES SUMMARY</Title>
          <ScrollArea h={200}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>SID</Table.Th>
                  <Table.Th>Signature</Table.Th>
                  <Table.Th>Category</Table.Th>
                  <Table.Th>Severity</Table.Th>
                  <Table.Th>Action</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rules.map((r, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Text size="xs" className="pitbull-mono">{r.signature_id}</Text></Table.Td>
                    <Table.Td><Text size="xs">{r.signature}</Text></Table.Td>
                    <Table.Td><Badge size="xs" variant="dot" color="cyan">{r.category}</Badge></Table.Td>
                    <Table.Td><Badge size="xs" color={SEV_NUM_COLORS[r.severity] || "gray"} variant="light">{r.severity}</Badge></Table.Td>
                    <Table.Td><Badge size="xs" color={r.action === "blocked" ? "red" : "gray"} variant="light">{r.action}</Badge></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Card>
      )}

      <Text size="xs" c="dimmed" className="pitbull-mono" ta="center">
        Suricata 8.0.6 · 52,106 active rules · EVE JSON ingestion · Feeds into Sentinel
      </Text>
    </Stack>
  );
}