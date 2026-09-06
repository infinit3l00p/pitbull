import { useState, useEffect, useCallback } from "react";
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
  Progress,
  SimpleGrid,
  ThemeIcon,
  Box,
  Alert,
  Modal,
  Tabs,
  Skeleton,
  Divider,
  Tooltip,
  RingProgress,
} from "@mantine/core";
import {
  IconBolt,
  IconShield,
  IconAlertTriangle,
  IconCheck,
  IconX,
  IconClock,
  IconRefresh,
  IconHistory,
  IconLock,
  IconLockOpen,
  IconEye,
  IconBan,
  IconBug,
  IconFlame,
  IconActivity,
  IconChevronRight,
} from "@tabler/icons-react";
import { responseApi, type ResponseStatus, type ResponseAction, type PendingApproval, type ResponseRules } from "../api-response";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "red",
  HIGH: "orange",
  MEDIUM: "yellow",
  LOW: "blue",
};

const STATUS_COLORS: Record<string, string> = {
  executed: "green",
  pending_approval: "yellow",
  rate_limited: "orange",
  validation_failed: "red",
  verification_failed: "red",
  error: "red",
  auto_reversed: "cyan",
  skipped: "gray",
  approved_executed: "green",
  rejected: "gray",
};

const ACTION_LEVEL_COLORS: Record<number, string> = {
  0: "blue",
  1: "cyan",
  2: "yellow",
  3: "orange",
  4: "red",
  5: "grape",
};

const ACTION_ICONS: Record<string, typeof IconBolt> = {
  LOG: IconEye,
  EVIDENCE_CAPTURE: IconBug,
  ENRICH: IconActivity,
  ALERT_HUMAN: IconAlertTriangle,
  THROTTLE: IconClock,
  DECEIVE: IconShield,
  PROXY_ROTATE: IconRefresh,
  IP_BLOCK: IconBan,
  PORT_CLOSE: IconLock,
  SESSION_KILL: IconX,
  PROCESS_QUARANTINE: IconLock,
  NETWORK_QUARANTINE: IconLock,
  PROCESS_KILL: IconFlame,
  SERVICE_STOP: IconX,
  CONTAINER_KILL: IconX,
  SERVICE_DISABLE: IconFlame,
  NETWORK_ISOLATE_HOST: IconFlame,
};

function timeAgo(ts: number): string {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function ResponsePage() {
  const [status, setStatus] = useState<ResponseStatus | null>(null);
  const [history, setHistory] = useState<ResponseAction[]>([]);
  const [pending, setPending] = useState<PendingApproval[]>([]);
  const [rules, setRules] = useState<ResponseRules | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("history");
  const [detailsModal, setDetailsModal] = useState<{ open: boolean; action: ResponseAction | null }>({ open: false, action: null });

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const [s, h, p, r] = await Promise.all([
        responseApi.status(),
        responseApi.history(50),
        responseApi.pending(),
        responseApi.rules(),
      ]);
      setStatus(s);
      setHistory(h.actions || []);
      setPending(p.pending || []);
      setRules(r);
    } catch (e) {
      console.error("Response API error:", e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [load]);

  const handleApprove = async (id: string) => {
    try {
      await responseApi.approve(id);
      await load();
    } catch (e) {
      console.error("Approve error:", e);
    }
  };

  const handleReject = async (id: string) => {
    try {
      await responseApi.reject(id);
      await load();
    } catch (e) {
      console.error("Reject error:", e);
    }
  };

  if (loading) {
    return (
      <Stack gap="md">
        <Skeleton height={120} />
        <Skeleton height={200} />
        <Skeleton height={300} />
      </Stack>
    );
  }

  const totalActions = status?.stats.total_actions || 0;
  const byAction = status?.stats.by_action || {};
  const byAttackType = status?.stats.by_attack_type || {};
  const maxActionCount = Math.max(...Object.values(byAction), 1);

  return (
    <Stack gap="md">
      {/* Header */}
      <Group justify="space-between" align="center">
        <Group gap="sm">
          <ThemeIcon size={42} radius="md" variant="light" color={status?.running ? "green" : "red"}>
            <IconBolt size={24} />
          </ThemeIcon>
          <Stack gap={0}>
            <Text size="xl" fw={900} className="pitbull-display" c="cyan.4">
              Response Engine
            </Text>
            <Text size="xs" c="dimmed" className="pitbull-mono">
              Graduated automated threat response · {status?.running ? "ACTIVE" : "STOPPED"}
            </Text>
          </Stack>
        </Group>
        <Group gap="xs">
          <Button
            size="xs"
            variant="light"
            leftSection={<IconRefresh size={14} />}
            loading={refreshing}
            onClick={load}
          >
            Refresh
          </Button>
        </Group>
      </Group>

      {/* Stats Cards */}
      <SimpleGrid cols={{ base: 2, md: 4, lg: 6 }} spacing="sm">
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <ThemeIcon size={32} variant="light" color="cyan">
              <IconActivity size={18} />
            </ThemeIcon>
            <Stack gap={0}>
              <Text size="xs" c="dimmed">Total Actions</Text>
              <Text size="xl" fw={700} c="cyan.4">{totalActions}</Text>
            </Stack>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <ThemeIcon size={32} variant="light" color="orange">
              <IconClock size={18} />
            </ThemeIcon>
            <Stack gap={0}>
              <Text size="xs" c="dimmed">Rate Limited</Text>
              <Text size="xl" fw={700} c="orange.4">{status?.stats.total_blocked_by_rate_limit || 0}</Text>
            </Stack>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <ThemeIcon size={32} variant="light" color="yellow">
              <IconAlertTriangle size={18} />
            </ThemeIcon>
            <Stack gap={0}>
              <Text size="xs" c="dimmed">Pending Approval</Text>
              <Text size="xl" fw={700} c="yellow.4">{status?.pending_approvals || 0}</Text>
            </Stack>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <ThemeIcon size={32} variant="light" color="grape">
              <IconRefresh size={18} />
            </ThemeIcon>
            <Stack gap={0}>
              <Text size="xs" c="dimmed">Auto-Reversed</Text>
              <Text size="xl" fw={700} c="grape.4">{status?.stats.total_auto_reversed || 0}</Text>
            </Stack>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <ThemeIcon size={32} variant="light" color="blue">
              <IconShield size={18} />
            </ThemeIcon>
            <Stack gap={0}>
              <Text size="xs" c="dimmed">Active Actions</Text>
              <Text size="xl" fw={700} c="blue.4">{status?.active_actions || 0}</Text>
            </Stack>
          </Group>
        </Card>
        <Card withBorder padding="sm" style={{ borderColor: "var(--pitbull-border)" }}>
          <Group gap="xs" align="center">
            <ThemeIcon size={32} variant="light" color="teal">
              <IconBug size={18} />
            </ThemeIcon>
            <Stack gap={0}>
              <Text size="xs" c="dimmed">Response Rules</Text>
              <Text size="xl" fw={700} c="teal.4">{status?.response_rules || 0}</Text>
            </Stack>
          </Group>
        </Card>
      </SimpleGrid>

      {/* Pending Approvals Alert */}
      {pending.length > 0 && (
        <Alert icon={<IconAlertTriangle size={16} />} color="red" variant="light" title={`${pending.length} Action(s) Need Approval`}>
          <Stack gap="xs">
            {pending.map((p) => (
              <Group key={p.approval_id} justify="space-between" align="center">
                <Group gap="sm">
                  <Badge color={ACTION_LEVEL_COLORS[rules?.actions[p.action]?.level ?? 4] || "red"} variant="filled">
                    {p.action}
                  </Badge>
                  <Text size="sm">
                    <Text span c="red.4" fw={600}>{p.attack_type}</Text>
                    <Text span c="dimmed"> from </Text>
                    <Text span fw={600}>{p.source_ip}</Text>
                  </Text>
                  <Text size="xs" c="dimmed">{timeAgo(p.queued_at)}</Text>
                </Group>
                <Group gap="xs">
                  <Button
                    size="xs"
                    color="green"
                    variant="light"
                    leftSection={<IconCheck size={14} />}
                    onClick={() => handleApprove(p.approval_id)}
                  >
                    Approve
                  </Button>
                  <Button
                    size="xs"
                    color="red"
                    variant="light"
                    leftSection={<IconX size={14} />}
                    onClick={() => handleReject(p.approval_id)}
                  >
                    Reject
                  </Button>
                </Group>
              </Group>
            ))}
          </Stack>
        </Alert>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onChange={(v) => setActiveTab(v || "history")}>
        <Tabs.List>
          <Tabs.Tab value="history" leftSection={<IconHistory size={14} />}>
            Action History
          </Tabs.Tab>
          <Tabs.Tab value="breakdown" leftSection={<IconActivity size={14} />}>
            Breakdown
          </Tabs.Tab>
          <Tabs.Tab value="rules" leftSection={<IconShield size={14} />}>
            Response Rules
          </Tabs.Tab>
        </Tabs.List>

        {/* Action History Tab */}
        <Tabs.Panel value="history">
          <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
            <ScrollArea h={500}>
              {history.length === 0 ? (
                <Text c="dimmed" ta="center" py="xl">No response actions yet</Text>
              ) : (
                <Table striped highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Time</Table.Th>
                      <Table.Th>Action</Table.Th>
                      <Table.Th>Attack Type</Table.Th>
                      <Table.Th>Source IP</Table.Th>
                      <Table.Th>Status</Table.Th>
                      <Table.Th>Details</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {history.slice().reverse().map((a, i) => {
                      const Icon = ACTION_ICONS[a.action] || IconBolt;
                      const level = rules?.actions[a.action]?.level ?? 0;
                      return (
                        <Table.Tr key={i}>
                          <Table.Td>
                            <Text size="xs" c="dimmed" className="pitbull-mono">
                              {timeAgo(a.timestamp)}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Group gap="xs">
                              <ThemeIcon size={24} variant="light" color={ACTION_LEVEL_COLORS[level] || "blue"}>
                                <Icon size={14} />
                              </ThemeIcon>
                              <Text size="sm" fw={500}>{a.action}</Text>
                            </Group>
                          </Table.Td>
                          <Table.Td>
                            <Badge size="sm" variant="light" color={SEVERITY_COLORS[a.attack_type in ["kernel_rootkit", "c2_communication", "container_escape", "privilege_escalation", "process_injection"] ? "CRITICAL" : a.attack_type in ["cryptojacking", "dns_exfiltration", "ssh_brute_force"] ? "HIGH" : "MEDIUM"] || "blue"}>
                              {a.attack_type}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Text size="xs" className="pitbull-mono">{a.source_ip}</Text>
                          </Table.Td>
                          <Table.Td>
                            <Badge
                              size="sm"
                              color={STATUS_COLORS[a.status] || "gray"}
                              variant={a.status === "executed" || a.status === "approved_executed" ? "filled" : "light"}
                            >
                              {a.status}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Tooltip label={a.details} position="left" multiline w={400}>
                              <Text size="xs" c="dimmed" truncate style={{ maxWidth: 200 }}>
                                {a.details}
                              </Text>
                            </Tooltip>
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              )}
            </ScrollArea>
          </Card>
        </Tabs.Panel>

        {/* Breakdown Tab */}
        <Tabs.Panel value="breakdown">
          <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
            {/* By Action */}
            <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
              <Text size="sm" fw={700} c="cyan.4" mb="md" className="pitbull-display">ACTIONS BY TYPE</Text>
              <Stack gap="xs">
                {Object.entries(byAction)
                  .sort(([, a], [, b]) => b - a)
                  .map(([action, count]) => {
                    const Icon = ACTION_ICONS[action] || IconBolt;
                    const level = rules?.actions[action]?.level ?? 0;
                    const pct = (count / maxActionCount) * 100;
                    return (
                      <Group key={action} gap="sm" align="center">
                        <ThemeIcon size={28} variant="light" color={ACTION_LEVEL_COLORS[level] || "blue"} style={{ flexShrink: 0 }}>
                          <Icon size={14} />
                        </ThemeIcon>
                        <Stack gap={2} style={{ flex: 1 }}>
                          <Group justify="space-between">
                            <Text size="xs" fw={500}>{action.replace(/_/g, " ")}</Text>
                            <Text size="xs" c="dimmed" className="pitbull-mono">{count}</Text>
                          </Group>
                          <Progress
                            value={pct}
                            size="xs"
                            color={ACTION_LEVEL_COLORS[level] || "blue"}
                            radius="xs"
                          />
                        </Stack>
                      </Group>
                    );
                  })}
                {Object.keys(byAction).length === 0 && (
                  <Text c="dimmed" ta="center" py="lg">No actions recorded</Text>
                )}
              </Stack>
            </Card>

            {/* By Attack Type */}
            <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
              <Text size="sm" fw={700} c="cyan.4" mb="md" className="pitbull-display">TRIGGERED BY ATTACK TYPE</Text>
              <Stack gap="xs">
                {Object.entries(byAttackType)
                  .sort(([, a], [, b]) => b - a)
                  .map(([type, count]) => {
                    const isCritical = ["kernel_rootkit", "c2_communication", "container_escape", "privilege_escalation", "process_injection"].includes(type);
                    const isHigh = ["cryptojacking", "dns_exfiltration", "ssh_brute_force", "ssh_password_spraying"].includes(type);
                    const color = isCritical ? "red" : isHigh ? "orange" : "blue";
                    const pct = (count / Math.max(...Object.values(byAttackType), 1)) * 100;
                    return (
                      <Group key={type} gap="sm" align="center">
                        <Badge size="sm" color={color} variant="light" style={{ flexShrink: 0, minWidth: 120 }}>
                          {type.replace(/_/g, " ")}
                        </Badge>
                        <Stack gap={2} style={{ flex: 1 }}>
                          <Group justify="space-between">
                            <Text size="xs" c="dimmed">{count} response{count !== 1 ? "s" : ""}</Text>
                          </Group>
                          <Progress value={pct} size="xs" color={color} radius="xs" />
                        </Stack>
                      </Group>
                    );
                  })}
                {Object.keys(byAttackType).length === 0 && (
                  <Text c="dimmed" ta="center" py="lg">No attacks triggered</Text>
                )}
              </Stack>
            </Card>
          </SimpleGrid>
        </Tabs.Panel>

        {/* Response Rules Tab */}
        <Tabs.Panel value="rules">
          <Card withBorder padding="md" style={{ borderColor: "var(--pitbull-border)" }}>
            <Group justify="space-between" mb="md">
              <Text size="sm" fw={700} c="cyan.4" className="pitbull-display">RESPONSE RULE MAPPING</Text>
              <Text size="xs" c="dimmed">{rules ? Object.keys(rules.rules).length : 0} attack types · {rules ? Object.keys(rules.actions).length : 0} action types</Text>
            </Group>
            <ScrollArea h={500}>
              <Table striped>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Attack Type</Table.Th>
                    <Table.Th>Response Chain</Table.Th>
                    <Table.Th>Levels</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {rules && Object.entries(rules.rules)
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([attackType, actions]) => (
                      <Table.Tr key={attackType}>
                        <Table.Td>
                          <Badge
                            size="sm"
                            color={
                              ["kernel_rootkit", "c2_communication", "container_escape", "privilege_escalation", "process_injection"].includes(attackType) ? "red" :
                              ["cryptojacking", "dns_exfiltration", "ssh_brute_force", "ssh_password_spraying", "distributed_attack"].includes(attackType) ? "orange" :
                              "blue"
                            }
                            variant="light"
                          >
                            {attackType.replace(/_/g, " ")}
                          </Badge>
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4}>
                            {actions.map((action, i) => {
                              const meta = rules.actions[action];
                              const Icon = ACTION_ICONS[action] || IconBolt;
                              const level = meta?.level ?? 0;
                              return (
                                <Group key={i} gap={4}>
                                  {i > 0 && <IconChevronRight size={12} color="var(--mantine-color-dimmed)" />}
                                  <Tooltip label={`${action} · Level ${level} · ${meta?.destructive ? "Destructive" : "Non-destructive"} · ${meta?.reversible ? "Reversible" : "Irreversible"} · ${meta?.auto ? "Auto" : "Needs Approval"}`}>
                                    <Group gap={4} style={{ cursor: "help" }}>
                                      <ThemeIcon size={20} variant="light" color={ACTION_LEVEL_COLORS[level] || "blue"}>
                                        <Icon size={11} />
                                      </ThemeIcon>
                                      <Text size="xs">{action.replace(/_/g, " ")}</Text>
                                    </Group>
                                  </Tooltip>
                                </Group>
                              );
                            })}
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4}>
                            {actions.map((action, i) => {
                              const meta = rules.actions[action];
                              const level = meta?.level ?? 0;
                              return (
                                <Box
                                  key={i}
                                  style={{
                                    width: 8,
                                    height: 20,
                                    borderRadius: 2,
                                    background: `var(--mantine-color-${ACTION_LEVEL_COLORS[level] || "blue"}-6)`,
                                    opacity: 0.7,
                                  }}
                                />
                              );
                            })}
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                </Table.Tbody>
              </Table>
            </ScrollArea>

            {/* Action Level Legend */}
            <Divider my="md" />
            <Group gap="lg">
              {[
                { level: 0, label: "Observe", color: "blue" },
                { level: 1, label: "Delay", color: "cyan" },
                { level: 2, label: "Contain", color: "yellow" },
                { level: 3, label: "Isolate", color: "orange" },
                { level: 4, label: "Terminate", color: "red" },
                { level: 5, label: "Evacuate", color: "grape" },
              ].map((l) => (
                <Group key={l.level} gap="xs">
                  <Box style={{ width: 12, height: 12, borderRadius: 3, background: `var(--mantine-color-${l.color}-6)` }} />
                  <Text size="xs" c="dimmed">L{l.level}: {l.label}</Text>
                </Group>
              ))}
            </Group>
          </Card>
        </Tabs.Panel>
      </Tabs>

      {/* Details Modal */}
      <Modal
        opened={detailsModal.open}
        onClose={() => setDetailsModal({ open: false, action: null })}
        title="Action Details"
        size="lg"
      >
        {detailsModal.action && (
          <Stack gap="sm">
            <Group gap="xs">
              <Text size="sm" fw={600}>Action:</Text>
              <Badge color={ACTION_LEVEL_COLORS[rules?.actions[detailsModal.action.action]?.level ?? 0] || "blue"}>
                {detailsModal.action.action}
              </Badge>
            </Group>
            <Group gap="xs">
              <Text size="sm" fw={600}>Attack:</Text>
              <Badge variant="light">{detailsModal.action.attack_type}</Badge>
            </Group>
            <Group gap="xs">
              <Text size="sm" fw={600}>Source:</Text>
              <Code>{detailsModal.action.source_ip}</Code>
            </Group>
            <Group gap="xs">
              <Text size="sm" fw={600}>Status:</Text>
              <Badge color={STATUS_COLORS[detailsModal.action.status] || "gray"}>
                {detailsModal.action.status}
              </Badge>
            </Group>
            <Divider />
            <Text size="sm" fw={600}>Details:</Text>
            <Code block style={{ whiteSpace: "pre-wrap", maxHeight: 300, overflow: "auto" }}>
              {detailsModal.action.details}
            </Code>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}