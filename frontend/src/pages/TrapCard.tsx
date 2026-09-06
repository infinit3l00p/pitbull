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
  Box,
  Alert,
  Modal,
  Tabs,
  Skeleton,
  Divider,
  Progress,
  TextInput,
  Textarea,
} from "@mantine/core";
import {
  IconBug,
  IconShield,
  IconServer,
  IconUpload,
  IconPlayerPlay,
  IconPlayerStop,
  IconRefresh,
  IconTerminal,
  IconFile,
  IconNetwork,
  IconDatabase,
  IconActivity,
  IconChevronRight,
  IconBolt,
  IconEye,
} from "@tabler/icons-react";
import {
  trapcardApi,
  type TrapCardStatus,
  type Capture,
  type AttackerSession,
  type SessionDetail,
  type TrapCardAnalytics,
  type FeedEvent,
} from "../api-trapcard";

const SERVICE_COLORS: Record<string, string> = {
  ssh: "blue",
  web: "green",
};

const FILE_TYPE_COLORS: Record<string, string> = {
  elf: "red",
  pe: "red",
  "mach-o-64": "red",
  python: "grape",
  python3: "grape",
  bash: "cyan",
  sh: "cyan",
  perl: "cyan",
  text: "gray",
  unknown: "dark",
};

export default function TrapCardPage() {
  const [status, setStatus] = useState<TrapCardStatus | null>(null);
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [sessions, setSessions] = useState<AttackerSession[]>([]);
  const [analytics, setAnalytics] = useState<TrapCardAnalytics | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("captures");
  const [selectedSession, setSelectedSession] = useState<SessionDetail | null>(null);
  const [sessionModalOpen, setSessionModalOpen] = useState(false);
  const [sshPort, setSSHPort] = useState("2222");
  const [feedConnected, setFeedConnected] = useState(false);
  const [liveEvents, setLiveEvents] = useState<FeedEvent[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, c, sess, a] = await Promise.all([
        trapcardApi.status(),
        trapcardApi.captures(50),
        trapcardApi.sessions(50),
        trapcardApi.analytics(),
      ]);
      setStatus(s as any);
      setCaptures((c as any).captures || []);
      setSessions((sess as any).sessions || []);
      setAnalytics(a as any);
    } catch (e) {
      console.error("TrapCard refresh failed:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 15000);
    return () => clearInterval(interval);
  }, [refresh]);

  // SSE feed
  useEffect(() => {
    const es = new EventSource(trapcardApi.feedUrl);
    eventSourceRef.current = es;

    es.onopen = () => setFeedConnected(true);
    es.onerror = () => setFeedConnected(false);
    es.onmessage = (e) => {
      try {
        const event: FeedEvent = JSON.parse(e.data);
        if (event.type === "connected") return;
        setLiveEvents((prev) => [event, ...prev].slice(0, 50));
      } catch {
        // ignore parse errors
      }
    };

    return () => {
      es.close();
      setFeedConnected(false);
    };
  }, []);

  const handleStartSSH = async () => {
    try {
      await trapcardApi.startSSH(parseInt(sshPort) || 2222);
      refresh();
    } catch (e) {
      console.error("Failed to start SSH honeypot:", e);
    }
  };

  const handleStopSSH = async () => {
    try {
      await trapcardApi.stopSSH();
      refresh();
    } catch (e) {
      console.error("Failed to stop SSH honeypot:", e);
    }
  };

  const handleStartWeb = async () => {
    try {
      await trapcardApi.startWeb();
      refresh();
    } catch (e) {
      console.error("Failed to start web honeypot:", e);
    }
  };

  const handleViewSession = async (sessionId: string) => {
    try {
      const detail = await trapcardApi.session(sessionId);
      setSelectedSession(detail as any);
      setSessionModalOpen(true);
    } catch (e) {
      console.error("Failed to load session:", e);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  };

  const formatTime = (ts: string) => {
    if (!ts) return "—";
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  };

  if (loading) {
    return (
      <Stack gap="md">
        <Skeleton height={120} />
        <Skeleton height={400} />
      </Stack>
    );
  }

  return (
    <Stack gap="md">
      {/* Header */}
      <Group justify="space-between">
        <Group gap="sm">
          <ThemeIcon size={36} variant="filled" color="red" radius="md">
            <IconBug size={20} />
          </ThemeIcon>
          <div>
            <Text size="xl" fw={700}>TrapCard</Text>
            <Text size="xs" c="dimmed">Attacker Tool Capture Engine</Text>
          </div>
        </Group>
        <Group gap="sm">
          <Badge
            color={feedConnected ? "green" : "red"}
            variant="light"
            leftSection={<IconActivity size={12} />}
          >
            {feedConnected ? "LIVE" : "OFFLINE"}
          </Badge>
          <Button variant="subtle" leftSection={<IconRefresh size={16} />} onClick={refresh} size="sm">
            Refresh
          </Button>
        </Group>
      </Group>

      {/* Status Cards */}
      <SimpleGrid cols={4} spacing="md">
        {/* SSH Honeypot */}
        <Card withBorder padding="md" radius="md">
          <Group justify="space-between" mb="xs">
            <Group gap="xs">
              <ThemeIcon size={28} variant="light" color="blue" radius="sm">
                <IconTerminal size={16} />
              </ThemeIcon>
              <Text size="sm" fw={600}>SSH Honeypot</Text>
            </Group>
            <Badge color={status?.ssh_honeypot?.running ? "green" : "gray"} size="sm">
              {status?.ssh_honeypot?.running ? "RUNNING" : "STOPPED"}
            </Badge>
          </Group>
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="xs" c="dimmed">Port</Text>
              <Text size="xs" fw={500}>{status?.ssh_honeypot?.port || "—"}</Text>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">Active</Text>
              <Text size="xs" fw={500}>{status?.ssh_honeypot?.active_connections || 0}</Text>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">Total Conns</Text>
              <Text size="xs" fw={500}>{status?.ssh_honeypot?.total_connections || 0}</Text>
            </Group>
            <Group gap="xs" mt="xs">
              {status?.ssh_honeypot?.running ? (
                <Button size="xs" variant="light" color="red" leftSection={<IconPlayerStop size={14} />} onClick={handleStopSSH}>
                  Stop
                </Button>
              ) : (
                <>
                  <TextInput
                    size="xs"
                    style={{ width: 70 }}
                    value={sshPort}
                    onChange={(e) => setSSHPort(e.currentTarget.value)}
                    placeholder="Port"
                  />
                  <Button size="xs" variant="light" color="green" leftSection={<IconPlayerPlay size={14} />} onClick={handleStartSSH}>
                    Start
                  </Button>
                </>
              )}
            </Group>
          </Stack>
        </Card>

        {/* Web Honeypot */}
        <Card withBorder padding="md" radius="md">
          <Group justify="space-between" mb="xs">
            <Group gap="xs">
              <ThemeIcon size={28} variant="light" color="green" radius="sm">
                <IconUpload size={16} />
              </ThemeIcon>
              <Text size="sm" fw={600}>Web Honeypot</Text>
            </Group>
            <Badge color={status?.web_honeypot?.running ? "green" : "gray"} size="sm">
              {status?.web_honeypot?.running ? "ACTIVE" : "OFF"}
            </Badge>
          </Group>
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="xs" c="dimmed">Endpoints</Text>
              <Text size="xs" fw={500}>{status?.web_honeypot?.endpoints?.length || 0}</Text>
            </Group>
            <ScrollArea.Autosize h={60}>
              <Stack gap={2}>
                {(status?.web_honeypot?.endpoints || []).slice(0, 3).map((ep) => (
                  <Code key={ep} fz="xs">{ep}</Code>
                ))}
              </Stack>
            </ScrollArea.Autosize>
            <Button size="xs" variant="light" color="green" leftSection={<IconPlayerPlay size={14} />} onClick={handleStartWeb}>
              Active
            </Button>
          </Stack>
        </Card>

        {/* Total Captures */}
        <Card withBorder padding="md" radius="md">
          <Group justify="space-between" mb="xs">
            <Group gap="xs">
              <ThemeIcon size={28} variant="light" color="orange" radius="sm">
                <IconFile size={16} />
              </ThemeIcon>
              <Text size="sm" fw={600}>Captures</Text>
            </Group>
          </Group>
          <Text size="xl" fw={700} c="orange">{status?.total_captures || 0}</Text>
          <Text size="xs" c="dimmed" mt="xs">Total tool samples captured</Text>
        </Card>

        {/* Total Sessions */}
        <Card withBorder padding="md" radius="md">
          <Group justify="space-between" mb="xs">
            <Group gap="xs">
              <ThemeIcon size={28} variant="light" color="violet" radius="sm">
                <IconNetwork size={16} />
              </ThemeIcon>
              <Text size="sm" fw={600}>Sessions</Text>
            </Group>
          </Group>
          <Text size="xl" fw={700} c="violet">{status?.total_sessions || 0}</Text>
          <Text size="xs" c="dimmed" mt="xs">Attacker sessions recorded</Text>
        </Card>
      </SimpleGrid>

      {/* Live Feed */}
      {liveEvents.length > 0 && (
        <Card withBorder padding="sm" radius="md">
          <Group justify="space-between" mb="xs">
            <Group gap="xs">
              <IconBolt size={16} color="orange" />
              <Text size="sm" fw={600}>Live Feed</Text>
            </Group>
            <Badge size="xs" color="orange">{liveEvents.length} events</Badge>
          </Group>
          <ScrollArea.Autosize h={120}>
            <Stack gap={2}>
              {liveEvents.slice(0, 10).map((ev, i) => (
                <Group key={i} gap="xs">
                  <Badge size="xs" color={ev.type === "file_captured" ? "red" : ev.type === "ssh_connect" ? "blue" : "gray"}>
                    {ev.type}
                  </Badge>
                  <Text size="xs" c="dimmed">{ev.source_ip || "—"}</Text>
                  {ev.command && <Code fz="xs">{ev.command.substring(0, 60)}</Code>}
                  {ev.filename && <Text size="xs" c="orange">{ev.filename} ({ev.size}B)</Text>}
                </Group>
              ))}
            </Stack>
          </ScrollArea.Autosize>
        </Card>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onChange={(v) => setActiveTab(v || "captures")}>
        <Tabs.List>
          <Tabs.Tab value="captures" leftSection={<IconFile size={16} />}>
            Captures
          </Tabs.Tab>
          <Tabs.Tab value="sessions" leftSection={<IconTerminal size={16} />}>
            Sessions
          </Tabs.Tab>
          <Tabs.Tab value="analytics" leftSection={<IconDatabase size={16} />}>
            Analytics
          </Tabs.Tab>
        </Tabs.List>

        {/* Captures Tab */}
        <Tabs.Panel value="captures" pt="md">
          <Card withBorder padding="md" radius="md">
            <ScrollArea>
              <Table striped highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>SHA256</Table.Th>
                    <Table.Th>Type</Table.Th>
                    <Table.Th>Filename</Table.Th>
                    <Table.Th>Size</Table.Th>
                    <Table.Th>Source IP</Table.Th>
                    <Table.Th>Service</Table.Th>
                    <Table.Th>ATT&CK</Table.Th>
                    <Table.Th>Captured</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {captures.length === 0 ? (
                    <Table.Tr>
                      <Table.Td colSpan={8}>
                        <Text ta="center" c="dimmed" py="lg">No captures yet — start the honeypots to collect attacker tools</Text>
                      </Table.Td>
                    </Table.Tr>
                  ) : (
                    captures.map((cap) => (
                      <Table.Tr key={cap.capture_id}>
                        <Table.Td>
                          <Code fz="xs">{cap.sha256?.substring(0, 16)}...</Code>
                        </Table.Td>
                        <Table.Td>
                          <Badge size="xs" color={FILE_TYPE_COLORS[cap.mime_type?.split("/").pop() || "unknown"] || "gray"}>
                            {cap.mime_type || "unknown"}
                          </Badge>
                        </Table.Td>
                        <Table.Td>{cap.filename || "—"}</Table.Td>
                        <Table.Td>{formatBytes(cap.size || 0)}</Table.Td>
                        <Table.Td>
                          <Text size="xs" ff="monospace">{cap.source_ip || "—"}</Text>
                        </Table.Td>
                        <Table.Td>
                          <Badge size="xs" color={SERVICE_COLORS[cap.service] || "gray"}>
                            {cap.service || "—"}
                          </Badge>
                        </Table.Td>
                        <Table.Td>
                          {cap.attack_techniques && cap.attack_techniques.length > 0 ? (
                            <Group gap={4}>
                              {cap.attack_techniques.map((t) => (
                                <Badge key={t} size="xs" color="red" variant="light">{t}</Badge>
                              ))}
                            </Group>
                          ) : (
                            <Text size="xs" c="dimmed">—</Text>
                          )}
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs" c="dimmed">{formatTime(cap.captured_at)}</Text>
                        </Table.Td>
                      </Table.Tr>
                    ))
                  )}
                </Table.Tbody>
              </Table>
            </ScrollArea>
          </Card>
        </Tabs.Panel>

        {/* Sessions Tab */}
        <Tabs.Panel value="sessions" pt="md">
          <Card withBorder padding="md" radius="md">
            <ScrollArea>
              <Table striped highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Session ID</Table.Th>
                    <Table.Th>Source IP</Table.Th>
                    <Table.Th>Service</Table.Th>
                    <Table.Th>Tools</Table.Th>
                    <Table.Th>First Seen</Table.Th>
                    <Table.Th>Last Seen</Table.Th>
                    <Table.Th>Actions</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {sessions.length === 0 ? (
                    <Table.Tr>
                      <Table.Td colSpan={7}>
                        <Text ta="center" c="dimmed" py="lg">No sessions recorded yet</Text>
                      </Table.Td>
                    </Table.Tr>
                  ) : (
                    sessions.map((sess) => (
                      <Table.Tr key={sess.session_id}>
                        <Table.Td>
                          <Code fz="xs">{sess.session_id?.substring(0, 12)}...</Code>
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs" ff="monospace">{sess.source_ip || "—"}</Text>
                        </Table.Td>
                        <Table.Td>
                          <Badge size="xs" color={SERVICE_COLORS[sess.service] || "gray"}>
                            {sess.service || "—"}
                          </Badge>
                        </Table.Td>
                        <Table.Td>{sess.tool_count || 0}</Table.Td>
                        <Table.Td>
                          <Text size="xs" c="dimmed">{formatTime(sess.first_seen)}</Text>
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs" c="dimmed">{formatTime(sess.last_seen)}</Text>
                        </Table.Td>
                        <Table.Td>
                          <ActionIcon
                            size="sm"
                            variant="subtle"
                            color="blue"
                            onClick={() => handleViewSession(sess.session_id)}
                          >
                            <IconEye size={16} />
                          </ActionIcon>
                        </Table.Td>
                      </Table.Tr>
                    ))
                  )}
                </Table.Tbody>
              </Table>
            </ScrollArea>
          </Card>
        </Tabs.Panel>

        {/* Analytics Tab */}
        <Tabs.Panel value="analytics" pt="md">
          <SimpleGrid cols={2} spacing="md">
            {/* By Type */}
            <Card withBorder padding="md" radius="md">
              <Text size="sm" fw={600} mb="sm">Captures by Type</Text>
              <Stack gap="xs">
                {(analytics?.by_type || []).map((item) => (
                  <Group key={item.type} justify="space-between">
                    <Text size="xs">{item.type || "unknown"}</Text>
                    <Group gap="xs">
                      <Progress
                        value={(item.count / Math.max(...(analytics?.by_type || []).map((t) => t.count), 1)) * 100}
                        size="xs"
                        style={{ width: 100 }}
                        color="orange"
                      />
                      <Text size="xs" fw={500}>{item.count}</Text>
                    </Group>
                  </Group>
                ))}
                {(!analytics?.by_type || analytics.by_type.length === 0) && (
                  <Text size="xs" c="dimmed">No data yet</Text>
                )}
              </Stack>
            </Card>

            {/* By IP */}
            <Card withBorder padding="md" radius="md">
              <Text size="sm" fw={600} mb="sm">Top Attacker IPs</Text>
              <Stack gap="xs">
                {(analytics?.by_ip || []).map((item) => (
                  <Group key={item.ip} justify="space-between">
                    <Text size="xs" ff="monospace">{item.ip}</Text>
                    <Badge size="xs" color="red" variant="light">{item.count}</Badge>
                  </Group>
                ))}
                {(!analytics?.by_ip || analytics.by_ip.length === 0) && (
                  <Text size="xs" c="dimmed">No data yet</Text>
                )}
              </Stack>
            </Card>

            {/* ATT&CK Mapping */}
            <Card withBorder padding="md" radius="md">
              <Text size="sm" fw={600} mb="sm">MITRE ATT&CK Techniques</Text>
              <Stack gap="xs">
                {(analytics?.attack_mapping || []).map((item) => (
                  <Group key={item.technique} justify="space-between">
                    <Badge size="xs" color="red" variant="light">{item.technique}</Badge>
                    <Text size="xs" fw={500}>{item.count}</Text>
                  </Group>
                ))}
                {(!analytics?.attack_mapping || analytics.attack_mapping.length === 0) && (
                  <Text size="xs" c="dimmed">No ATT&CK mappings yet</Text>
                )}
              </Stack>
            </Card>

            {/* By Day */}
            <Card withBorder padding="md" radius="md">
              <Text size="sm" fw={600} mb="sm">Captures by Day</Text>
              <Stack gap="xs">
                {(analytics?.by_day || []).map((item) => (
                  <Group key={item.day} justify="space-between">
                    <Text size="xs">{item.day}</Text>
                    <Badge size="xs" color="blue" variant="light">{item.count}</Badge>
                  </Group>
                ))}
                {(!analytics?.by_day || analytics.by_day.length === 0) && (
                  <Text size="xs" c="dimmed">No data yet</Text>
                )}
              </Stack>
            </Card>
          </SimpleGrid>
        </Tabs.Panel>
      </Tabs>

      {/* Session Viewer Modal */}
      <Modal
        opened={sessionModalOpen}
        onClose={() => setSessionModalOpen(false)}
        title="Session Recording"
        size="xl"
        scrollAreaComponent={ScrollArea.Autosize}
      >
        {selectedSession && (
          <Stack gap="md">
            <SimpleGrid cols={3} spacing="sm">
              <div>
                <Text size="xs" c="dimmed">Session ID</Text>
                <Code fz="xs">{selectedSession.session_id}</Code>
              </div>
              <div>
                <Text size="xs" c="dimmed">Source IP</Text>
                <Text size="sm" ff="monospace">{selectedSession.source_ip}</Text>
              </div>
              <div>
                <Text size="xs" c="dimmed">Service</Text>
                <Badge size="sm" color={SERVICE_COLORS[selectedSession.service] || "gray"}>
                  {selectedSession.service}
                </Badge>
              </div>
            </SimpleGrid>

            <Divider label="Captured Tools" labelPosition="center" />
            {selectedSession.tools && selectedSession.tools.length > 0 ? (
              <Stack gap="xs">
                {selectedSession.tools.map((tool, i) => (
                  <Group key={i} gap="sm">
                    <IconFile size={16} />
                    <Text size="sm" fw={500}>{tool.filename || "unknown"}</Text>
                    <Badge size="xs">{formatBytes(tool.size)}</Badge>
                    <Badge size="xs" color="gray">{tool.mime_type}</Badge>
                    {tool.attack_techniques && tool.attack_techniques.map((t) => (
                      <Badge key={t} size="xs" color="red" variant="light">{t}</Badge>
                    ))}
                  </Group>
                ))}
              </Stack>
            ) : (
              <Text size="sm" c="dimmed">No tools captured in this session</Text>
            )}

            <Divider label="Session Recording" labelPosition="center" />
            {selectedSession.recording ? (
              <ScrollArea.Autosize h={400}>
                <pre style={{
                  fontFamily: "monospace",
                  fontSize: "12px",
                  lineHeight: "1.5",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  background: "var(--mantine-color-dark-7)",
                  padding: "12px",
                  borderRadius: "6px",
                  color: "var(--mantine-color-green-5)",
                }}>
                  {selectedSession.recording}
                </pre>
              </ScrollArea.Autosize>
            ) : (
              <Text size="sm" c="dimmed">No recording available</Text>
            )}
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}