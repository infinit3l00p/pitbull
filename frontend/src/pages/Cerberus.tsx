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
  Select,
  NumberInput,
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
  Textarea,
  SegmentedControl,
} from "@mantine/core";
import {
  IconBug,
  IconPlayerPlay,
  IconPlayerStop,
  IconRefresh,
  IconDownload,
  IconFileReport,
  IconTarget,
  IconFlame,
  IconAlertTriangle,
  IconShield,
  IconActivity,
  IconSearch,
  IconChevronRight,
  IconBrain,
} from "@tabler/icons-react";
import {
  cerberusApi,
  type CerberusStatus,
  type CampaignStatus,
  type ZeroDayFinding,
  type TargetAnalysis,
  type CWEClass,
  type Analytics,
} from "../api-cerberus";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "red",
  High: "orange",
  Medium: "yellow",
  Low: "blue",
};

const STATUS_COLORS: Record<string, string> = {
  new: "blue",
  confirmed: "cyan",
  reported: "grape",
  fixed: "green",
  false_positive: "gray",
};

const STRATEGIES = [
  { value: "mutation", label: "Mutation" },
  { value: "grammar", label: "Grammar-based" },
  { value: "semantic", label: "Semantic" },
  { value: "path-guided", label: "Path-guided" },
  { value: "hybrid", label: "Hybrid" },
];

const TARGET_TYPES = [
  { value: "binary", label: "Binary" },
  { value: "protocol", label: "Protocol (host:port)" },
  { value: "api", label: "API (URL)" },
];

export default function CerberusPage() {
  const [status, setStatus] = useState<CerberusStatus | null>(null);
  const [campaign, setCampaign] = useState<CampaignStatus | null>(null);
  const [findings, setFindings] = useState<ZeroDayFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<string>("dashboard");

  // Target analysis
  const [targetInput, setTargetInput] = useState("");
  const [targetType, setTargetType] = useState("binary");
  const [analysisResult, setAnalysisResult] = useState<TargetAnalysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  // Fuzzing controls
  const [fuzzTarget, setFuzzTarget] = useState("");
  const [fuzzStrategy, setFuzzStrategy] = useState("mutation");
  const [fuzzIterations, setFuzzIterations] = useState(1000);
  const [fuzzDelay, setFuzzDelay] = useState(100);
  const [fuzzTargetType, setFuzzTargetType] = useState("binary");

  // Finding detail
  const [selectedFinding, setSelectedFinding] = useState<ZeroDayFinding | null>(null);
  const [findingReport, setFindingReport] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);

  // CWE classes
  const [cweClasses, setCweClasses] = useState<CWEClass[]>([]);

  // Analytics
  const [analytics, setAnalytics] = useState<Analytics | null>(null);

  // SSE feed
  const [feedConnected, setFeedConnected] = useState(false);
  const [liveEvents, setLiveEvents] = useState<any[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Export
  const [exportFormat, setExportFormat] = useState("json");

  const refresh = useCallback(async () => {
    try {
      const [s, f, c, a] = await Promise.all([
        cerberusApi.status(),
        cerberusApi.findings(),
        cerberusApi.fuzzStatus(),
        cerberusApi.analytics(),
      ]);
      setStatus(s as any);
      setFindings((f as any).findings || []);
      setCampaign(c as any);
      setAnalytics(a as any);
    } catch (e) {
      console.error("Cerberus refresh failed:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    cerberusApi.cweClasses().then((r) => setCweClasses((r as any).classes || []));

    // SSE feed
    const es = new EventSource(cerberusApi.feedUrl);
    eventSourceRef.current = es;

    es.onopen = () => setFeedConnected(true);
    es.onerror = () => setFeedConnected(false);

    es.addEventListener("status", (e: any) => {
      try {
        const data = JSON.parse(e.data);
        if (data.status === "running" || data.status === "completed" || data.status === "stopped") {
          setCampaign((prev) => prev ? { ...prev, ...data } : data);
        }
      } catch {}
    });

    es.addEventListener("crash", (e: any) => {
      try {
        const data = JSON.parse(e.data);
        setLiveEvents((prev) => [{ ...data, id: Date.now() }, ...prev].slice(0, 50));
      } catch {}
    });

    es.addEventListener("progress", (e: any) => {
      try {
        const data = JSON.parse(e.data);
        setLiveEvents((prev) => [{ ...data, id: Date.now() }, ...prev].slice(0, 50));
      } catch {}
    });

    es.addEventListener("done", (e: any) => {
      try {
        const data = JSON.parse(e.data);
        setLiveEvents((prev) => [{ ...data, id: Date.now() }, ...prev].slice(0, 50));
        refresh();
      } catch {}
    });

    return () => {
      es.close();
    };
  }, [refresh]);

  const handleAnalyze = async () => {
    if (!targetInput) return;
    setAnalyzing(true);
    try {
      const result = await cerberusApi.analyze(targetInput, targetType);
      setAnalysisResult(result as any);
    } catch (e) {
      console.error("Analysis failed:", e);
      setAnalysisResult({ error: String(e) } as any);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleStartFuzz = async () => {
    if (!fuzzTarget) return;
    try {
      await cerberusApi.startFuzz(fuzzTarget, fuzzStrategy, fuzzIterations, fuzzDelay, fuzzTargetType);
      setLiveEvents([]);
      refresh();
    } catch (e) {
      console.error("Failed to start fuzzing:", e);
    }
  };

  const handleStopFuzz = async () => {
    try {
      await cerberusApi.stopFuzz();
      refresh();
    } catch (e) {
      console.error("Failed to stop fuzzing:", e);
    }
  };

  const handleGenerateReport = async (findingId: string) => {
    setReportLoading(true);
    try {
      const result = await cerberusApi.generateReport(findingId);
      setFindingReport((result as any).report);
    } catch (e) {
      console.error("Report generation failed:", e);
    } finally {
      setReportLoading(false);
    }
  };

  const handleExport = async (fmt: string) => {
    try {
      const result = await cerberusApi.exportFindings(fmt);
      const data = (result as any).data;
      const blob = new Blob([data], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cerberus-findings.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Export failed:", e);
    }
  };

  const handleUpdateStatus = async (findingId: string, newStatus: string) => {
    try {
      await cerberusApi.updateFinding(findingId, newStatus);
      refresh();
      if (selectedFinding?.finding_id === findingId) {
        setSelectedFinding({ ...selectedFinding, status: newStatus });
      }
    } catch (e) {
      console.error("Status update failed:", e);
    }
  };

  if (loading) {
    return (
      <Stack>
        <Skeleton height={80} />
        <Skeleton height={200} />
        <Skeleton height={300} />
      </Stack>
    );
  }

  return (
    <Stack gap="md">
      {/* Header */}
      <Card withBorder padding="md" radius="md">
        <Group justify="space-between">
          <Group>
            <ThemeIcon size={42} variant="gradient" gradient={{ from: "red", to: "orange" }} radius="md">
              <IconBug size={24} />
            </ThemeIcon>
            <div>
              <Text size="xl" fw={700}>Cerberus</Text>
              <Text size="xs" c="dimmed">LLM-Guided Zero-Day Discovery Engine</Text>
            </div>
          </Group>
          <Group>
            <Badge color={feedConnected ? "green" : "red"} variant="dot" size="lg">
              {feedConnected ? "Live" : "Disconnected"}
            </Badge>
            <Button variant="subtle" leftSection={<IconRefresh size={16} />} onClick={refresh}>
              Refresh
            </Button>
          </Group>
        </Group>
      </Card>

      {/* Stats */}
      {status && (
        <SimpleGrid cols={4} spacing="sm">
          <Card withBorder padding="sm">
            <Group>
              <ThemeIcon color="red" variant="light"><IconAlertTriangle size={20} /></ThemeIcon>
              <div>
                <Text size="xs" c="dimmed">Total Findings</Text>
                <Text size="xl" fw={700}>{status.total_findings}</Text>
              </div>
            </Group>
          </Card>
          <Card withBorder padding="sm">
            <Group>
              <ThemeIcon color="orange" variant="light"><IconFlame size={20} /></ThemeIcon>
              <div>
                <Text size="xs" c="dimmed">Critical</Text>
                <Text size="xl" fw={700} c="red">{status.critical_findings}</Text>
              </div>
            </Group>
          </Card>
          <Card withBorder padding="sm">
            <Group>
              <ThemeIcon color="yellow" variant="light"><IconBug size={20} /></ThemeIcon>
              <div>
                <Text size="xs" c="dimmed">New</Text>
                <Text size="xl" fw={700} c="blue">{status.new_findings}</Text>
              </div>
            </Group>
          </Card>
          <Card withBorder padding="sm">
            <Group>
              <ThemeIcon color="green" variant="light"><IconShield size={20} /></ThemeIcon>
              <div>
                <Text size="xs" c="dimmed">Confirmed</Text>
                <Text size="xl" fw={700} c="cyan">{status.confirmed_findings}</Text>
              </div>
            </Group>
          </Card>
        </SimpleGrid>
      )}

      <Tabs value={activeTab} onChange={(v) => setActiveTab(v || "dashboard")}>
        <Tabs.List>
          <Tabs.Tab value="dashboard" leftSection={<IconActivity size={16} />}>Dashboard</Tabs.Tab>
          <Tabs.Tab value="analyze" leftSection={<IconSearch size={16} />}>Target Analysis</Tabs.Tab>
          <Tabs.Tab value="fuzz" leftSection={<IconBug size={16} />}>Fuzzing</Tabs.Tab>
          <Tabs.Tab value="findings" leftSection={<IconAlertTriangle size={16} />}>Findings</Tabs.Tab>
          <Tabs.Tab value="analytics" leftSection={<IconActivity size={16} />}>Analytics</Tabs.Tab>
        </Tabs.List>

        {/* Dashboard Tab */}
        <Tabs.Panel value="dashboard" pt="md">
          <SimpleGrid cols={2} spacing="md">
            {/* Campaign Status */}
            <Card withBorder padding="md">
              <Group justify="space-between" mb="sm">
                <Text fw={600}>Campaign Status</Text>
                <Badge color={campaign?.status === "running" ? "green" : "gray"} variant="dot">
                  {campaign?.status || "idle"}
                </Badge>
              </Group>
              {campaign ? (
                <Stack gap="xs">
                  <Group justify="space-between">
                    <Text size="sm" c="dimmed">Target</Text>
                    <Code>{campaign.target}</Code>
                  </Group>
                  <Group justify="space-between">
                    <Text size="sm" c="dimmed">Strategy</Text>
                    <Badge variant="light">{campaign.strategy}</Badge>
                  </Group>
                  <Group justify="space-between">
                    <Text size="sm" c="dimmed">Iterations</Text>
                    <Text size="sm" fw={600}>{campaign.iterations_run} / {campaign.iterations_requested}</Text>
                  </Group>
                  <Progress
                    value={(campaign.iterations_run / campaign.iterations_requested) * 100}
                    color={campaign.status === "running" ? "blue" : "gray"}
                  />
                  <SimpleGrid cols={3} spacing="xs">
                    <Box>
                      <Text size="xs" c="dimmed">Crashes</Text>
                      <Text size="lg" fw={700} c="red">{campaign.crashes_found}</Text>
                    </Box>
                    <Box>
                      <Text size="xs" c="dimmed">Unique</Text>
                      <Text size="lg" fw={700} c="orange">{campaign.unique_crashes}</Text>
                    </Box>
                    <Box>
                      <Text size="xs" c="dimmed">Hangs</Text>
                      <Text size="lg" fw={700} c="yellow">{campaign.hangs_found}</Text>
                    </Box>
                  </SimpleGrid>
                </Stack>
              ) : (
                <Text c="dimmed" size="sm">No active campaign</Text>
              )}
            </Card>

            {/* Live Events */}
            <Card withBorder padding="md">
              <Text fw={600} mb="sm">Live Fuzzing Events</Text>
              <ScrollArea h={250}>
                <Stack gap="xs">
                  {liveEvents.length === 0 ? (
                    <Text c="dimmed" size="sm">No events yet — start a fuzzing campaign</Text>
                  ) : (
                    liveEvents.map((event) => (
                      <Group key={event.id} gap="xs">
                        <Badge
                          size="xs"
                          color={
                            event.type === "crash" ? "red" :
                            event.type === "hang" ? "yellow" :
                            event.type === "done" ? "green" :
                            "blue"
                          }
                        >
                          {event.type}
                        </Badge>
                        <Text size="xs" c="dimmed" style={{ flex: 1 }}>
                          {typeof event.data === "string" ? event.data : JSON.stringify(event.data)}
                        </Text>
                      </Group>
                    ))
                  )}
                </Stack>
              </ScrollArea>
            </Card>
          </SimpleGrid>
        </Tabs.Panel>

        {/* Target Analysis Tab */}
        <Tabs.Panel value="analyze" pt="md">
          <Card withBorder padding="md">
            <Text fw={600} mb="md">Target Analysis</Text>
            <Group mb="md">
              <Select
                data={TARGET_TYPES}
                value={targetType}
                onChange={(v) => setTargetType(v || "binary")}
                w={200}
                label="Target Type"
              />
              <TextInput
                placeholder={targetType === "binary" ? "/usr/bin/cat" : targetType === "protocol" ? "127.0.0.1:80" : "http://localhost:3000"}
                value={targetInput}
                onChange={(e) => setTargetInput(e.currentTarget.value)}
                label="Target"
                style={{ flex: 1 }}
              />
              <Button
                leftSection={<IconSearch size={16} />}
                onClick={handleAnalyze}
                loading={analyzing}
                mt="xl"
              >
                Analyze
              </Button>
            </Group>

            {analysisResult && (
              <Box mt="md">
                <Divider label="Analysis Results" labelPosition="center" mb="sm" />
                {analysisResult.error ? (
                  <Alert color="red" icon={<IconAlertTriangle size={16} />}>
                    {analysisResult.error}
                  </Alert>
                ) : (
                  <Stack gap="sm">
                    {analysisResult.binary_type && (
                      <Group>
                        <Text size="sm" c="dimmed">Binary Type:</Text>
                        <Badge>{analysisResult.binary_type}</Badge>
                      </Group>
                    )}
                    {analysisResult.architecture && (
                      <Group>
                        <Text size="sm" c="dimmed">Architecture:</Text>
                        <Badge>{analysisResult.architecture}</Badge>
                      </Group>
                    )}
                    {analysisResult.detected_protocol && (
                      <Group>
                        <Text size="sm" c="dimmed">Protocol:</Text>
                        <Badge color="cyan">{analysisResult.detected_protocol}</Badge>
                      </Group>
                    )}
                    {analysisResult.endpoints && analysisResult.endpoints.length > 0 && (
                      <Stack gap="xs">
                        <Text size="sm" fw={600}>Discovered Endpoints:</Text>
                        <ScrollArea h={200}>
                          <Table striped>
                            <Table.Thead>
                              <Table.Tr>
                                <Table.Th>Path</Table.Th>
                                <Table.Th>Method</Table.Th>
                                <Table.Th>Status</Table.Th>
                              </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>
                              {analysisResult.endpoints.map((ep: any, i: number) => (
                                <Table.Tr key={i}>
                                  <Table.Td><Code>{ep.path}</Code></Table.Td>
                                  <Table.Td><Badge size="xs">{ep.method}</Badge></Table.Td>
                                  <Table.Td>{ep.status || "-"}</Table.Td>
                                </Table.Tr>
                              ))}
                            </Table.Tbody>
                          </Table>
                        </ScrollArea>
                      </Stack>
                    )}
                    {analysisResult.input_vectors && analysisResult.input_vectors.length > 0 && (
                      <Stack gap="xs">
                        <Text size="sm" fw={600}>Input Vectors:</Text>
                        {analysisResult.input_vectors.map((v: any, i: number) => (
                          <Group key={i} gap="xs">
                            <IconChevronRight size={14} />
                            <Badge size="sm" variant="light">{v.type}</Badge>
                            <Text size="xs" c="dimmed">{v.description}</Text>
                          </Group>
                        ))}
                      </Stack>
                    )}
                    {analysisResult.linked_libraries && analysisResult.linked_libraries.length > 0 && (
                      <Stack gap="xs">
                        <Text size="sm" fw={600}>Linked Libraries:</Text>
                        <Group gap="xs">
                          {analysisResult.linked_libraries.map((lib: string, i: number) => (
                            <Badge key={i} size="sm" variant="light" color="grape">{lib}</Badge>
                          ))}
                        </Group>
                      </Stack>
                    )}
                    {analysisResult.llm_analysis && (
                      <Stack gap="xs">
                        <Divider label="LLM Analysis" labelPosition="center" />
                        {analysisResult.llm_analysis.attack_surface && (
                          <Stack gap="xs">
                            <Text size="sm" fw={600}>Attack Surface:</Text>
                            {analysisResult.llm_analysis.attack_surface.map((s: string, i: number) => (
                              <Text key={i} size="xs" c="dimmed">• {s}</Text>
                            ))}
                          </Stack>
                        )}
                        {analysisResult.llm_analysis.recommended_seed_inputs && (
                          <Stack gap="xs">
                            <Text size="sm" fw={600}>Recommended Seed Inputs:</Text>
                            {analysisResult.llm_analysis.recommended_seed_inputs.map((s: string, i: number) => (
                              <Code key={i} block>{s}</Code>
                            ))}
                          </Stack>
                        )}
                      </Stack>
                    )}
                  </Stack>
                )}
              </Box>
            )}
          </Card>
        </Tabs.Panel>

        {/* Fuzzing Tab */}
        <Tabs.Panel value="fuzz" pt="md">
          <Card withBorder padding="md">
            <Text fw={600} mb="md">Fuzzing Campaign</Text>
            <Stack gap="md">
              <Group>
                <Select
                  data={TARGET_TYPES}
                  value={fuzzTargetType}
                  onChange={(v) => setFuzzTargetType(v || "binary")}
                  label="Target Type"
                  w={180}
                />
                <TextInput
                  placeholder="Target (binary path, host:port, or URL)"
                  value={fuzzTarget}
                  onChange={(e) => setFuzzTarget(e.currentTarget.value)}
                  label="Target"
                  style={{ flex: 1 }}
                />
              </Group>
              <Group>
                <Select
                  data={STRATEGIES}
                  value={fuzzStrategy}
                  onChange={(v) => setFuzzStrategy(v || "mutation")}
                  label="Strategy"
                  w={200}
                />
                <NumberInput
                  label="Iterations"
                  value={fuzzIterations}
                  onChange={(v) => setFuzzIterations(Number(v) || 1000)}
                  min={1}
                  max={100000}
                  w={150}
                />
                <NumberInput
                  label="Delay (ms)"
                  value={fuzzDelay}
                  onChange={(v) => setFuzzDelay(Number(v) || 100)}
                  min={0}
                  max={60000}
                  w={150}
                />
              </Group>
              <Group>
                <Button
                  leftSection={<IconPlayerPlay size={16} />}
                  onClick={handleStartFuzz}
                  color="red"
                  disabled={!fuzzTarget || campaign?.status === "running"}
                >
                  Start Campaign
                </Button>
                <Button
                  leftSection={<IconPlayerStop size={16} />}
                  onClick={handleStopFuzz}
                  color="orange"
                  variant="light"
                  disabled={campaign?.status !== "running"}
                >
                  Stop Campaign
                </Button>
              </Group>

              {campaign && (
                <Box mt="md">
                  <Divider label="Campaign Progress" labelPosition="center" mb="sm" />
                  <Stack gap="xs">
                    <Group justify="space-between">
                      <Text size="sm" c="dimmed">Campaign ID</Text>
                      <Code>{campaign.campaign_id}</Code>
                    </Group>
                    <Group justify="space-between">
                      <Text size="sm" c="dimmed">Progress</Text>
                      <Text size="sm" fw={600}>{campaign.iterations_run} / {campaign.iterations_requested}</Text>
                    </Group>
                    <Progress
                      value={(campaign.iterations_run / campaign.iterations_requested) * 100}
                      color={campaign.status === "running" ? "red" : "gray"}
                      size="lg"
                    />
                    <SimpleGrid cols={4} spacing="xs" mt="sm">
                      <Box>
                        <Text size="xs" c="dimmed">Crashes</Text>
                        <Text size="xl" fw={700} c="red">{campaign.crashes_found}</Text>
                      </Box>
                      <Box>
                        <Text size="xs" c="dimmed">Unique</Text>
                        <Text size="xl" fw={700} c="orange">{campaign.unique_crashes}</Text>
                      </Box>
                      <Box>
                        <Text size="xs" c="dimmed">Hangs</Text>
                        <Text size="xl" fw={700} c="yellow">{campaign.hangs_found}</Text>
                      </Box>
                      <Box>
                        <Text size="xs" c="dimmed">Errors</Text>
                        <Text size="xl" fw={700} c="gray">{campaign.errors_found}</Text>
                      </Box>
                    </SimpleGrid>
                  </Stack>
                </Box>
              )}
            </Stack>
          </Card>
        </Tabs.Panel>

        {/* Findings Tab */}
        <Tabs.Panel value="findings" pt="md">
          <Stack gap="md">
            <Card withBorder padding="md">
              <Group justify="space-between" mb="md">
                <Text fw={600}>Zero-Day Findings</Text>
                <Group>
                  <SegmentedControl
                    data={[
                      { value: "json", label: "JSON" },
                      { value: "csv", label: "CSV" },
                      { value: "md", label: "MD" },
                    ]}
                    value={exportFormat}
                    onChange={(v) => setExportFormat(v || "json")}
                    size="xs"
                  />
                  <Button
                    size="xs"
                    variant="light"
                    leftSection={<IconDownload size={14} />}
                    onClick={() => handleExport(exportFormat)}
                  >
                    Export
                  </Button>
                </Group>
              </Group>

              <ScrollArea h={400}>
                <Table striped highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>ID</Table.Th>
                      <Table.Th>Target</Table.Th>
                      <Table.Th>Type</Table.Th>
                      <Table.Th>CWE</Table.Th>
                      <Table.Th>Severity</Table.Th>
                      <Table.Th>Status</Table.Th>
                      <Table.Th>Date</Table.Th>
                      <Table.Th></Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {findings.length === 0 ? (
                      <Table.Tr>
                        <Table.Td colSpan={8}>
                          <Text c="dimmed" ta="center" py="lg">No findings yet — start a fuzzing campaign</Text>
                        </Table.Td>
                      </Table.Tr>
                    ) : (
                      findings.map((f) => (
                        <Table.Tr key={f.finding_id}>
                          <Table.Td><Code>{f.finding_id}</Code></Table.Td>
                          <Table.Td style={{ maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis" }}>{f.target}</Table.Td>
                          <Table.Td>{f.vuln_type}</Table.Td>
                          <Table.Td><Badge size="xs" variant="light">{f.cwe_class}</Badge></Table.Td>
                          <Table.Td>
                            <Badge color={SEVERITY_COLORS[f.severity] || "gray"} size="xs">
                              {f.severity}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Badge color={STATUS_COLORS[f.status] || "gray"} size="xs" variant="dot">
                              {f.status}
                            </Badge>
                          </Table.Td>
                          <Table.Td style={{ fontSize: "0.75rem" }}>{f.discovered_at?.slice(0, 10)}</Table.Td>
                          <Table.Td>
                            <ActionIcon
                              size="sm"
                              variant="subtle"
                              onClick={() => { setSelectedFinding(f); setFindingReport(null); }}
                            >
                              <IconChevronRight size={14} />
                            </ActionIcon>
                          </Table.Td>
                        </Table.Tr>
                      ))
                    )}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Card>
          </Stack>
        </Tabs.Panel>

        {/* Analytics Tab */}
        <Tabs.Panel value="analytics" pt="md">
          {analytics && (
            <SimpleGrid cols={2} spacing="md">
              <Card withBorder padding="md">
                <Text fw={600} mb="sm">By Severity</Text>
                <Stack gap="xs">
                  {Object.entries(analytics.by_severity).map(([sev, count]) => (
                    <Group key={sev} justify="space-between">
                      <Badge color={SEVERITY_COLORS[sev] || "gray"}>{sev}</Badge>
                      <Text fw={600}>{count}</Text>
                    </Group>
                  ))}
                </Stack>
              </Card>

              <Card withBorder padding="md">
                <Text fw={600} mb="sm">By Status</Text>
                <Stack gap="xs">
                  {Object.entries(analytics.by_status).map(([st, count]) => (
                    <Group key={st} justify="space-between">
                      <Badge color={STATUS_COLORS[st] || "gray"} variant="dot">{st}</Badge>
                      <Text fw={600}>{count}</Text>
                    </Group>
                  ))}
                </Stack>
              </Card>

              <Card withBorder padding="md">
                <Text fw={600} mb="sm">By CWE Class</Text>
                <ScrollArea h={200}>
                  <Stack gap="xs">
                    {Object.entries(analytics.by_cwe).map(([cwe, count]) => (
                      <Group key={cwe} justify="space-between">
                        <Badge size="sm" variant="light">{cwe}</Badge>
                        <Text size="sm" fw={600}>{count}</Text>
                      </Group>
                    ))}
                  </Stack>
                </ScrollArea>
              </Card>

              <Card withBorder padding="md">
                <Text fw={600} mb="sm">By Target</Text>
                <ScrollArea h={200}>
                  <Stack gap="xs">
                    {Object.entries(analytics.by_target).map(([t, count]) => (
                      <Group key={t} justify="space-between">
                        <Text size="xs" style={{ maxWidth: 250, overflow: "hidden", textOverflow: "ellipsis" }}>{t}</Text>
                        <Text size="sm" fw={600}>{count}</Text>
                      </Group>
                    ))}
                  </Stack>
                </ScrollArea>
              </Card>
            </SimpleGrid>
          )}
        </Tabs.Panel>
      </Tabs>

      {/* Finding Detail Modal */}
      <Modal
        opened={selectedFinding !== null}
        onClose={() => { setSelectedFinding(null); setFindingReport(null); }}
        title={selectedFinding ? `Finding: ${selectedFinding.finding_id}` : ""}
        size="lg"
      >
        {selectedFinding && (
          <Stack gap="sm">
            <SimpleGrid cols={2} spacing="xs">
              <Group>
                <Text size="sm" c="dimmed">Target:</Text>
                <Code>{selectedFinding.target}</Code>
              </Group>
              <Group>
                <Text size="sm" c="dimmed">Type:</Text>
                <Badge>{selectedFinding.vuln_type}</Badge>
              </Group>
              <Group>
                <Text size="sm" c="dimmed">CWE:</Text>
                <Badge color={SEVERITY_COLORS[selectedFinding.severity] || "gray"}>
                  {selectedFinding.cwe_class}
                </Badge>
              </Group>
              <Group>
                <Text size="sm" c="dimmed">Severity:</Text>
                <Badge color={SEVERITY_COLORS[selectedFinding.severity] || "gray"} variant="dot">
                  {selectedFinding.severity}
                </Badge>
              </Group>
              <Group>
                <Text size="sm" c="dimmed">Exploitability:</Text>
                <Badge variant="light">{selectedFinding.exploitability || "unknown"}</Badge>
              </Group>
              <Group>
                <Text size="sm" c="dimmed">Signal:</Text>
                <Text size="sm">{selectedFinding.signal_name || "N/A"}</Text>
              </Group>
            </SimpleGrid>

            <Divider label="Description" labelPosition="center" />
            <Text size="sm">{selectedFinding.description}</Text>

            {selectedFinding.attack_techniques && selectedFinding.attack_techniques.length > 0 && (
              <>
                <Divider label="MITRE ATT&CK" labelPosition="center" />
                <Group gap="xs">
                  {selectedFinding.attack_techniques.map((t) => (
                    <Badge key={t} color="grape" variant="light">{t}</Badge>
                  ))}
                </Group>
              </>
            )}

            <Divider label="Stack Trace" labelPosition="center" />
            <ScrollArea h={150}>
              <Code block>
                {selectedFinding.stack_trace || "No stack trace available"}
              </Code>
            </ScrollArea>

            <Divider label="PoC Code (Defensive Validation Only)" labelPosition="center" />
            <ScrollArea h={100}>
              <Code block>
                {selectedFinding.poc_code || "No PoC available"}
              </Code>
            </ScrollArea>

            <Group>
              <Select
                data={[
                  { value: "new", label: "New" },
                  { value: "confirmed", label: "Confirmed" },
                  { value: "reported", label: "Reported" },
                  { value: "fixed", label: "Fixed" },
                  { value: "false_positive", label: "False Positive" },
                ]}
                value={selectedFinding.status}
                onChange={(v) => {
                  if (v) handleUpdateStatus(selectedFinding.finding_id, v);
                }}
                w={200}
                label="Update Status"
              />
              <Button
                leftSection={<IconFileReport size={16} />}
                onClick={() => handleGenerateReport(selectedFinding.finding_id)}
                loading={reportLoading}
                variant="light"
              >
                Generate Report
              </Button>
            </Group>

            {findingReport && (
              <>
                <Divider label="Vulnerability Report" labelPosition="center" />
                <ScrollArea h={300}>
                  <Code block style={{ whiteSpace: "pre-wrap", fontSize: "0.75rem" }}>
                    {findingReport}
                  </Code>
                </ScrollArea>
              </>
            )}
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}