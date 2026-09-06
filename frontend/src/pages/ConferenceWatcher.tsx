import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Grid,
  Text,
  Group,
  Badge,
  Stack,
  SimpleGrid,
  ThemeIcon,
  Box,
  Button,
  TextInput,
  Select,
  Tabs,
  ScrollArea,
  Loader,
  Center,
  Divider,
  Alert,
  Modal,
  Anchor,
  Progress,
} from "@mantine/core";
import {
  IconCalendar,
  IconBook,
  IconBrain,
  IconRefresh,
  IconSearch,
  IconWorld,
  IconFlask,
  IconBolt,
  IconAlertCircle,
  IconExternalLink,
  IconClock,
  IconMapPin,
  IconTag,
} from "@tabler/icons-react";
import {
  conferenceApi,
  type Conference,
  type Paper,
  type KnowledgeEntry,
  type WatcherStats,
  type ScanSummary,
} from "../api-conferences";

const TIER_COLORS: Record<number, string> = {
  1: "red",
  2: "blue",
};

const STATUS_COLORS: Record<string, string> = {
  upcoming: "cyan",
  ongoing: "green",
  past: "gray",
};

const TECH_TYPE_COLORS: Record<string, string> = {
  deception: "violet",
  fuzzing: "orange",
  exploitation: "red",
  defense: "green",
  ai_security: "cyan",
  hardware: "yellow",
  crypto: "indigo",
  malware: "pink",
  network: "teal",
  general: "gray",
};

export default function ConferenceWatcherPage() {
  const [conferences, setConferences] = useState<Conference[]>([]);
  const [papers, setPapers] = useState<Paper[]>([]);
  const [knowledge, setKnowledge] = useState<KnowledgeEntry[]>([]);
  const [stats, setStats] = useState<WatcherStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanSummary | null>(null);
  const [paperSearch, setPaperSearch] = useState("");
  const [kbSearch, setKbSearch] = useState("");
  const [techFilter, setTechFilter] = useState<string | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<KnowledgeEntry | null>(null);
  const [activeTab, setActiveTab] = useState<string>("conferences");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [confRes, paperRes, kbRes, statsRes] = await Promise.all([
        conferenceApi.list().catch(() => ({ total: 0, conferences: [] })),
        conferenceApi.papers(30).catch(() => ({ count: 0, days: 30, papers: [] })),
        conferenceApi.knowledge({ limit: 100 }).catch(() => ({ count: 0, entries: [] })),
        conferenceApi.stats().catch(() => null),
      ]);
      setConferences(confRes.conferences || []);
      setPapers(paperRes.papers || []);
      setKnowledge(kbRes.entries || []);
      setStats(statsRes);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleScan = async () => {
    setScanning(true);
    setScanResult(null);
    try {
      const result = await conferenceApi.fullScan();
      setScanResult(result);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const handlePaperSearch = async () => {
    if (!paperSearch.trim()) {
      const res = await conferenceApi.papers(30);
      setPapers(res.papers || []);
      return;
    }
    try {
      const res = await conferenceApi.searchPapers(paperSearch);
      setPapers(res.papers || []);
    } catch {
      setError("Paper search failed");
    }
  };

  const handleKbSearch = async () => {
    if (!kbSearch.trim()) {
      const res = await conferenceApi.knowledge({ limit: 100 });
      setKnowledge(res.entries || []);
      return;
    }
    try {
      const res = await conferenceApi.searchKnowledge(kbSearch);
      setKnowledge(res.entries || []);
    } catch {
      setError("Knowledge search failed");
    }
  };

  const handleTechFilter = async (value: string | null) => {
    setTechFilter(value);
    if (value) {
      const res = await conferenceApi.knowledge({ technique_type: value, limit: 100 });
      setKnowledge(res.entries || []);
    } else {
      const res = await conferenceApi.knowledge({ limit: 100 });
      setKnowledge(res.entries || []);
    }
  };

  const upcomingConfs = conferences
    .filter((c) => c.status === "upcoming" || c.status === "ongoing")
    .sort((a, b) => a.start_date.localeCompare(b.start_date));

  if (loading) {
    return (
      <Center h="100vh">
        <Stack align="center" gap="md">
          <Loader size="lg" />
          <Text c="dimmed">Loading Conference Watcher…</Text>
        </Stack>
      </Center>
    );
  }

  return (
    <Stack gap="lg" className="pitbull-fade-in">
      {/* Header */}
      <Group justify="space-between" align="flex-start">
        <Stack gap={4}>
          <Text size="xs" c="cyan.5" className="pitbull-display" style={{ letterSpacing: "0.2em", opacity: 0.7 }}>
            ASIAN HACKING CONFERENCE TRACKER
          </Text>
          <Text size="28px" fw={900} className="pitbull-display" c="cyan.3" style={{ textShadow: "0 0 30px rgba(34,211,238,0.3)" }}>
            Conference Watcher
          </Text>
          <Text size="sm" c="dimmed">
            Tracking {conferences.length} conferences · {papers.length} papers · {knowledge.length} knowledge entries
          </Text>
        </Stack>
        <Button
          leftSection={<IconRefresh size={16} />}
          variant="filled"
          color="cyan"
          loading={scanning}
          onClick={handleScan}
        >
          Full Scan
        </Button>
      </Group>

      {error && (
        <Alert icon={<IconAlertCircle size={16} />} color="red" variant="filled">
          {error}
        </Alert>
      )}

      {scanResult && (
        <Alert icon={<IconBolt size={16} />} color="green" variant="filled" withCloseButton onClose={() => setScanResult(null)}>
          Scan complete — Conferences: {scanResult.conferences.total} · Papers fetched: {scanResult.papers.fetched} · KB entries created: {scanResult.knowledge_base.entries_created}
        </Alert>
      )}

      {/* Stats Cards */}
      <SimpleGrid cols={{ base: 2, md: 4 }} spacing="md">
        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Conferences</Text>
            <ThemeIcon size="sm" variant="light" color="cyan">
              <IconCalendar size={16} />
            </ThemeIcon>
          </Group>
          <Text size="xl" fw={900} c="cyan.3">{stats?.conferences.total ?? conferences.length}</Text>
          <Text size="xs" c="dimmed">
            {stats?.conferences.by_status.upcoming ?? 0} upcoming · {stats?.conferences.by_status.ongoing ?? 0} ongoing
          </Text>
        </Card>

        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Papers</Text>
            <ThemeIcon size="sm" variant="light" color="orange">
              <IconBook size={16} />
            </ThemeIcon>
          </Group>
          <Text size="xl" fw={900} c="orange.3">{stats?.papers.total_stored ?? papers.length}</Text>
          <Text size="xs" c="dimmed">arXiv cs.CR tracked</Text>
        </Card>

        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>KB Entries</Text>
            <ThemeIcon size="sm" variant="light" color="violet">
              <IconBrain size={16} />
            </ThemeIcon>
          </Group>
          <Text size="xl" fw={900} c="violet.3">{stats?.knowledge_base.total ?? knowledge.length}</Text>
          <Text size="xs" c="dimmed">
            {(stats?.knowledge_base.types ?? []).length} types
          </Text>
        </Card>

        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Tier 1 Events</Text>
            <ThemeIcon size="sm" variant="light" color="red">
              <IconFlask size={16} />
            </ThemeIcon>
          </Group>
          <Text size="xl" fw={900} c="red.3">{stats?.conferences.by_tier["1"] ?? 0}</Text>
          <Text size="xs" c="dimmed">Major international</Text>
        </Card>
      </SimpleGrid>

      {/* Tabs */}
      <Tabs value={activeTab} onChange={(v) => setActiveTab(v || "conferences")}>
        <Tabs.List>
          <Tabs.Tab value="conferences" leftSection={<IconCalendar size={16} />}>
            Conferences
          </Tabs.Tab>
          <Tabs.Tab value="papers" leftSection={<IconBook size={16} />}>
            Papers
          </Tabs.Tab>
          <Tabs.Tab value="knowledge" leftSection={<IconBrain size={16} />}>
            Knowledge Base
          </Tabs.Tab>
        </Tabs.List>

        {/* ── Conferences Tab ─────────────────────────────────────── */}
        <Tabs.Panel value="conferences" pt="lg">
          <Stack gap="md">
            {upcomingConfs.length === 0 && (
              <Text c="dimmed" ta="center" py="xl">
                No upcoming conferences found.
              </Text>
            )}
            {upcomingConfs.map((conf) => (
              <ConferenceCard key={conf.id} conf={conf} />
            ))}

            {conferences.some((c) => c.status === "past") && (
              <>
                <Divider label="Past Conferences" labelPosition="center" my="md" />
                {conferences
                  .filter((c) => c.status === "past")
                  .sort((a, b) => b.start_date.localeCompare(a.start_date))
                  .map((conf) => (
                    <ConferenceCard key={conf.id} conf={conf} />
                  ))}
              </>
            )}
          </Stack>
        </Tabs.Panel>

        {/* ── Papers Tab ──────────────────────────────────────────── */}
        <Tabs.Panel value="papers" pt="lg">
          <Stack gap="md">
            <Group gap="sm">
              <TextInput
                placeholder="Search papers by title, abstract, author…"
                value={paperSearch}
                onChange={(e) => setPaperSearch(e.currentTarget.value)}
                onKeyDown={(e) => e.key === "Enter" && handlePaperSearch()}
                leftSection={<IconSearch size={16} />}
                style={{ flex: 1 }}
              />
              <Button variant="light" color="orange" onClick={handlePaperSearch}>
                Search
              </Button>
              <Button
                variant="subtle"
                color="gray"
                onClick={async () => {
                  setPaperSearch("");
                  const res = await conferenceApi.papers(30);
                  setPapers(res.papers || []);
                }}
              >
                Clear
              </Button>
            </Group>

            {papers.length === 0 ? (
              <Text c="dimmed" ta="center" py="xl">
                No papers found. Run a scan to fetch from arXiv.
              </Text>
            ) : (
              papers.map((paper) => <PaperCard key={paper.paper_id} paper={paper} />)
            )}
          </Stack>
        </Tabs.Panel>

        {/* ── Knowledge Base Tab ──────────────────────────────────── */}
        <Tabs.Panel value="knowledge" pt="lg">
          <Stack gap="md">
            <Group gap="sm" grow>
              <TextInput
                placeholder="Search knowledge base…"
                value={kbSearch}
                onChange={(e) => setKbSearch(e.currentTarget.value)}
                onKeyDown={(e) => e.key === "Enter" && handleKbSearch()}
                leftSection={<IconSearch size={16} />}
              />
              <Select
                placeholder="Filter by type"
                clearable
                value={techFilter}
                onChange={handleTechFilter}
                data={[
                  { value: "deception", label: "Deception" },
                  { value: "fuzzing", label: "Fuzzing" },
                  { value: "exploitation", label: "Exploitation" },
                  { value: "defense", label: "Defense" },
                  { value: "ai_security", label: "AI Security" },
                  { value: "hardware", label: "Hardware" },
                  { value: "crypto", label: "Crypto" },
                  { value: "malware", label: "Malware" },
                  { value: "network", label: "Network" },
                  { value: "general", label: "General" },
                ]}
                w={200}
              />
            </Group>

            {knowledge.length === 0 ? (
              <Text c="dimmed" ta="center" py="xl">
                No knowledge entries yet. Run a full scan to populate.
              </Text>
            ) : (
              <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
                {knowledge.map((entry) => (
                  <KnowledgeCard key={entry.entry_id} entry={entry} onClick={() => setSelectedEntry(entry)} />
                ))}
              </SimpleGrid>
            )}
          </Stack>
        </Tabs.Panel>
      </Tabs>

      {/* Knowledge Entry Detail Modal */}
      <Modal
        opened={!!selectedEntry}
        onClose={() => setSelectedEntry(null)}
        title={selectedEntry?.title}
        size="lg"
      >
        {selectedEntry && (
          <Stack gap="sm">
            <Group gap="xs">
              <Badge color={TECH_TYPE_COLORS[selectedEntry.technique_type] || "gray"} variant="light">
                {selectedEntry.technique_type}
              </Badge>
              {selectedEntry.mitre_attack_ids.map((id) => (
                <Badge key={id} color="red" variant="light">
                  MITRE {id}
                </Badge>
              ))}
            </Group>
            <Text size="sm" c="dimmed">
              Source: {selectedEntry.source}
            </Text>
            {selectedEntry.source_url && (
              <Anchor href={selectedEntry.source_url} target="_blank" size="sm" c="cyan.4">
                <Group gap="xs">
                  <IconExternalLink size={14} />
                  {selectedEntry.source_url}
                </Group>
              </Anchor>
            )}
            <Divider />
            <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
              {selectedEntry.description}
            </Text>
            <Group gap="xs">
              {selectedEntry.tags.map((tag) => (
                <Badge key={tag} size="sm" variant="dot" color="cyan">
                  {tag}
                </Badge>
              ))}
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                Added: {new Date(selectedEntry.added_at).toLocaleString()}
              </Text>
              <Group gap="xs">
                <Text size="xs" c="dimmed">Relevance:</Text>
                <Progress
                  value={selectedEntry.relevance_score * 100}
                  size="sm"
                  w={100}
                  color={selectedEntry.relevance_score > 0.7 ? "green" : "yellow"}
                />
              </Group>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}

// ── Conference Card ──────────────────────────────────────────────────

function ConferenceCard({ conf }: { conf: Conference }) {
  const daysUntil = conf.days_until ?? 0;
  const isImminent = daysUntil <= 7 && conf.status === "upcoming";
  const isOngoing = conf.status === "ongoing";

  return (
    <Card withBorder padding="lg" radius="md" className="pitbull-stat-card"
      style={{
        borderColor: isOngoing ? "var(--mantine-color-green-5)" : isImminent ? "var(--mantine-color-orange-5)" : undefined,
        boxShadow: isOngoing ? "0 0 20px rgba(34,197,94,0.15)" : isImminent ? "0 0 20px rgba(249,115,22,0.1)" : undefined,
      }}
    >
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Stack gap="xs" style={{ flex: 1 }}>
          <Group gap="sm">
            <Badge color={TIER_COLORS[conf.tier] || "gray"} variant="filled" size="sm">
              T{conf.tier}
            </Badge>
            <Badge color={STATUS_COLORS[conf.status] || "gray"} variant="light" size="sm">
              {conf.status}
            </Badge>
            {isOngoing && (
              <Badge color="green" variant="filled" size="sm" leftSection={<IconBolt size={10} />}>
                LIVE
              </Badge>
            )}
          </Group>

          <Text size="lg" fw={700} c="cyan.3">
            {conf.name}
          </Text>

          <Group gap="lg" wrap="wrap">
            <Group gap="xs">
              <IconMapPin size={14} className="mantine-icon-gray" />
              <Text size="sm" c="dimmed">{conf.location}</Text>
            </Group>
            <Group gap="xs">
              <IconCalendar size={14} className="mantine-icon-gray" />
              <Text size="sm" c="dimmed">
                {conf.start_date} → {conf.end_date}
              </Text>
            </Group>
            {conf.status === "upcoming" && daysUntil > 0 && (
              <Group gap="xs">
                <IconClock size={14} className="mantine-icon-gray" />
                <Text size="sm" c={isImminent ? "orange.4" : "cyan.4"} fw={isImminent ? 700 : 400}>
                  {daysUntil} days away
                </Text>
              </Group>
            )}
          </Group>

          <Group gap="xs" wrap="wrap">
            {conf.focus_areas.map((area) => (
              <Badge key={area} size="xs" variant="dot" color="cyan">
                {area}
              </Badge>
            ))}
          </Group>

          <Anchor href={conf.website} target="_blank" size="sm" c="cyan.5">
            <Group gap="xs">
              <IconWorld size={14} />
              {conf.website}
            </Group>
          </Anchor>
        </Stack>
      </Group>
    </Card>
  );
}

// ── Paper Card ──────────────────────────────────────────────────────

function PaperCard({ paper }: { paper: Paper }) {
  const [expanded, setExpanded] = useState(false);
  const abstractPreview = paper.abstract.length > 300 && !expanded
    ? paper.abstract.slice(0, 300) + "…"
    : paper.abstract;

  return (
    <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
      <Stack gap="xs">
        <Group justify="space-between" align="flex-start">
          <Text size="md" fw={700} c="orange.3" style={{ flex: 1 }}>
            {paper.title}
          </Text>
          <Anchor href={paper.arxiv_url} target="_blank" c="cyan.5">
            <IconExternalLink size={16} />
          </Anchor>
        </Group>

        <Text size="xs" c="dimmed">
          {paper.authors.join(", ")}
        </Text>

        <Text size="sm" c="gray.5" style={{ whiteSpace: "pre-wrap" }}>
          {abstractPreview}
        </Text>
        {paper.abstract.length > 300 && (
          <Button
            variant="subtle"
            size="xs"
            color="cyan"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? "Show less" : "Show more"}
          </Button>
        )}

        <Group justify="space-between">
          <Group gap="xs">
            {paper.categories.map((cat) => (
              <Badge key={cat} size="xs" variant="light" color="orange">
                {cat}
              </Badge>
            ))}
          </Group>
          <Text size="xs" c="dimmed">
            {paper.published ? new Date(paper.published).toLocaleDateString() : ""}
          </Text>
        </Group>
      </Stack>
    </Card>
  );
}

// ── Knowledge Card ──────────────────────────────────────────────────

function KnowledgeCard({ entry, onClick }: { entry: KnowledgeEntry; onClick: () => void }) {
  return (
    <Card withBorder padding="lg" radius="md" className="pitbull-stat-card"
      onClick={onClick}
      style={{ cursor: "pointer" }}
    >
      <Stack gap="xs">
        <Group justify="space-between" align="flex-start">
          <Text size="md" fw={700} c="violet.3" style={{ flex: 1 }}>
            {entry.title}
          </Text>
          <Badge color={TECH_TYPE_COLORS[entry.technique_type] || "gray"} variant="light" size="sm">
            {entry.technique_type}
          </Badge>
        </Group>

        <Text size="sm" c="gray.5" lineClamp={3}>
          {entry.description}
        </Text>

        <Group gap="xs" wrap="wrap">
          {entry.tags.slice(0, 5).map((tag) => (
            <Badge key={tag} size="xs" variant="dot" color="violet">
              {tag}
            </Badge>
          ))}
        </Group>

        <Group justify="space-between">
          <Text size="xs" c="dimmed">
            Source: {entry.source}
          </Text>
          <Group gap="xs">
            <IconTag size={12} className="mantine-icon-gray" />
            <Text size="xs" c="dimmed">
              Relevance: {(entry.relevance_score * 100).toFixed(0)}%
            </Text>
          </Group>
        </Group>
      </Stack>
    </Card>
  );
}