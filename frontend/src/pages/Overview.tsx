import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Grid,
  Text,
  Group,
  Badge,
  Progress,
  SimpleGrid,
  ThemeIcon,
  Box,
  Button,
  Stack,
  RingProgress,
} from "@mantine/core";
import {
  IconHeart,
  IconDatabase,
  IconBrain,
  IconRadar,
  IconNetwork,
  IconActivity,
  IconBolt,
  IconTarget,
  IconShieldLock,
} from "@tabler/icons-react";
import { api, HealthResponse, GraphStats, PersonalityState } from "../api";

interface Props {
  health: HealthResponse | null;
  onNavigate: (page: "overview" | "explore" | "graph" | "mind" | "forensic" | "darknet" | "evolution" | "chat" | "settings") => void;
}

const TRAIT_LABELS: Record<string, string> = {
  openness: "Openness",
  conscientiousness: "Conscientiousness",
  extraversion: "Extraversion",
  agreeableness: "Agreeableness",
  neuroticism: "Neuroticism",
};

const TRAIT_COLORS: Record<string, string> = {
  openness: "cyan",
  conscientiousness: "green",
  extraversion: "orange",
  agreeableness: "violet",
  neuroticism: "red",
};

export default function OverviewPage({ health, onNavigate }: Props) {
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [personality, setPersonality] = useState<PersonalityState | null>(null);
  const [threatStats, setThreatStats] = useState<any>(null);

  const refresh = useCallback(async () => {
    try { setStats(await api.getGraphStats()); } catch {}
    try { setPersonality(await api.getPersonality()); } catch {}
    try { setThreatStats(await api.getThreatStats()); } catch {}
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, [refresh]);

  const totalNodes = stats
    ? stats.domain + stats.subdomain + stats.ipaddress + stats.certificate + stats.memory + stats.onionservice + stats.cve
    : 0;

  return (
    <Stack gap="lg" className="pitbull-fade-in">
      {/* Hero Banner */}
      <Card withBorder padding="xl" radius="lg" className="pitbull-stat-card">
        <Group justify="space-between" align="flex-start">
          <Stack gap={4}>
            <Text size="xs" c="cyan.5" className="pitbull-display" style={{ letterSpacing: "0.2em", opacity: 0.7 }}>
              AUTONOMOUS BENEVOLENT YIELDING & FORENSIC INTELLIGENCE SYSTEM
            </Text>
            <Group gap="sm" style={{ position: "relative" }}>
              <img
                src="/pitbull-head.svg"
                alt="Pitbull"
                width={280}
                height={280}
                style={{
                  position: "absolute",
                  left: "-40px",
                  top: "-50px",
                  opacity: 0.25,
                  filter: "drop-shadow(0 0 20px rgba(251,191,36,0.6)) brightness(0) saturate(100%) invert(85%) sepia(40%) saturate(800%) hue-rotate(0deg)",
                  pointerEvents: "none",
                  zIndex: 0,
                }}
              />
              <Text size="32px" fw={900} className="pitbull-display" c="cyan.3" style={{ textShadow: "0 0 30px rgba(34,211,238,0.3)", position: "relative", zIndex: 1, paddingLeft: "6px" }}>
                PITBULL Dashboard
              </Text>
            </Group>
            <Stack gap={2} mt={4}>
              <Text size="sm" c="dimmed" tt="uppercase" style={{ letterSpacing: "0.05em" }}>
                Self-evolving digital intelligence mapping hidden infrastructure
              </Text>
              <Text size="sm" c="dimmed" tt="uppercase" style={{ letterSpacing: "0.05em" }}>
                across the surface web, deep web, and darknet.
              </Text>
            </Stack>
          </Stack>
          <Group gap="md">
            {personality && (
              <Box style={{ textAlign: "center" }}>
                <RingProgress
                  size={80}
                  thickness={6}
                  roundCaps
                  sections={[{ value: personality.neuroticism > 0 ? (1 - personality.neuroticism) * 100 : 100, color: "cyan" }]}
                  label={<Text size="xs" ta="center" c="cyan.3" className="pitbull-mono">{personality.missions_completed}M</Text>}
                />
                <Text size="xs" c="dimmed" mt={4}>MISSIONS</Text>
              </Box>
            )}
          </Group>
        </Group>
      </Card>

      {/* Stat Cards */}
      <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} spacing="lg">
        {/* System Status */}
        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700} className="pitbull-display">System</Text>
            <ThemeIcon color={health?.status === "healthy" ? "green" : "orange"} variant="light" size="sm"
              styles={{ root: { boxShadow: `0 0 12px ${health?.status === "healthy" ? "rgba(52,211,153,0.4)" : "rgba(251,191,36,0.4)"}` } }}>
              <IconHeart size={16} />
            </ThemeIcon>
          </Group>
          <Text fw={800} size="xl" c={health?.status === "healthy" ? "green.4" : "orange.4"} className="pitbull-display">
            {health?.status?.toUpperCase() || "..."}
          </Text>
          <Text size="xs" c="dimmed" mt={4} className="pitbull-mono">v{health?.version || "0.0.0"}</Text>
        </Card>

        {/* Neo4j */}
        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700} className="pitbull-display">Neo4j</Text>
            <ThemeIcon color={health?.neo4j.connected ? "green" : "red"} variant="light" size="sm"
              styles={{ root: { boxShadow: `0 0 12px ${health?.neo4j.connected ? "rgba(52,211,153,0.4)" : "rgba(248,113,113,0.4)"}` } }}>
              <IconDatabase size={16} />
            </ThemeIcon>
          </Group>
          <Text fw={800} size="xl" c={health?.neo4j.connected ? "green.4" : "red.4"} className="pitbull-display">
            {health?.neo4j.connected ? "CONNECTED" : "OFFLINE"}
          </Text>
          <Text size="xs" c="dimmed" mt={4} className="pitbull-mono">{totalNodes} nodes · {stats?.total_edges || 0} edges</Text>
        </Card>

        {/* Findings */}
        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700} className="pitbull-display">Findings</Text>
            <ThemeIcon color="cyan" variant="light" size="sm"
              styles={{ root: { boxShadow: "0 0 12px rgba(34,211,238,0.4)" } }}>
              <IconRadar size={16} />
            </ThemeIcon>
          </Group>
          <Text fw={800} size="xl" c="cyan.4" className="pitbull-display">
            {personality?.findings_total || 0}
          </Text>
          <Text size="xs" c="dimmed" mt={4} className="pitbull-mono">{personality?.missions_completed || 0} missions completed</Text>
        </Card>

        {/* Accuracy */}
        <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="xs">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700} className="pitbull-display">Accuracy</Text>
            <ThemeIcon color="violet" variant="light" size="sm"
              styles={{ root: { boxShadow: "0 0 12px rgba(167,139,250,0.4)" } }}>
              <IconActivity size={16} />
            </ThemeIcon>
          </Group>
          <Text fw={800} size="xl" c="violet.4" className="pitbull-display">
            {personality && personality.findings_total > 0
              ? `${Math.round((1 - personality.false_positives / personality.findings_total) * 100)}%`
              : "—"}
          </Text>
          <Text size="xs" c="dimmed" mt={4} className="pitbull-mono">{personality?.false_positives || 0} false positives</Text>
        </Card>
      </SimpleGrid>

      {/* Memory Graph + Personality */}
      <Grid>
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card withBorder padding="xl" radius="md" h="100%">
            <Group justify="space-between" mb="md">
              <Group gap="sm">
                <IconNetwork size={20} style={{ color: "var(--pitbull-cyan)" }} />
                <Text fw={700} className="pitbull-display" size="sm">MEMORY GRAPH</Text>
              </Group>
              <Button size="xs" variant="subtle" color="cyan" leftSection={<IconNetwork size={12} />}
                onClick={() => onNavigate("graph")}>
                View →
              </Button>
            </Group>
            <Stack gap="sm">
              {stats && [
                { label: "Domains", count: stats.domain, color: "cyan", max: Math.max(stats.domain, 1) },
                { label: "Subdomains", count: stats.subdomain, color: "blue", max: Math.max(stats.subdomain, 1) },
                { label: "IP Addresses", count: stats.ipaddress, color: "teal", max: Math.max(stats.ipaddress, 1) },
                { label: "Certificates", count: stats.certificate, color: "indigo", max: Math.max(stats.certificate, 1) },
                { label: "Memories", count: stats.memory, color: "violet", max: Math.max(stats.memory, 1) },
                { label: "Onion Services", count: stats.onionservice, color: "grape", max: Math.max(stats.onionservice, 1) },
                { label: "CVEs", count: stats.cve, color: "red", max: Math.max(stats.cve, 1) },
              ].map((item) => {
                const max = Math.max(stats.domain + stats.subdomain + stats.ipaddress + stats.certificate, 1);
                return (
                  <Group key={item.label} justify="space-between" align="center">
                    <Text size="xs" c="dimmed" style={{ width: 100 }}>{item.label}</Text>
                    <Progress value={(item.count / max) * 100} color={item.color} size="sm" style={{ flex: 1, marginRight: 8 }} />
                    <Text size="xs" c="dimmed" className="pitbull-mono" style={{ width: 40, textAlign: "right" }}>{item.count}</Text>
                  </Group>
                );
              })}
              {!stats && <Text c="dimmed" size="sm">Loading...</Text>}
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card withBorder padding="xl" radius="md" h="100%">
            <Group justify="space-between" mb="md">
              <Group gap="sm">
                <IconBrain size={20} style={{ color: "var(--pitbull-violet)" }} />
                <Text fw={700} className="pitbull-display" size="sm">PERSONALITY · OCEAN</Text>
              </Group>
              <Button size="xs" variant="subtle" color="violet" leftSection={<IconBrain size={12} />}
                onClick={() => onNavigate("mind")}>
                Mind Stream →
              </Button>
            </Group>
            <Stack gap="sm">
              {personality && Object.entries(TRAIT_LABELS).map(([key, label]) => {
                const val = personality[key as keyof PersonalityState] as number;
                return (
                  <Box key={key}>
                    <Group justify="space-between" mb={4}>
                      <Text size="xs" c="dimmed">{label}</Text>
                      <Text size="xs" className="pitbull-mono" c={`${TRAIT_COLORS[key]}.4`}>{(val * 100).toFixed(1)}%</Text>
                    </Group>
                    <Progress
                      value={val * 100}
                      color={TRAIT_COLORS[key]}
                      size="md"
                      radius="xl"
                      styles={{ section: { boxShadow: `0 0 10px var(--pitbull-${TRAIT_COLORS[key] === 'cyan' ? 'cyan' : TRAIT_COLORS[key] === 'green' ? 'green' : TRAIT_COLORS[key] === 'orange' ? 'amber' : TRAIT_COLORS[key] === 'violet' ? 'violet' : 'red'}-glow)` } }}
                    />
                  </Box>
                );
              })}
              {!personality && <Text c="dimmed" size="sm">Loading...</Text>}
              {personality && (
                <Group justify="space-between" mt="sm" p="sm" style={{ background: "rgba(34,211,238,0.05)", borderRadius: 8, border: "1px solid var(--pitbull-border)" }}>
                  <Text size="xs" c="dimmed">Current Mood</Text>
                  <Badge color={personality.mood === "neutral" ? "gray" : personality.mood === "satisfied" ? "green" : "yellow"} variant="light">
                    {personality.mood}
                  </Badge>
                </Group>
              )}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      {/* Quick Actions */}
      {/* Threat Intelligence */}
      {threatStats && (
        <Card withBorder padding="xl" radius="md" className="pitbull-stat-card">
          <Group justify="space-between" mb="md">
            <Group gap="sm">
              <IconShieldLock size={20} style={{ color: "var(--pitbull-red)", filter: "drop-shadow(0 0 8px var(--pitbull-red-glow))" }} />
              <Text fw={700} className="pitbull-display" size="sm" c="red.4">THREAT INTELLIGENCE</Text>
            </Group>
            <Badge variant="light" color="cyan" className="pitbull-display" size="xs">LIVE</Badge>
          </Group>
          <SimpleGrid cols={{ base: 2, sm: 3, md: 6 }} spacing="md">
            <Group justify="space-between">
              <Text size="xs" c="dimmed" className="pitbull-display">CVEs</Text>
              <Badge color="red" variant="light" size="lg" className="pitbull-mono">{threatStats.cves_total}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed" className="pitbull-display">Critical</Text>
              <Badge color="red" variant="filled" size="lg" className="pitbull-mono">{threatStats.cves_critical}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed" className="pitbull-display">High</Text>
              <Badge color="orange" variant="filled" size="lg" className="pitbull-mono">{threatStats.cves_high}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed" className="pitbull-display">OWASP</Text>
              <Badge color="violet" variant="light" size="lg" className="pitbull-mono">{threatStats.owasp_categories}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed" className="pitbull-display">ATT&CK</Text>
              <Badge color="cyan" variant="light" size="lg" className="pitbull-mono">{threatStats.attack_techniques}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed" className="pitbull-display">Mappings</Text>
              <Badge color="teal" variant="light" size="lg" className="pitbull-mono">{threatStats.cve_attack_mappings}</Badge>
            </Group>
          </SimpleGrid>
          {threatStats.cves_by_severity && Object.keys(threatStats.cves_by_severity).length > 0 && (
            <Group mt="sm" gap="xs">
              {Object.entries(threatStats.cves_by_severity).map(([sev, count]) => (
                <Badge key={sev} size="xs" variant="light" color={sev === 'CRITICAL' ? 'red' : sev === 'HIGH' ? 'orange' : sev === 'MEDIUM' ? 'yellow' : 'gray'}>
                  {sev}: {String(count)}
                </Badge>
              ))}
            </Group>
          )}
        </Card>
      )}

      {/* Quick Actions */}
      <Card withBorder padding="lg" radius="md" className="pitbull-stat-card">
        <Group justify="space-between" mb="md">
          <Text fw={700} className="pitbull-display" size="sm">QUICK ACTIONS</Text>
        </Group>
        <Group gap="md">
          <Button leftSection={<IconRadar size={16} />} onClick={() => onNavigate("explore")} size="md" radius="md">
            Launch Mission
          </Button>
          <Button variant="light" color="cyan" leftSection={<IconNetwork size={16} />} onClick={() => onNavigate("graph")}>
            Memory Graph
          </Button>
          <Button variant="light" color="violet" leftSection={<IconBrain size={16} />} onClick={() => onNavigate("mind")}>
            Mind Stream
          </Button>
          <Button variant="light" color="orange" leftSection={<IconTarget size={16} />} onClick={() => onNavigate("forensic")}>
            Forensic
          </Button>
          <Button variant="light" color="teal" leftSection={<IconBolt size={16} />} onClick={() => onNavigate("chat")}>
            Chat with PITBULL
          </Button>
        </Group>
      </Card>
    </Stack>
  );
}