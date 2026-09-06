import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Stack,
  Text,
  Group,
  Badge,
  ScrollArea,
  Select,
  TextInput,
  Divider,
  ThemeIcon,
  Progress,
  Tabs,
  Table,
} from "@mantine/core";
import {
  IconBrain,
  IconMoodSmile,
  IconBulb,
  IconAlertTriangle,
  IconInfoCircle,
  IconRefresh,
  IconBook2,
  IconBulb as IconBulbFilled,
  IconHistory,
} from "@tabler/icons-react";
import { api, PersonalityState, Memory, MoodState, Opinion, SemanticRule, EvolutionEntry } from "../api";

const SEVERITY_ICONS: Record<string, typeof IconInfoCircle> = {
  critical: IconAlertTriangle,
  high: IconAlertTriangle,
  medium: IconBulb,
  low: IconInfoCircle,
  info: IconInfoCircle,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "red",
  high: "orange",
  medium: "yellow",
  low: "blue",
  info: "gray",
};

const TRAIT_COLORS: Record<string, string> = {
  openness: "cyan",
  conscientiousness: "green",
  extraversion: "orange",
  agreeableness: "violet",
  neuroticism: "red",
};

const MOOD_COLORS: Record<string, string> = {
  neutral: "gray",
  excited: "yellow",
  bored: "blue",
  frustrated: "red",
  cautious: "orange",
  satisfied: "green",
  curious: "cyan",
};

export default function MindStreamPage() {
  const [personality, setPersonality] = useState<PersonalityState | null>(null);
  const [mood, setMood] = useState<MoodState | null>(null);
  const [memories, setMemories] = useState<Memory[]>([]);
  const [opinions, setOpinions] = useState<Opinion[]>([]);
  const [rules, setRules] = useState<SemanticRule[]>([]);
  const [evolution, setEvolution] = useState<EvolutionEntry[]>([]);
  const [filter, setFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const refresh = useCallback(async () => {
    try { setPersonality(await api.getPersonality()); } catch {}
    try { setMood(await api.getMood()); } catch {}
    try {
      const data = await api.getMemories(100, filter || undefined);
      setMemories(data.memories);
    } catch {}
    try { setOpinions((await api.getOpinions()).opinions); } catch {}
    try { setRules((await api.getSemanticRules()).rules); } catch {}
    try { setEvolution((await api.getEvolutionHistory()).history); } catch {}
  }, [filter]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, [refresh]);

  const filteredMemories = memories.filter(
    (m) =>
      !search ||
      m.content.toLowerCase().includes(search.toLowerCase()) ||
      m.target.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <Stack gap="md">
      {/* Personality + Mood */}
      <Card withBorder padding="lg" radius="md">
        <Group mb="md">
          <IconBrain size={24} color="var(--mantine-color-violet-5)" />
          <Text fw={700} size="lg">PITBULL Mind</Text>
          {personality && (
            <Badge
              color={MOOD_COLORS[personality.mood] || "gray"}
              variant="light"
              leftSection={<IconMoodSmile size={12} />}
            >
              {personality.mood}
            </Badge>
          )}
          {mood?.expires && (
            <Text size="xs" c="dimmed">
              expires {new Date(mood.expires).toLocaleTimeString()}
            </Text>
          )}
        </Group>

        {personality && (
          <Group gap="lg" align="flex-start">
            {/* Traits */}
            <Stack gap="xs" style={{ flex: 1 }}>
              {Object.entries(TRAIT_COLORS).map(([trait, color]) => {
                const val = personality[trait as keyof PersonalityState] as number;
                return (
                  <Group key={trait} gap="sm" align="center">
                    <Text size="xs" c="dimmed" style={{ width: 130, textTransform: "capitalize" }}>
                      {trait}
                    </Text>
                    <Progress value={val * 100} color={color} size="sm" style={{ flex: 1 }} />
                    <Text size="xs" c="dimmed" style={{ width: 36 }} ta="right">
                      {(val * 100).toFixed(0)}%
                    </Text>
                  </Group>
                );
              })}
            </Stack>

            {/* Stats */}
            <Stack gap="xs" style={{ width: 200 }}>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Missions</Text>
                <Badge size="sm" variant="light">{personality.missions_completed}</Badge>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Findings</Text>
                <Badge size="sm" variant="light" color="cyan">{personality.findings_total}</Badge>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">False Positives</Text>
                <Badge size="sm" variant="light" color="red">{personality.false_positives}</Badge>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Mistakes Learned</Text>
                <Badge size="sm" variant="light" color="violet">{personality.mistakes_learned}</Badge>
              </Group>
            </Stack>

            {/* Mood Effects */}
            {mood && Object.keys(mood.effects).length > 0 && (
              <Stack gap="xs" style={{ width: 200 }}>
                <Text size="xs" fw={600} c="dimmed">Mood Effects</Text>
                {Object.entries(mood.effects).map(([key, val]) => (
                  <Group key={key} justify="space-between">
                    <Text size="xs" c="dimmed">{key.replace(/_/g, " ")}</Text>
                    <Badge size="xs" variant="light" color={MOOD_COLORS[mood.mood] || "gray"}>
                      {val.toFixed(2)}
                    </Badge>
                  </Group>
                ))}
              </Stack>
            )}
          </Group>
        )}
      </Card>

      {/* Tabs: Memories | Opinions | Semantic Rules | Evolution */}
      <Card withBorder padding="lg" radius="md">
        <Tabs defaultValue="memories">
          <Tabs.List>
            <Tabs.Tab value="memories" leftSection={<IconBrain size={16} />}>
              Memories
            </Tabs.Tab>
            <Tabs.Tab value="opinions" leftSection={<IconBulb size={16} />}>
              Opinions {opinions.length > 0 && `(${opinions.length})`}
            </Tabs.Tab>
            <Tabs.Tab value="rules" leftSection={<IconBook2 size={16} />}>
              Semantic Rules {rules.length > 0 && `(${rules.length})`}
            </Tabs.Tab>
            <Tabs.Tab value="evolution" leftSection={<IconHistory size={16} />}>
              Evolution {evolution.length > 0 && `(${evolution.length})`}
            </Tabs.Tab>
          </Tabs.List>

          {/* Memories Tab */}
          <Tabs.Panel value="memories" pt="md">
            <Group justify="space-between" mb="sm">
              <Select
                size="xs"
                w={140}
                clearable
                placeholder="All types"
                value={filter}
                onChange={(v) => setFilter(v)}
                data={[
                  { value: "episodic", label: "Episodic" },
                  { value: "semantic", label: "Semantic" },
                  { value: "procedural", label: "Procedural" },
                  { value: "cartographic", label: "Cartographic" },
                ]}
              />
              <TextInput
                size="xs"
                w={180}
                placeholder="Search memories..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Group>
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {filteredMemories.length === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No memories yet
                  </Text>
                )}
                {filteredMemories.map((m) => {
                  const SevIcon = SEVERITY_ICONS[m.severity] || IconInfoCircle;
                  const sevColor = SEVERITY_COLORS[m.severity] || "gray";
                  return (
                    <Card key={m.id} withBorder padding="sm" radius="sm">
                      <Group gap="sm" align="flex-start">
                        <ThemeIcon size="sm" color={sevColor} variant="light">
                          <SevIcon size={14} />
                        </ThemeIcon>
                        <Stack gap={2} style={{ flex: 1 }}>
                          <Group gap="xs">
                            <Badge size="xs" color={sevColor} variant="light">{m.severity}</Badge>
                            <Badge size="xs" variant="light" color="violet">{m.type}</Badge>
                            {m.target && (
                              <Text size="xs" c="dimmed" ff="monospace">{m.target}</Text>
                            )}
                          </Group>
                          <Text size="sm">{m.content}</Text>
                          <Text size="xs" c="dimmed">{m.timestamp}</Text>
                        </Stack>
                      </Group>
                    </Card>
                  );
                })}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>

          {/* Opinions Tab */}
          <Tabs.Panel value="opinions" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {opinions.length === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No opinions formed yet — PITBULL will develop opinions as it explores more targets
                  </Text>
                )}
                {opinions.map((op) => (
                  <Card key={op.id} withBorder padding="sm" radius="sm">
                    <Group justify="space-between" mb={4}>
                      <Group gap="xs">
                        <Badge size="xs" variant="light" color="yellow">{op.category}</Badge>
                        <Text size="sm" fw={600}>{op.subject}</Text>
                        {op.revised && <Badge size="xs" color="orange" variant="light">revised</Badge>}
                      </Group>
                      <Badge size="xs" color={op.confidence > 0.7 ? "green" : op.confidence > 0.4 ? "yellow" : "gray"}>
                        {(op.confidence * 100).toFixed(0)}% confident
                      </Badge>
                    </Group>
                    <Text size="sm" c="dimmed">{op.text}</Text>
                    <Group gap="xs" mt={4}>
                      <Text size="xs" c="dimmed">{op.evidence_count} evidence</Text>
                      <Text size="xs" c="dimmed">·</Text>
                      <Text size="xs" c="dimmed">{op.supporting_count} supporting</Text>
                      {op.contradictions > 0 && (
                        <>
                          <Text size="xs" c="dimmed">·</Text>
                          <Text size="xs" c="red.5">{op.contradictions} contradictions</Text>
                        </>
                      )}
                    </Group>
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>

          {/* Semantic Rules Tab */}
          <Tabs.Panel value="rules" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {rules.length === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No semantic rules yet — memories will consolidate into rules after more explorations
                  </Text>
                )}
                {rules.map((r) => (
                  <Card key={r.id} withBorder padding="sm" radius="sm">
                    <Group justify="space-between" mb={4}>
                      <Group gap="xs">
                        <Badge size="xs" variant="light" color="indigo">{r.rule_type}</Badge>
                        <Text size="sm" fw={600}>{r.subject}</Text>
                      </Group>
                      <Badge size="xs" color={r.confidence > 0.7 ? "green" : "yellow"}>
                        {(r.confidence * 100).toFixed(0)}%
                      </Badge>
                    </Group>
                    <Text size="sm" c="dimmed">{r.content}</Text>
                    <Group gap="xs" mt={4}>
                      <Text size="xs" c="dimmed">{r.evidence_count} evidence</Text>
                      <Text size="xs" c="dimmed">·</Text>
                      <Text size="xs" c="dimmed">applied {r.times_applied}×</Text>
                      {r.times_confirmed > 0 && (
                        <Text size="xs" c="green.5">· {r.times_confirmed} confirmed</Text>
                      )}
                    </Group>
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>

          {/* Evolution Tab */}
          <Tabs.Panel value="evolution" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {evolution.length === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No personality evolution yet — traits will shift as PITBULL gains experience
                  </Text>
                )}
                {evolution.map((e, i) => (
                  <Card key={i} withBorder padding="sm" radius="sm">
                    <Group justify="space-between" mb={4}>
                      <Group gap="xs">
                        <Badge size="xs" color={TRAIT_COLORS[e.trait] || "gray"} variant="light">
                          {e.trait}
                        </Badge>
                        <Text size="sm" fw={600} c={e.delta > 0 ? "green.4" : "red.4"}>
                          {e.delta > 0 ? "+" : ""}{e.delta.toFixed(4)}
                        </Text>
                      </Group>
                      <Badge size="xs" variant="light">{e.event_type}</Badge>
                    </Group>
                    <Text size="sm" c="dimmed">{e.reason}</Text>
                    {e.target && <Text size="xs" c="dimmed" ff="monospace">{e.target}</Text>}
                    <Text size="xs" c="dimmed">{e.timestamp}</Text>
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>
        </Tabs>
      </Card>
    </Stack>
  );
}