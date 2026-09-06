import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Stack,
  Text,
  Group,
  Badge,
  Tabs,
  ScrollArea,
  ThemeIcon,
  SimpleGrid,
  Progress,
  Alert,
  Code,
} from "@mantine/core";
import {
  IconAtom,
  IconAlertTriangle,
  IconBulb,
  IconBook2,
  IconTools,
  IconTrendingUp,
  IconBrain,
  IconMoodSmile,
} from "@tabler/icons-react";
import { api } from "../api";

const TRAIT_COLORS: Record<string, string> = {
  openness: "cyan",
  conscientiousness: "green",
  extraversion: "orange",
  agreeableness: "violet",
  neuroticism: "red",
};

export default function EvolutionPage() {
  const [mistakeStats, setMistakeStats] = useState<any>(null);
  const [lessons, setLessons] = useState<any[]>([]);
  const [knowledgeStats, setKnowledgeStats] = useState<any>(null);
  const [studyPlan, setStudyPlan] = useState<any[]>([]);
  const [gaps, setGaps] = useState<any[]>([]);
  const [tools, setTools] = useState<any[]>([]);
  const [driftHistory, setDriftHistory] = useState<any[]>([]);
  const [personality, setPersonality] = useState<any>(null);
  const [evolutionSummary, setEvolutionSummary] = useState<any>(null);

  const refresh = useCallback(async () => {
    try { setMistakeStats(await api.getMistakeStats()); } catch {}
    try { setLessons((await api.getLessons()).lessons || []); } catch {}
    try { setKnowledgeStats(await api.getKnowledgeStats()); } catch {}
    try { setStudyPlan((await api.getStudyPlan()).plan || []); } catch {}
    try { setGaps((await api.getKnowledgeGaps()).gaps || []); } catch {}
    try { setTools((await api.getGeneratedTools()).tools || []); } catch {}
    try { setDriftHistory((await api.getDriftHistory()).history || []); } catch {}
    try { setPersonality(await api.getPersonality()); } catch {}
    try {
      const evo = await api.getEvolutionHistory();
      setEvolutionSummary(evo.summary);
    } catch {}
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 10000);
    return () => clearInterval(interval);
  }, [refresh]);

  return (
    <Stack gap="md">
      {/* Evolution Summary */}
      <Card withBorder padding="lg" radius="md">
        <Group mb="md">
          <IconAtom size={24} color="var(--mantine-color-cyan-5)" />
          <Text fw={700} size="lg">PITBULL Evolution</Text>
          {evolutionSummary && (
            <Badge variant="light" color="cyan">
              {evolutionSummary.total_adjustments} adjustments
            </Badge>
          )}
        </Group>

        {personality && evolutionSummary && (
          <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} spacing="md">
            {/* Current traits with drift */}
            {Object.entries(TRAIT_COLORS).map(([trait, color]) => {
              const val = personality[trait] as number;
              const delta = evolutionSummary.trait_deltas?.[trait] || 0;
              return (
                <div key={trait}>
                  <Group justify="space-between" mb={4}>
                    <Text size="xs" c="dimmed" style={{ textTransform: "capitalize" }}>{trait}</Text>
                    <Group gap={4}>
                      <Text size="xs" c={delta > 0 ? "green.4" : delta < 0 ? "red.4" : "dimmed"}>
                        {delta > 0 ? "+" : ""}{delta.toFixed(4)}
                      </Text>
                      <Text size="xs" c="dimmed">{(val * 100).toFixed(1)}%</Text>
                    </Group>
                  </Group>
                  <Progress value={val * 100} color={color} size="sm" radius="xs" />
                </div>
              );
            })}
          </SimpleGrid>
        )}

        {evolutionSummary && (
          <Group mt="md" gap="xs">
            {Object.entries(evolutionSummary.event_counts || {}).map(([event, count]) => (
              <Badge key={event} size="xs" variant="light" color="blue">
                {event}: {String(count)}
              </Badge>
            ))}
          </Group>
        )}
      </Card>

      {/* Tabs */}
      <Card withBorder padding="lg" radius="md">
        <Tabs defaultValue="mistakes">
          <Tabs.List>
            <Tabs.Tab value="mistakes" leftSection={<IconAlertTriangle size={16} />}>
              Mistakes
            </Tabs.Tab>
            <Tabs.Tab value="patterns" leftSection={<IconBulb size={16} />}>
              Knowledge Gaps
            </Tabs.Tab>
            <Tabs.Tab value="study" leftSection={<IconBook2 size={16} />}>
              Study Plan
            </Tabs.Tab>
            <Tabs.Tab value="tools" leftSection={<IconTools size={16} />}>
              Tools
            </Tabs.Tab>
            <Tabs.Tab value="drift" leftSection={<IconTrendingUp size={16} />}>
              Drift History
            </Tabs.Tab>
          </Tabs.List>

          {/* Mistakes Tab */}
          <Tabs.Panel value="mistakes" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {mistakeStats && mistakeStats.total_mistakes === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No mistakes logged yet — PITBULL is being careful
                  </Text>
                )}
                {lessons.length === 0 && mistakeStats?.total_mistakes > 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    Mistakes logged but no lessons extracted yet
                  </Text>
                )}
                {lessons.map((lesson, i) => (
                  <Card key={i} withBorder padding="sm" radius="sm">
                    <Group justify="space-between" mb={4}>
                      <Badge size="xs" color="orange" variant="light">{lesson.type}</Badge>
                      <Text size="xs" c="dimmed">{lesson.timestamp?.slice(0, 10)}</Text>
                    </Group>
                    <Text size="sm">{lesson.lesson}</Text>
                    {lesson.target && <Text size="xs" c="dimmed" ff="monospace">{lesson.target}</Text>}
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>

          {/* Knowledge Gaps Tab */}
          <Tabs.Panel value="patterns" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {gaps.length === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No knowledge gaps identified yet
                  </Text>
                )}
                {gaps.map((gap, i) => (
                  <Card key={i} withBorder padding="sm" radius="sm">
                    <Group gap="xs" mb={4}>
                      <Badge size="xs" color="yellow" variant="light">{gap.gap_type}</Badge>
                    </Group>
                    <Text size="sm">{gap.description}</Text>
                    {gap.items && gap.items.length > 0 && (
                      <Group gap={4} mt={4}>
                        {gap.items.slice(0, 10).map((item: string, j: number) => (
                          <Badge key={j} size="xs" variant="light">{item}</Badge>
                        ))}
                        {gap.items.length > 10 && <Text size="xs" c="dimmed">+{gap.items.length - 10} more</Text>}
                      </Group>
                    )}
                    {gap.suggestion && <Text size="xs" c="cyan.5" mt={4}>→ {gap.suggestion}</Text>}
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>

          {/* Study Plan Tab */}
          <Tabs.Panel value="study" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {studyPlan.length === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No study plan generated yet
                  </Text>
                )}
                {studyPlan.map((item, i) => (
                  <Card key={i} withBorder padding="sm" radius="sm">
                    <Group justify="space-between" mb={4}>
                      <Text size="sm" fw={600}>{item.topic}</Text>
                      <Badge size="xs" color={item.priority === "high" ? "red" : "yellow"} variant="light">
                        {item.priority}
                      </Badge>
                    </Group>
                    <Text size="xs" c="dimmed">{item.reason}</Text>
                    <Badge size="xs" variant="light" mt={4}>{item.type}</Badge>
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>

          {/* Tools Tab */}
          <Tabs.Panel value="tools" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {tools.length === 0 && (
                  <Alert icon={<IconTools size={16} />} color="blue" variant="light">
                    No tools generated yet. PITBULL will generate custom scripts when it encounters capability gaps during exploration.
                  </Alert>
                )}
                {tools.map((tool, i) => (
                  <Card key={i} withBorder padding="sm" radius="sm">
                    <Group justify="space-between" mb={4}>
                      <Text size="sm" fw={600} ff="monospace">{tool.name}</Text>
                      <Badge size="xs" color={tool.successful ? "green" : "gray"} variant="light">
                        {tool.tested ? (tool.successful ? "tested ✓" : "failed") : "untested"}
                      </Badge>
                    </Group>
                    <Text size="xs" c="dimmed">{tool.gap}</Text>
                    <Text size="xs" c="dimmed" mt={2}>{tool.generated_at?.slice(0, 19)}</Text>
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>

          {/* Drift History Tab */}
          <Tabs.Panel value="drift" pt="md">
            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                {driftHistory.length === 0 && (
                  <Text c="dimmed" size="sm" ta="center" py="xl">
                    No personality drift recorded yet
                  </Text>
                )}
                {driftHistory.map((entry, i) => (
                  <Card key={i} withBorder padding="sm" radius="sm">
                    <Group justify="space-between" mb={4}>
                      <Badge size="xs" color={TRAIT_COLORS[entry.trait] || "gray"} variant="light">
                        {entry.trait}
                      </Badge>
                      <Text size="sm" fw={600} c={entry.delta > 0 ? "green.4" : "red.4"}>
                        {entry.delta > 0 ? "+" : ""}{entry.delta.toFixed(5)}
                      </Text>
                    </Group>
                    <Text size="xs" c="dimmed">{entry.reason}</Text>
                    <Text size="xs" c="dimmed">{entry.timestamp?.slice(0, 19)}</Text>
                  </Card>
                ))}
              </Stack>
            </ScrollArea.Autosize>
          </Tabs.Panel>
        </Tabs>
      </Card>

      {/* Knowledge Stats */}
      {knowledgeStats && (
        <Card withBorder padding="lg" radius="md">
          <Group mb="sm">
            <IconBrain size={20} color="var(--mantine-color-violet-5)" />
            <Text fw={700}>Knowledge Base</Text>
          </Group>
          <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
            <Group justify="space-between">
              <Text size="xs" c="dimmed">CVEs</Text>
              <Badge color="red" variant="light">{knowledgeStats.cves_known}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">Semantic Rules</Text>
              <Badge color="violet" variant="light">{knowledgeStats.semantic_rules}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">Episodic</Text>
              <Badge color="cyan" variant="light">{knowledgeStats.episodic_memories}</Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">Procedural</Text>
              <Badge color="green" variant="light">{knowledgeStats.procedural_memories}</Badge>
            </Group>
          </SimpleGrid>
        </Card>
      )}
    </Stack>
  );
}