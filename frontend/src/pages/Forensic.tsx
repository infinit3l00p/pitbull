import { useState, useCallback } from "react";
import {
  Card,
  Stack,
  Text,
  Group,
  Badge,
  TextInput,
  Button,
  Divider,
  Timeline,
  ThemeIcon,
  ScrollArea,
  Alert,
} from "@mantine/core";
import {
  IconHistory,
  IconSearch,
  IconGitBranch,
  IconCircleDot,
  IconCertificate,
  IconWorld,
  IconServer,
  IconBrain,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { api } from "../api";

export default function ForensicPage() {
  const [target, setTarget] = useState("");
  const [timeline, setTimeline] = useState<any>(null);
  const [genealogy, setGenealogy] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const investigate = useCallback(async () => {
    if (!target.trim()) return;
    setLoading(true);
    try {
      const [tl, gen] = await Promise.all([
        api.getForensicTimeline(target.trim()),
        api.getInfrastructureGenealogy(target.trim()),
      ]);
      setTimeline(tl);
      setGenealogy(gen);
    } catch {}
    setLoading(false);
  }, [target]);

  const eventIcon = (source: string) => {
    if (source === "WHOIS") return <IconWorld size={16} />;
    if (source === "Certificate Transparency") return <IconCertificate size={16} />;
    if (source === "DNS Recon") return <IconServer size={16} />;
    if (source === "PITBULL Memory") return <IconBrain size={16} />;
    return <IconCircleDot size={16} />;
  };

  const severityColor = (severity?: string) => {
    switch (severity) {
      case "critical": return "red";
      case "high": return "orange";
      case "medium": return "yellow";
      case "low": return "blue";
      default: return "gray";
    }
  };

  return (
    <Stack gap="md">
      {/* Search */}
      <Card withBorder padding="lg" radius="md">
        <Group mb="md">
          <IconHistory size={24} color="var(--mantine-color-cyan-5)" />
          <Text fw={700} size="lg">Forensic Reconstruction</Text>
        </Group>
        <Group gap="md" align="flex-end">
          <TextInput
            label="Target Domain"
            placeholder="example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            style={{ flex: 1 }}
            leftSection={<IconSearch size={16} />}
            onKeyDown={(e) => e.key === "Enter" && investigate()}
          />
          <Button loading={loading} onClick={investigate} leftSection={<IconSearch size={16} />}>
            Investigate
          </Button>
        </Group>
      </Card>

      {/* Timeline */}
      {timeline && (
        <Card withBorder padding="lg" radius="md">
          <Group justify="space-between" mb="md">
            <Text fw={700}>Timeline</Text>
            <Badge variant="light" color="cyan">{timeline.count} events</Badge>
          </Group>

          {timeline.count === 0 ? (
            <Text c="dimmed" size="sm" ta="center" py="lg">
              No timeline data — explore this target first
            </Text>
          ) : (
            <ScrollArea.Autosize mah={500}>
              <Timeline active={timeline.count - 1} bulletSize={24} lineWidth={2}>
                {timeline.events.map((event: any, i: number) => (
                  <Timeline.Item
                    key={i}
                    bullet={
                      <ThemeIcon size={24} radius="xl" color={severityColor(event.severity)} variant="light">
                        {eventIcon(event.source)}
                      </ThemeIcon>
                    }
                    title={event.event}
                  >
                    <Text size="xs" c="dimmed">
                      {String(event.date).slice(0, 19)}
                    </Text>
                    {event.details && (
                      <Text size="sm" c="dimmed">{event.details}</Text>
                    )}
                    {event.source && (
                      <Badge size="xs" variant="light" mt={2}>{event.source}</Badge>
                    )}
                  </Timeline.Item>
                ))}
              </Timeline>
            </ScrollArea.Autosize>
          )}
        </Card>
      )}

      {/* Infrastructure Genealogy */}
      {genealogy && (
        <Card withBorder padding="lg" radius="md">
          <Group justify="space-between" mb="md">
            <Group gap="xs">
              <IconGitBranch size={20} color="var(--mantine-color-violet-5)" />
              <Text fw={700}>Infrastructure Genealogy</Text>
            </Group>
            <Badge variant="light" color="violet">{genealogy.count} connections</Badge>
          </Group>

          {genealogy.count === 0 ? (
            <Text c="dimmed" size="sm" ta="center" py="lg">
              No infrastructure connections found
            </Text>
          ) : (
            <Stack gap="xs">
              {genealogy.connections.map((conn: any, i: number) => (
                <Card key={i} withBorder padding="sm" radius="sm">
                  <Group justify="space-between" mb={4}>
                    <Badge size="xs" variant="light" color="blue">{conn.type.replace(/_/g, " ")}</Badge>
                    <Text size="sm" fw={600} c="cyan.4">{conn.to}</Text>
                  </Group>
                  <Text size="sm" c="dimmed">{conn.description}</Text>
                  {conn.evidence && (
                    <Text size="xs" c="dimmed" ff="monospace" mt={2}>
                      Evidence: {Array.isArray(conn.evidence) ? conn.evidence.join(", ") : conn.evidence}
                    </Text>
                  )}
                </Card>
              ))}
            </Stack>
          )}
        </Card>
      )}

      {!timeline && !genealogy && (
        <Alert icon={<IconAlertTriangle size={16} />} color="blue" variant="light">
          Enter a target domain above to reconstruct its forensic timeline and trace infrastructure connections.
          The target must have been explored by PITBULL first.
        </Alert>
      )}
    </Stack>
  );
}