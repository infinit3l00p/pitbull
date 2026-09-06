import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Stack,
  Text,
  Group,
  Badge,
  Button,
  ThemeIcon,
  ScrollArea,
  TextInput,
  Code,
  Alert,
  SimpleGrid,
} from "@mantine/core";
import {
  IconMoon,
  IconBolt,
  IconSearch,
  IconWorldWww,
  IconShieldCheck,
  IconRefresh,
  IconAlertTriangle,
  IconCircleCheck,
  IconCircleX,
} from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "../api";

export default function DarknetPage() {
  const [torStatus, setTorStatus] = useState<any>(null);
  const [i2pStatus, setI2pStatus] = useState<any>(null);
  const [onions, setOnions] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [classifying, setClassifying] = useState(false);
  const [onionUrl, setOnionUrl] = useState("");
  const [classifyResult, setClassifyResult] = useState<any>(null);

  const refresh = useCallback(async () => {
    try { setTorStatus(await api.getTorStatus()); } catch {}
    try { setI2pStatus(await api.getI2PStatus()); } catch {}
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 15000);
    return () => clearInterval(interval);
  }, [refresh]);

  const handleNewCircuit = async () => {
    try {
      await api.newTorCircuit();
      notifications.show({ message: "New Tor circuit requested", color: "cyan" });
      refresh();
    } catch {
      notifications.show({ message: "Failed to get new circuit", color: "red" });
    }
  };

  const handleDiscover = async () => {
    try {
      const data = await api.discoverOnions(searchQuery);
      setOnions(data.onions || []);
      notifications.show({
        message: `Found ${data.count || 0} .onion addresses`,
        color: data.count > 0 ? "green" : "gray",
      });
    } catch {
      notifications.show({ message: "Discovery failed", color: "red" });
    }
  };

  const handleClassify = async () => {
    if (!onionUrl.trim()) return;
    setClassifying(true);
    try {
      const result = await api.classifyOnion(onionUrl.trim());
      setClassifyResult(result);
      if (result.online) {
        notifications.show({
          title: "Onion Classified",
          message: `[${result.service_type}] ${result.title || "No title"}`,
          color: "violet",
        });
      } else {
        notifications.show({
          message: `Onion offline or unreachable: ${result.error || "unknown"}`,
          color: "orange",
        });
      }
    } catch {
      notifications.show({ message: "Classification failed", color: "red" });
    }
    setClassifying(false);
  };

  return (
    <Stack gap="md">
      {/* Tor Status */}
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
        <Card withBorder padding="lg" radius="md">
          <Group justify="space-between" mb="sm">
            <Group gap="xs">
              <ThemeIcon color={torStatus?.running ? "green" : "red"} variant="light">
                {torStatus?.running ? <IconCircleCheck size={18} /> : <IconCircleX size={18} />}
              </ThemeIcon>
              <Text fw={700}>Tor Network</Text>
            </Group>
            <Badge color={torStatus?.running ? "green" : "red"} variant="light">
              {torStatus?.running ? "Connected" : "Offline"}
            </Badge>
          </Group>
          {torStatus?.running && (
            <Stack gap="xs">
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Version</Text>
                <Text size="xs" ff="monospace">{torStatus.version || "?"}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">SOCKS Port</Text>
                <Text size="xs" ff="monospace">{torStatus.socks_port}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Control Port</Text>
                <Text size="xs" ff="monospace">{torStatus.control_port}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Active Circuits</Text>
                <Badge size="xs" variant="light" color="cyan">{torStatus.circuit_status || 0}</Badge>
              </Group>
              <Button size="xs" variant="light" leftSection={<IconBolt size={14} />} onClick={handleNewCircuit} mt="xs">
                New Identity
              </Button>
            </Stack>
          )}
          {!torStatus?.running && (
            <Text size="sm" c="dimmed">Start Tor to enable darknet exploration</Text>
          )}
        </Card>

        {/* I2P Status */}
        <Card withBorder padding="lg" radius="md">
          <Group justify="space-between" mb="sm">
            <Group gap="xs">
              <ThemeIcon color={i2pStatus?.running ? "green" : "gray"} variant="light">
                {i2pStatus?.running ? <IconCircleCheck size={18} /> : <IconCircleX size={18} />}
              </ThemeIcon>
              <Text fw={700}>I2P Network</Text>
            </Group>
            <Badge color={i2pStatus?.running ? "green" : "gray"} variant="light">
              {i2pStatus?.running ? "Connected" : "Not Running"}
            </Badge>
          </Group>
          {i2pStatus?.running ? (
            <Stack gap="xs">
              <Group justify="space-between">
                <Text size="xs" c="dimmed">HTTP Proxy</Text>
                <Text size="xs" ff="monospace">{i2pStatus.http_proxy || "?"}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Router Console</Text>
                <Text size="xs" ff="monospace">{i2pStatus.router_console || "?"}</Text>
              </Group>
            </Stack>
          ) : (
            <Text size="sm" c="dimmed">Install I2P for eepsite exploration</Text>
          )}
        </Card>
      </SimpleGrid>

      {/* Onion Discovery */}
      <Card withBorder padding="lg" radius="md">
        <Group mb="md">
          <IconSearch size={20} color="var(--mantine-color-violet-5)" />
          <Text fw={700}>Onion Service Discovery</Text>
        </Group>
        <Group gap="md" align="flex-end" mb="md">
          <TextInput
            placeholder="Search query (optional)"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ flex: 1 }}
            onKeyDown={(e) => e.key === "Enter" && handleDiscover()}
          />
          <Button onClick={handleDiscover} leftSection={<IconSearch size={16} />}>
            Discover
          </Button>
        </Group>

        {onions.length > 0 && (
          <ScrollArea.Autosize mah={200}>
            <Stack gap="xs">
              {onions.map((onion, i) => (
                <Group key={i} gap="xs">
                  <IconWorldWww size={14} color="var(--mantine-color-violet-5)" />
                  <Code>{onion}</Code>
                </Group>
              ))}
            </Stack>
          </ScrollArea.Autosize>
        )}
      </Card>

      {/* Onion Classification */}
      <Card withBorder padding="lg" radius="md">
        <Group mb="md">
          <IconShieldCheck size={20} color="var(--mantine-color-cyan-5)" />
          <Text fw={700}>Onion Service Classification</Text>
        </Group>
        <Group gap="md" align="flex-end" mb="md">
          <TextInput
            placeholder="http://abcdefghijklmnop.onion"
            value={onionUrl}
            onChange={(e) => setOnionUrl(e.target.value)}
            style={{ flex: 1 }}
            onKeyDown={(e) => e.key === "Enter" && handleClassify()}
          />
          <Button loading={classifying} onClick={handleClassify} leftSection={<IconShieldCheck size={16} />}>
            Classify
          </Button>
        </Group>

        {classifyResult && (
          <Stack gap="sm">
            <Group gap="xs">
              <Badge color={classifyResult.online ? "green" : "red"} variant="light">
                {classifyResult.online ? "Online" : "Offline"}
              </Badge>
              {classifyResult.classified && (
                <Badge color="violet" variant="light">
                  {classifyResult.service_type}
                </Badge>
              )}
              {classifyResult.opsec && (
                <Badge color={
                  classifyResult.opsec.risk_level === "critical" ? "red" :
                  classifyResult.opsec.risk_level === "high" ? "orange" :
                  classifyResult.opsec.risk_level === "medium" ? "yellow" : "green"
                } variant="light">
                  Risk: {classifyResult.opsec.risk_level}
                </Badge>
              )}
            </Group>

            {classifyResult.title && (
              <Text size="sm" fw={600}>{classifyResult.title}</Text>
            )}

            {classifyResult.opsec && (
              <Alert
                icon={<IconAlertTriangle size={16} />}
                color={
                  classifyResult.opsec.risk_level === "critical" ? "red" :
                  classifyResult.opsec.risk_level === "high" ? "orange" :
                  classifyResult.opsec.risk_level === "medium" ? "yellow" : "green"
                }
                variant="light"
              >
                <Text size="sm" fw={600}>{classifyResult.opsec.recommendation}</Text>
                {classifyResult.opsec.threats?.map((t: any, i: number) => (
                  <Text key={i} size="xs" c="dimmed" mt={2}>
                    ⚠ {t.description}
                  </Text>
                ))}
              </Alert>
            )}

            {classifyResult.online && (
              <SimpleGrid cols={2} spacing="xs">
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Status</Text>
                  <Text size="xs">{classifyResult.status}</Text>
                </Group>
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Body Size</Text>
                  <Text size="xs">{classifyResult.body_size} bytes</Text>
                </Group>
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Language</Text>
                  <Text size="xs">{classifyResult.language || "?"}</Text>
                </Group>
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Links</Text>
                  <Text size="xs">{classifyResult.links?.length || 0}</Text>
                </Group>
              </SimpleGrid>
            )}
          </Stack>
        )}
      </Card>

      {/* Info Alert */}
      <Alert icon={<IconMoon size={16} />} color="violet" variant="light">
        <Text size="sm">
          <strong>Darknet exploration is observation-only.</strong> PITBULL classifies services and
          detects honeypots/scams but does not interact with marketplaces or illegal services.
          OpSec analysis runs automatically on every .onion visit.
        </Text>
      </Alert>
    </Stack>
  );
}