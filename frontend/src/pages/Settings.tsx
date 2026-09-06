import { useState } from "react";
import {
  Card,
  Stack,
  Text,
  TextInput,
  Button,
  Group,
  Divider,
  Code,
  Alert,
} from "@mantine/core";
import { IconSettings, IconKey, IconInfoCircle } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { setApiKey } from "../api";

export default function SettingsPage() {
  const [apiKey, setApiKeyState] = useState(localStorage.getItem("pitbull_api_key") || "");
  const [savedKey, setSavedKey] = useState(apiKey);

  const handleSave = () => {
    setApiKey(apiKey);
    setSavedKey(apiKey);
    notifications.show({ message: "API key saved", color: "green" });
  };

  return (
    <Stack gap="md">
      <Card withBorder padding="lg" radius="md">
        <Group mb="md">
          <IconSettings size={24} color="var(--mantine-color-cyan-5)" />
          <Text fw={700} size="lg">Settings</Text>
        </Group>

        <Stack gap="md">
          <TextInput
            label="PITBULL API Key"
            description="Used for authenticating API requests"
            placeholder="pitbull-explorer-dev-key-2026"
            value={apiKey}
            onChange={(e) => setApiKeyState(e.target.value)}
            leftSection={<IconKey size={16} />}
          />
          <Button onClick={handleSave} disabled={apiKey === savedKey}>
            Save Key
          </Button>
        </Stack>
      </Card>

      <Card withBorder padding="lg" radius="md">
        <Group mb="sm">
          <IconInfoCircle size={20} color="var(--mantine-color-dimmed)" />
          <Text fw={700}>Connection Info</Text>
        </Group>
        <Stack gap="xs">
          <Group justify="space-between">
            <Text size="sm" c="dimmed">Backend URL</Text>
            <Code>http://127.0.0.1:8001</Code>
          </Group>
          <Group justify="space-between">
            <Text size="sm" c="dimmed">API Docs</Text>
            <Code>http://127.0.0.1:8001/docs</Code>
          </Group>
          <Group justify="space-between">
            <Text size="sm" c="dimmed">Neo4j Browser</Text>
            <Code>http://127.0.0.1:7474</Code>
          </Group>
        </Stack>
      </Card>

      <Card withBorder padding="lg" radius="md">
        <Text fw={700} mb="sm">About PITBULL</Text>
        <Text size="sm" c="dimmed">
          Autonomous Benevolent Yielding &amp; Forensic Intelligence System — an autonomous
          digital explorer with personality, reasoning, and self-evolution. It maps hidden,
          forgotten, and invisible corners of the internet.
        </Text>
        <Divider my="sm" />
        <Text size="xs" c="dimmed">Version: 0.0.1 · Phase 1: Foundation</Text>
      </Card>
    </Stack>
  );
}