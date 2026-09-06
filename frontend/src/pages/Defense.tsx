import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Group,
  Text,
  Button,
  Stack,
  Progress,
  Badge,
  Table,
  SimpleGrid,
  Code,
  Alert,
} from "@mantine/core";
import { api } from "../api";
import {
  IconDatabase,
  IconRefresh,
  IconBolt,
  IconShield,
  IconTrash,
  IconCpu,
} from "@tabler/icons-react";

interface RamZeroStatus {
  name: string;
  description: string;
  service_active: boolean;
  last_run: number | null;
  last_status: string | null;
  total_runs: number;
  total_freed_kb: number;
  current_memory: {
    total_kb: number;
    available_kb: number;
    free_kb: number;
    cached_kb: number;
    slab_kb: number;
    swap_total_kb: number;
    swap_free_kb: number;
  };
  history: Array<{
    timestamp: number;
    status: string;
    detail: string;
    freed_kb: number;
  }>;
}

interface RamPoisonStatus {
  name: string;
  description: string;
  service_active: boolean;
  running: boolean;
  target_mb: number;
  total_decoys: number;
  total_gb: number;
  mem_usage_mb: number;
  cycles: number;
  blocks_held: number;
  started_at: string | null;
  last_cycle: string | null;
  decoy_types: Record<string, number>;
  academic_basis: string[];
}

interface MeTelemetryStatus {
  name: string;
  description: string;
  available: boolean;
  error?: string;
  regions_total: number;
  regions_decoded: number;
  rails: Array<{ rail: string; voltage: number; current: number; freq: number; raw_power: number }>;
  cpu: { vid: number; amps_max: number } | null;
  cores: Record<string, number>;
  timestamp: string;
}

interface DmaStatus {
  name: string;
  iommu_mode: string;
  internal_wifi: {
    interface: string;
    carrier: string;
    driver_bound: boolean;
    status: string;
  };
  usb_wifi: {
    interface: string;
    driver: string;
    status: string;
  };
}

interface MacSyncStatus {
  name: string;
  current_mac: string;
  projected_mac: string | null;
  synced: boolean;
  interface: string;
}

function fmtKB(kb: number): string {
  if (kb >= 1048576) return (kb / 1048576).toFixed(2) + " GB";
  if (kb >= 1024) return (kb / 1024).toFixed(1) + " MB";
  return kb + " KB";
}

function fmtTime(ts: number | null): string {
  if (!ts) return "Never";
  return new Date(ts * 1000).toLocaleString();
}

export default function DefensePage() {
  const [ramZero, setRamZero] = useState<RamZeroStatus | null>(null);
  const [ramPoison, setRamPoison] = useState<RamPoisonStatus | null>(null);
  const [dma, setDma] = useState<DmaStatus | null>(null);
  const [macSync, setMacSync] = useState<MacSyncStatus | null>(null);
  const [meTelem, setMeTelem] = useState<MeTelemetryStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [triggering, setTriggering] = useState(false);

  const fetchAll = useCallback(async () => {
    try {
      const [rz, rp, dm, ms, mt] = await Promise.all([
        api.get("/defense/ram-zero/status"),
        api.get("/defense/ram-poison/status"),
        api.get("/defense/dma-protection/status"),
        api.get("/defense/mac-sync/status"),
        api.get("/defense/me-telemetry/status"),
      ]);
      setRamZero(rz as RamZeroStatus);
      setRamPoison(rp as RamPoisonStatus);
      setDma(dm as DmaStatus);
      setMacSync(ms as MacSyncStatus);
      setMeTelem(mt as MeTelemetryStatus);
    } catch (e) {
      console.error("Defense fetch error:", e);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const triggerFlush = async () => {
    setTriggering(true);
    try {
      await api.post("/defense/ram-zero/trigger");
      await fetchAll();
    } catch (e) {
      console.error("Trigger error:", e);
    }
    setTriggering(false);
  };

  const memUsedPct = ramZero
    ? ((ramZero.current_memory.total_kb - ramZero.current_memory.available_kb) /
        ramZero.current_memory.total_kb) *
      100
    : 0;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="xl" fw={700} style={{ color: "#f85149" }}>
          🛡️ Defense Operations
        </Text>
        <Button
          leftSection={<IconRefresh size={16} />}
          variant="light"
          onClick={fetchAll}
          loading={loading}
        >
          Refresh
        </Button>
      </Group>

      {/* RAM Zero */}
      <Card withBorder shadow="sm" radius="md" style={{ borderColor: "#30363d", backgroundColor: "#161b22" }}>
        <Group justify="space-between" mb="md">
          <Group gap="sm">
            <IconDatabase size={24} color="#f85149" />
            <Text size="lg" fw={600} style={{ color: "#e6edf3" }}>
              RAM Zero — Memory Hygiene
            </Text>
          </Group>
          <Group gap="sm">
            <Badge color={ramZero?.service_active ? "green" : "red"} variant="light">
              {ramZero?.service_active ? "● Active" : "● Inactive"}
            </Badge>
            <Button
              leftSection={<IconBolt size={16} />}
              color="red"
              variant="light"
              onClick={triggerFlush}
              loading={triggering}
            >
              Flush Now
            </Button>
          </Group>
        </Group>

        <Text  c="dimmed" mb="md">
          {ramZero?.description || "Memory hygiene flush — reduces DMA extraction window"}
        </Text>

        {/* Memory bar */}
        {ramZero && (
          <div style={{ marginBottom: 16 }}>
            <Group justify="space-between" mb={4}>
              <Text size="xs" c="dimmed">Memory Usage</Text>
              <Text size="xs" c="dimmed">
                {fmtKB(ramZero.current_memory.total_kb - ramZero.current_memory.available_kb)} / {fmtKB(ramZero.current_memory.total_kb)}
              </Text>
            </Group>
            <Progress
              value={memUsedPct}
              color={memUsedPct > 80 ? "red" : memUsedPct > 60 ? "orange" : "green"}
              size="lg"
              radius="sm"
            />
          </div>
        )}

        {/* Memory stats grid */}
        {ramZero && (
          <SimpleGrid cols={4} spacing="sm" mb="md">
            <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
              <Text size="xs" c="dimmed">Available</Text>
              <Text size="lg" fw={700} c="green">{fmtKB(ramZero.current_memory.available_kb)}</Text>
            </Card>
            <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
              <Text size="xs" c="dimmed">Cached</Text>
              <Text size="lg" fw={700} c="cyan">{fmtKB(ramZero.current_memory.cached_kb)}</Text>
            </Card>
            <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
              <Text size="xs" c="dimmed">Slab</Text>
              <Text size="lg" fw={700} c="orange">{fmtKB(ramZero.current_memory.slab_kb)}</Text>
            </Card>
            <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
              <Text size="xs" c="dimmed">Swap Free</Text>
              <Text size="lg" fw={700} c="grape">{fmtKB(ramZero.current_memory.swap_free_kb)}</Text>
            </Card>
          </SimpleGrid>
        )}

        {/* Run stats */}
        <Group gap="md" mb="md">
          <Text >Total runs: <b>{ramZero?.total_runs || 0}</b></Text>
          <Text >Total freed: <b>{ramZero ? fmtKB(ramZero.total_freed_kb) : "0 KB"}</b></Text>
          <Text >Last run: <b>{ramZero ? fmtTime(ramZero.last_run) : "Never"}</b></Text>
        </Group>

        {/* History */}
        {ramZero && ramZero.history.length > 0 && (
          <div>
            <Text  fw={600} mb="xs">Recent Flush History</Text>
            <Table striped highlightOnHover >
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Time</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Detail</Table.Th>
                  <Table.Th>Freed</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {ramZero.history.slice(-10).reverse().map((h, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>{fmtTime(h.timestamp)}</Table.Td>
                    <Table.Td>
                      <Badge color={h.status === "ok" ? "green" : "red"} variant="light" >
                        {h.status}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{h.detail}</Table.Td>
                    <Table.Td>{fmtKB(h.freed_kb)}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
        )}
      </Card>

      {/* RAM Poison */}
      <Card withBorder shadow="sm" radius="md" style={{ borderColor: "#30363d", backgroundColor: "#161b22" }}>
        <Group justify="space-between" mb="md">
          <Group gap="sm">
            <IconDatabase size={24} color="#f85149" />
            <Text size="lg" fw={600} style={{ color: "#e6edf3" }}>
              RAM Poison — Anti-Forensic Decoy Injector
            </Text>
          </Group>
          <Badge color={ramPoison?.service_active ? "green" : "red"} variant="light">
            {ramPoison?.service_active ? "● Active" : "● Inactive"}
          </Badge>
        </Group>

        <Text size="sm" c="dimmed" mb="md">
          {ramPoison?.description || "Fills RAM with fake keys, passwords, tokens to pollute DMA extraction"}
        </Text>

        {ramPoison && ramPoison.running && (
          <div style={{ marginBottom: 16 }}>
            <Group justify="space-between" mb={4}>
              <Text size="xs" c="dimmed">Decoys in RAM</Text>
              <Text size="xs" c="dimmed">{ramPoison.mem_usage_mb}MB / {ramPoison.target_mb}MB</Text>
            </Group>
            <Progress
              value={(ramPoison.mem_usage_mb / ramPoison.target_mb) * 100}
              color="red"
              size="lg"
              radius="sm"
            />
          </div>
        )}

        {ramPoison && (
          <>
            <SimpleGrid cols={4} spacing="sm" mb="md">
              <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
                <Text size="xs" c="dimmed">Total Decoys</Text>
                <Text size="lg" fw={700} c="red">{ramPoison.total_decoys.toLocaleString()}</Text>
              </Card>
              <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
                <Text size="xs" c="dimmed">Memory Held</Text>
                <Text size="lg" fw={700} c="orange">{ramPoison.mem_usage_mb}MB</Text>
              </Card>
              <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
                <Text size="xs" c="dimmed">Cycles</Text>
                <Text size="lg" fw={700} c="cyan">{ramPoison.cycles}</Text>
              </Card>
              <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
                <Text size="xs" c="dimmed">Blocks</Text>
                <Text size="lg" fw={700} c="grape">{ramPoison.blocks_held.toLocaleString()}</Text>
              </Card>
            </SimpleGrid>

            {Object.keys(ramPoison.decoy_types).length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <Text size="sm" fw={600} mb="xs">Decoy Types Injected</Text>
                <Table striped highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Type</Table.Th>
                      <Table.Th>Count</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {Object.entries(ramPoison.decoy_types)
                      .sort(([,a],[,b]) => b - a)
                      .map(([type, count]) => (
                        <Table.Tr key={type}>
                          <Table.Td><Badge variant="light" color="red">{type}</Badge></Table.Td>
                          <Table.Td>{count.toLocaleString()}</Table.Td>
                        </Table.Tr>
                      ))}
                  </Table.Tbody>
                </Table>
              </div>
            )}

            <Alert color="blue" variant="light" title="Academic Basis" mb="sm">
              {ramPoison.academic_basis.map((a, i) => (
                <Text key={i} size="xs" style={{ marginBottom: 4 }}>• {a}</Text>
              ))}
            </Alert>

            <Text size="xs" c="dimmed">
              Last cycle: {ramPoison.last_cycle ? new Date(ramPoison.last_cycle).toLocaleString() : "Never"} |
              Started: {ramPoison.started_at ? new Date(ramPoison.started_at).toLocaleString() : "Unknown"}
            </Text>
          </>
        )}
      </Card>

      {/* ME PMT Telemetry — Ring -3 → Ring 0 bridge */}
      <Card withBorder shadow="sm" radius="md" style={{ borderColor: "#30363d", backgroundColor: "#161b22" }}>
        <Group justify="space-between" mb="md">
          <Group gap="sm">
            <IconCpu size={24} color="#8b5cf6" />
            <Text size="lg" fw={600} style={{ color: "#e6edf3" }}>
              ME PMT Telemetry — Ring -3 Sensor Bridge
            </Text>
          </Group>
          <Badge color={meTelem?.available ? "green" : "red"} variant="light">
            {meTelem?.available ? "● Live" : "● Offline"}
          </Badge>
        </Group>

        <Text size="sm" c="dimmed" mb="md">
          {meTelem?.description || "Intel ME/PMC platform telemetry harvested below the OS"}
        </Text>

        {meTelem && meTelem.available ? (
          <>
            <SimpleGrid cols={3} spacing="sm" mb="md">
              <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
                <Text size="xs" c="dimmed">Decoded Regions</Text>
                <Text size="lg" fw={700} c="violet">{meTelem.regions_decoded} / {meTelem.regions_total}</Text>
              </Card>
              <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
                <Text size="xs" c="dimmed">Active Rails</Text>
                <Text size="lg" fw={700} c="teal">{meTelem.rails.filter(r => r.voltage > 0 || r.current > 0).length}</Text>
              </Card>
              <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
                <Text size="xs" c="dimmed">CPU VID / Max A</Text>
                <Text size="lg" fw={700} c="orange">{meTelem.cpu ? `${meTelem.cpu.vid} · ${(meTelem.cpu.amps_max/1000).toFixed(1)}A` : "—"}</Text>
              </Card>
            </SimpleGrid>

            {meTelem.rails.length > 0 && (
              <Table striped highlightOnHover mb="md">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Rail</Table.Th>
                    <Table.Th>Voltage</Table.Th>
                    <Table.Th>Current</Table.Th>
                    <Table.Th>Freq</Table.Th>
                    <Table.Th>V×I</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {meTelem.rails.map((r) => (
                    <Table.Tr key={r.rail}>
                      <Table.Td><Badge variant="light" color={(r.voltage > 0 || r.current > 0) ? "teal" : "gray"}>{r.rail}</Badge></Table.Td>
                      <Table.Td>{r.voltage}</Table.Td>
                      <Table.Td>{r.current}</Table.Td>
                      <Table.Td>{r.freq}</Table.Td>
                      <Table.Td>{r.raw_power.toLocaleString()}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}

            <Text size="xs" c="dimmed">
              Below-OS sensor feed — rootkits can't fake these values · Last: {meTelem.timestamp ? new Date(meTelem.timestamp).toLocaleTimeString() : "—"}
            </Text>
          </>
        ) : (
          <Text size="xs" c="dimmed">{meTelem?.error || "PMT regions not accessible (need root backend)"}</Text>
        )}
      </Card>

      {/* DMA Protection */}
      <Card withBorder shadow="sm" radius="md" style={{ borderColor: "#30363d", backgroundColor: "#161b22" }}>
        <Group gap="sm" mb="md">
          <IconShield size={24} color="#34d399" />
          <Text size="lg" fw={600} style={{ color: "#e6edf3" }}>
            ME DMA Protection
          </Text>
        </Group>

        {dma && (
          <SimpleGrid cols={3} spacing="sm">
            <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
              <Text size="xs" c="dimmed">IOMMU Mode</Text>
              <Text size="md" fw={700} c={dma.iommu_mode === "identity" ? "green" : "orange"}>
                {dma.iommu_mode}
              </Text>
            </Card>
            <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
              <Text size="xs" c="dimmed">Internal WiFi</Text>
              <Text size="md" fw={700} c={dma.internal_wifi.carrier === "0" ? "green" : "red"}>
                {dma.internal_wifi.status}
              </Text>
              <Text size="xs" c="dimmed">Driver: {dma.internal_wifi.driver_bound ? "bound ⚠️" : "unbound ✅"}</Text>
            </Card>
            <Card withBorder p="sm" style={{ backgroundColor: "#0d1117" }}>
              <Text size="xs" c="dimmed">USB WiFi (ME-free)</Text>
              <Text size="md" fw={700} c="green">{dma.usb_wifi.status}</Text>
              <Text size="xs" c="dimmed">{dma.usb_wifi.interface} / {dma.usb_wifi.driver}</Text>
            </Card>
          </SimpleGrid>
        )}
      </Card>

      {/* MAC Sync */}
      <Card withBorder shadow="sm" radius="md" style={{ borderColor: "#30363d", backgroundColor: "#161b22" }}>
        <Group gap="sm" mb="md">
          <IconTrash size={24} color="#58a6ff" />
          <Text size="lg" fw={600} style={{ color: "#e6edf3" }}>
            MAC Sync — adapter ↔ identity
          </Text>
          {macSync && (
            <Badge color={macSync.synced ? "green" : "orange"} variant="light">
              {macSync.synced ? "● Synced" : "● Out of sync"}
            </Badge>
          )}
        </Group>

        {macSync && (
          <Group gap="md">
            <Text >Current MAC: <Code>{macSync.current_mac}</Code></Text>
            <Text >Projected MAC: <Code>{macSync.projected_mac || "unknown"}</Code></Text>
            <Text  c="dimmed">Interface: {macSync.interface}</Text>
          </Group>
        )}
      </Card>

      {/* Threat model note */}
      <Alert color="red" variant="light" title="Threat Model">
        RAM Zero reduces the window of exposure for DMA-based memory extraction (Intel ME, cold boot attacks).
        It cannot fully stop ME's hardware DMA — no software can. Instead it limits sensitive data accumulation
        in RAM to ~30 minute windows. Combined with IOMMU strict mode, internal WiFi isolation, and MAC sync,
        this creates a hardened defense-in-depth posture against Ring -3 adversaries.
      </Alert>
    </Stack>
  );
}