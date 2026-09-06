import { useState, useEffect, useCallback, lazy, Suspense } from "react";
import {
  AppShell,
  Burger,
  Group,
  Text,
  NavLink,
  Badge,
  Stack,
  ScrollArea,
  Box,
  Tooltip,
} from "@mantine/core";
import {
  IconHome2,
  IconRadar,
  IconNetwork,
  IconBrain,
  IconSettings,
  IconHistory,
  IconMoon,
  IconAtom,
  IconMessage2,
  IconCrosshair,
  IconActivity,
} from "@tabler/icons-react";
import { useDisclosure } from "@mantine/hooks";
import { api, HealthResponse } from "./api";

// ── Lazy-loaded pages (code splitting) ─────────────────────────────
const OverviewPage = lazy(() => import("./pages/Overview"));
const ExplorePage = lazy(() => import("./pages/Explore"));
const GraphPage = lazy(() => import("./pages/Graph"));
const MindStreamPage = lazy(() => import("./pages/MindStream"));
const ForensicPage = lazy(() => import("./pages/Forensic"));
const DarknetPage = lazy(() => import("./pages/Darknet"));
const EvolutionPage = lazy(() => import("./pages/Evolution"));
const ChatPage = lazy(() => import("./pages/Chat"));
const SettingsPage = lazy(() => import("./pages/Settings"));
const ExploitPage = lazy(() => import("./pages/Exploit"));
const AntiForensicsPage = lazy(() => import("./pages/AntiForensics"));
const SentinelPage = lazy(() => import("./pages/Sentinel"));
const ResponsePage = lazy(() => import("./pages/Response"));
const LabyrinthPage = lazy(() => import("./pages/Labyrinth"));
const TrapCardPage = lazy(() => import("./pages/TrapCard"));
const BrainMazePage = lazy(() => import("./pages/BrainMaze"));
const CerberusPage = lazy(() => import("./pages/Cerberus"));
const ConferenceWatcherPage = lazy(() => import("./pages/ConferenceWatcher"));
const NtopngPage = lazy(() => import("./pages/Ntopng"));
const SuricataPage = lazy(() => import("./pages/Suricata"));
const DefensePage = lazy(() => import("./pages/Defense"));

// Loading fallback
const PageLoader = () => (
  <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "50vh" }}>
    <Text size="lg" c="cyan.4" className="pitbull-display">Loading...</Text>
  </div>
);

import { IconGhost, IconShield, IconFlame, IconMicroscope, IconCalendar, IconBolt, IconDatabase } from "@tabler/icons-react";
import { ErrorBoundary } from "./components/ErrorBoundary";

type Page = "overview" | "explore" | "graph" | "mind" | "forensic" | "darknet" | "evolution" | "chat" | "settings" | "exploit" | "antiforensics" | "sentinel" | "response" | "labyrinth" | "trapcard" | "brainmaze" | "cerberus" | "conferences" | "ntopng" | "suricata" | "defense";

const NAV_SECTIONS: { section: string; items: { id: Page; label: string; icon: typeof IconHome2; desc: string }[] }[] = [
  {
    section: "INTELLIGENCE",
    items: [
      { id: "overview", label: "Overview", icon: IconHome2, desc: "System status & stats" },
      { id: "explore", label: "Explore", icon: IconRadar, desc: "Launch exploration missions" },
      { id: "graph", label: "Memory Graph", icon: IconNetwork, desc: "Neo4j graph visualization" },
      { id: "mind", label: "Mind Stream", icon: IconBrain, desc: "Memories, opinions & evolution" },
    ],
  },
  {
    section: "FORENSICS",
    items: [
      { id: "forensic", label: "Forensic", icon: IconHistory, desc: "Timeline & genealogy" },
      { id: "darknet", label: "Darknet", icon: IconMoon, desc: "Tor, .onion & I2P" },
    ],
  },
  {
    section: "EVOLUTION",
    items: [
      { id: "evolution", label: "Evolution", icon: IconAtom, desc: "Mistakes, patterns & drift" },
      { id: "chat", label: "Chat", icon: IconMessage2, desc: "Talk to PITBULL" },
      { id: "exploit", label: "Exploit", icon: IconCrosshair, desc: "Armitage-style attack console" },
      { id: "antiforensics", label: "Anti-Forensics", icon: IconGhost, desc: "Trace wiping & ghost mode" },
      { id: "settings", label: "Settings", icon: IconSettings, desc: "Configuration" },
    ],
  },
  {
    section: "DEFENSE",
    items: [
      { id: "defense", label: "RAM Zero", icon: IconDatabase, desc: "Memory hygiene, DMA protection & MAC sync" },
      { id: "sentinel", label: "Sentinel", icon: IconShield, desc: "Real-time attack detection" },
      { id: "ntopng", label: "Network Traffic", icon: IconActivity, desc: "Live ntopng flow & alert data" },
      { id: "suricata", label: "IDS / IPS", icon: IconShield, desc: "Suricata intrusion detection & prevention" },
      { id: "response", label: "Response", icon: IconBolt, desc: "Graduated threat response engine" },
      { id: "labyrinth", label: "Labyrinth", icon: IconGhost, desc: "Deception & cognitive warfare" },
    ],
  },
  {
    section: "PHASE 8",
    items: [
      { id: "trapcard", label: "TrapCard", icon: IconFlame, desc: "Attacker tool capture" },
      { id: "brainmaze", label: "BrainMaze", icon: IconGhost, desc: "Cognitive confusion engine" },
      { id: "cerberus", label: "Cerberus", icon: IconMicroscope, desc: "Zero-day discovery" },
      { id: "conferences", label: "Conferences", icon: IconCalendar, desc: "Asian hacking conferences" },
    ],
  },
];

export default function App() {
  const [opened, { toggle }] = useDisclosure();
  const [page, setPage] = useState<Page>("overview");
  const [health, setHealth] = useState<HealthResponse | null>(null);

  const checkHealth = useCallback(async () => {
    try {
      const h = await api.health();
      setHealth(h);
    } catch {
      setHealth(null);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  const isHealthy = health?.status === "healthy";

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{ width: 260, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding="xl"
    >
      <AppShell.Header>
        <Group h="100%" px="lg" justify="space-between">
          <Group gap="md">
            <Burger opened={opened} onClick={toggle} size="sm" hiddenFrom="sm" />
            <Group gap="sm" style={{ position: "relative" }}>
              <img
                src="/pitbull-head.svg"
                alt="Pitbull"
                width={42}
                height={42}
                style={{
                  position: "absolute",
                  left: "-6px",
                  top: "-6px",
                  opacity: 0.35,
                  filter: "drop-shadow(0 0 8px rgba(34,211,238,0.5))",
                  pointerEvents: "none",
                  zIndex: 0,
                }}
              />
              <Text
                size="xl"
                fw={900}
                className="pitbull-display"
                c="cyan.4"
                style={{
                  textShadow: "0 0 20px rgba(34,211,238,0.4)",
                  position: "relative",
                  zIndex: 1,
                  paddingLeft: "4px",
                }}
              >
                PITBULL
              </Text>
              <Badge size="xs" variant="dot" color={isHealthy ? "green" : "orange"}
                styles={{ root: { background: "transparent", border: "1px solid rgba(52,211,153,0.3)" } }}
              >
                {isHealthy ? "ONLINE" : "CONNECTING"}
              </Badge>
            </Group>
          </Group>
          <Group gap="md" visibleFrom="sm">
            <Group gap="xs">
              <span className="pitbull-pulse-dot" style={{ color: isHealthy ? "var(--pitbull-green)" : "var(--pitbull-amber)" }} />
              <Text size="xs" c="dimmed" className="pitbull-mono">
                {health?.neo4j.connected ? "NEO4J ✓" : "NEO4J ✗"} · v{health?.version || "0.0.0"}
              </Text>
            </Group>
            <Text size="xs" c="dimmed" className="pitbull-display" style={{ letterSpacing: "0.1em", opacity: 0.5 }}>
              AUTONOMOUS FORENSIC INTELLIGENCE
            </Text>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="md">
        <ScrollArea h="100%">
          <Stack gap="xl">
            {NAV_SECTIONS.map((section) => (
              <Stack gap="xs" key={section.section}>
                <Text size="xs" fw={700} c="cyan.6" className="pitbull-display" pl="sm" style={{ opacity: 0.6, letterSpacing: "0.15em" }}>
                  {section.section}
                </Text>
                <Stack gap="xs">
                  {section.items.map((item) => (
                    <NavLink
                      key={item.id}
                      active={page === item.id}
                      onClick={() => {
                        setPage(item.id);
                        if (opened) toggle();
                      }}
                      label={
                        <Group justify="space-between" align="center">
                          <Text size="sm" fw={page === item.id ? 600 : 400}>{item.label}</Text>
                        </Group>
                      }
                      description={<Text size="xs" c="dimmed" style={{ opacity: 0.6 }}>{item.desc}</Text>}
                      leftSection={<item.icon size={18} />}
                      color="cyan"
                      variant="light"
                    />
                  ))}
                </Stack>
              </Stack>
            ))}

            {/* Bottom status */}
            <Box mt="auto" p="sm" style={{ borderTop: "1px solid var(--pitbull-border)" }}>
              <Group gap="xs" justify="center">
                <span className="pitbull-pulse-dot" style={{ color: "var(--pitbull-green)" }} />
                <Text size="xs" c="dimmed" className="pitbull-mono">SYSTEM ACTIVE</Text>
              </Group>
            </Box>
          </Stack>
        </ScrollArea>
      </AppShell.Navbar>

      <AppShell.Main className="pitbull-fade-in">
        <ErrorBoundary key={page}>
        <Suspense fallback={<PageLoader />}>
        {page === "overview" && <OverviewPage health={health} onNavigate={setPage} />}
        {page === "explore" && <ExplorePage />}
        {page === "graph" && <GraphPage />}
        {page === "mind" && <MindStreamPage />}
        {page === "forensic" && <ForensicPage />}
        {page === "darknet" && <DarknetPage />}
        {page === "evolution" && <EvolutionPage />}
        {page === "chat" && <ChatPage />}
        {page === "settings" && <SettingsPage />}
        {page === "exploit" && <ExploitPage />}
       {page === "antiforensics" && <AntiForensicsPage />}
       {page === "sentinel" && <SentinelPage />}
       {page === "response" && <ResponsePage />}
       {page === "labyrinth" && <LabyrinthPage />}
       {page === "trapcard" && <TrapCardPage />}
       {page === "brainmaze" && <BrainMazePage />}
       {page === "cerberus" && <CerberusPage />}
       {page === "conferences" && <ConferenceWatcherPage />}
       {page === "ntopng" && <NtopngPage />}
       {page === "suricata" && <SuricataPage />}
      {page === "defense" && <DefensePage />}
        </Suspense>
        </ErrorBoundary>
     </AppShell.Main>
    </AppShell>
  );
}
