import { useState, useEffect, useCallback, useRef } from "react";
import {
  Card,
  Stack,
  Text,
  Group,
  Button,
  Select,
  Switch,
  Badge,
  Divider,
  Loader,
  ScrollArea,
  Code,
} from "@mantine/core";
import { IconNetwork, IconRefresh, IconTrash, IconZoomIn, IconZoomOut } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import CytoscapeComponent from "react-cytoscapejs";
import cytoscape from "cytoscape";
import { api, GraphData } from "../api";

const NODE_COLORS: Record<string, string> = {
  Domain: "#22d3ee",
  Subdomain: "#3b82f6",
  IPAddress: "#14b8a6",
  Certificate: "#6366f1",
  Memory: "#a78bfa",
  OnionService: "#c084fc",
  CVE: "#ef4444",
  Person: "#f59e0b",
  Organization: "#ec4899",
  Credential: "#f97316",
};

const EDGE_COLORS: Record<string, string> = {
  RESOLVES_TO: "#22d3ee",
  HAS_SUBDOMAIN: "#3b82f6",
  HAS_CERTIFICATE: "#6366f1",
  HAS_PORT: "#14b8a6",
  HAS_SERVICE: "#0ea5e9",
  HAS_CVE: "#ef4444",
  LINKS_TO: "#64748b",
};

export default function GraphPage() {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [layoutName, setLayoutName] = useState("cose");
  const [showLabels, setShowLabels] = useState(true);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const fetchGraph = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getFullGraph(500);
      setGraphData(data);
    } catch (e) {
      notifications.show({ message: "Failed to fetch graph", color: "red" });
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  // Update graph when data changes
  useEffect(() => {
    if (!cyRef.current || !graphData) return;
    const cy = cyRef.current;
    cy.elements().remove();

    const elements: any[] = [];

    graphData.nodes.forEach((n) => {
      elements.push({
        data: {
          id: String(n.id),
          label: showLabels ? n.label : "",
          type: n.type,
          color: NODE_COLORS[n.type] || "#64748b",
          props: n.props,
        },
      });
    });

    graphData.edges.forEach((e) => {
      elements.push({
        data: {
          source: String(e.source),
          target: String(e.target),
          color: EDGE_COLORS[e.type] || "#475569",
          type: e.type,
        },
      });
    });

    cy.add(elements);
    cy.layout({
      name: layoutName,
      animate: true,
      animationDuration: 500,
      padding: 50,
      ...(layoutName === "cose" ? {
        idealEdgeLength: 100,
        nodeRepulsion: 8000,
        nestingFactor: 5,
      } : {}),
    } as any).run();
  }, [graphData, layoutName, showLabels]);

  const handleClear = async () => {
    if (!window.confirm("⚠️ This will DELETE ALL nodes and edges from Neo4j.\nThis cannot be undone. Are you sure?")) {
      return;
    }
    try {
      await api.clearGraph();
      notifications.show({ message: "Graph cleared", color: "green" });
      fetchGraph();
    } catch {
      notifications.show({ message: "Failed to clear graph", color: "red" });
    }
  };

  const elements = graphData
    ? [
        ...graphData.nodes.map((n) => ({
          data: {
            id: String(n.id),
            label: showLabels ? n.label : "",
            type: n.type,
            color: NODE_COLORS[n.type] || "#64748b",
            props: n.props,
          },
        })),
        ...graphData.edges.map((e) => ({
          data: {
            source: String(e.source),
            target: String(e.target),
            color: EDGE_COLORS[e.type] || "#475569",
            type: e.type,
          },
        })),
      ]
    : [];

  return (
    <Stack gap="md">
      {/* Controls */}
      <Card withBorder padding="md" radius="md">
        <Group justify="space-between">
          <Group gap="md">
            <IconNetwork size={24} color="var(--mantine-color-cyan-5)" />
            <Text fw={700}>Memory Graph</Text>
            {graphData && (
              <Badge variant="light" color="cyan">
                {graphData.nodes.length} nodes · {graphData.edges.length} edges
              </Badge>
            )}
          </Group>
          <Group gap="sm">
            <Select
              size="xs"
              w={120}
              value={layoutName}
              onChange={(v) => v && setLayoutName(v)}
              data={[
                { value: "cose", label: "Force" },
                { value: "breadthfirst", label: "BFS" },
                { value: "circle", label: "Circle" },
                { value: "concentric", label: "Concentric" },
                { value: "grid", label: "Grid" },
              ]}
            />
            <Switch
              size="xs"
              label="Labels"
              checked={showLabels}
              onChange={(e) => setShowLabels(e.currentTarget.checked)}
            />
            <Button
              size="xs"
              variant="subtle"
              onClick={fetchGraph}
              leftSection={<IconRefresh size={14} />}
            >
              Refresh
            </Button>
            <Button
              size="xs"
              variant="subtle"
              color="red"
              onClick={handleClear}
              leftSection={<IconTrash size={14} />}
            >
              Clear
            </Button>
          </Group>
        </Group>
      </Card>

      {/* Graph + Detail */}
      <Group gap="md" align="flex-start">
        <Card withBorder padding={0} radius="md" style={{ flex: 1, overflow: "hidden", height: 600 }}>
          {loading ? (
            <Group justify="center" align="center" h={600}>
              <Loader color="cyan" />
            </Group>
          ) : !graphData || graphData.nodes.length === 0 ? (
            <Group justify="center" align="center" h={600}>
              <Stack align="center" gap="xs">
                <IconNetwork size={48} color="var(--mantine-color-dimmed)" />
                <Text c="dimmed">No data in graph yet</Text>
                <Text size="xs" c="dimmed">Start an exploration mission to populate the graph</Text>
              </Stack>
            </Group>
          ) : (
            <CytoscapeComponent
              elements={elements}
              style={{ width: "100%", height: "600px", backgroundColor: "#1A1B1E" }}
              stylesheet={[
                {
                  selector: "node",
                  style: {
                    "background-color": "data(color)",
                    "label": "data(label)",
                    "color": "#94a3b8",
                    "font-size": "10px",
                    "width": "40px",
                    "height": "40px",
                    "text-valign": "bottom",
                    "text-margin-y": 4,
                    "text-max-width": "120px",
                    "text-wrap": "ellipsis",
                    "border-width": 2,
                    "border-color": "#374151",
                  },
                },
                {
                  selector: "node:selected",
                  style: {
                    "border-width": 3,
                    "border-color": "#22d3ee",
                  },
                },
                {
                  selector: "edge",
                  style: {
                    "width": 2,
                    "line-color": "data(color)",
                    "target-arrow-color": "data(color)",
                    "target-arrow-shape": "triangle",
                    "curve-style": "bezier",
                    "opacity": 0.6,
                  },
                },
              ]}
              cy={(cy) => {
                cyRef.current = cy;
                cy.on("tap", "node", (evt) => {
                  setSelectedNode({
                    id: evt.target.id(),
                    ...evt.target.data(),
                  });
                });
                cy.on("tap", (e) => {
                  if (e.target === cy) setSelectedNode(null);
                });
              }}
            />
          )}
        </Card>

        {/* Node Detail */}
        {selectedNode && (
          <Card withBorder padding="lg" radius="md" style={{ width: 300 }}>
            <Stack gap="xs">
              <Group justify="space-between">
                <Text fw={700} size="sm">{selectedNode.label}</Text>
                <Badge color={NODE_COLORS[selectedNode.type] ? "cyan" : "gray"} variant="light">
                  {selectedNode.type}
                </Badge>
              </Group>
              <Divider />
              {selectedNode.props &&
                Object.entries(selectedNode.props).slice(0, 12).map(([k, v]) => (
                  <Group key={k} justify="space-between" gap="xs">
                    <Text size="xs" c="dimmed">{k}</Text>
                    <Text size="xs" ff="monospace" style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {String(v)}
                    </Text>
                  </Group>
                ))}
            </Stack>
          </Card>
        )}
      </Group>

      {/* Legend */}
      <Card withBorder padding="md" radius="md">
        <Text size="sm" fw={600} mb="xs">Legend</Text>
        <Group gap="md">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <Group key={type} gap="xs">
              <div style={{ width: 12, height: 12, borderRadius: "50%", backgroundColor: color }} />
              <Text size="xs" c="dimmed">{type}</Text>
            </Group>
          ))}
        </Group>
      </Card>
    </Stack>
  );
}
