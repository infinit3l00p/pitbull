import { useState, useEffect, useCallback, useRef } from "react";
import {
  Card,
  Stack,
  Text,
  TextInput,
  Button,
  ScrollArea,
  Avatar,
  Badge,
  Divider,
  Loader,
  Group,
} from "@mantine/core";
import { IconAtom, IconSend, IconUser } from "@tabler/icons-react";
import { api } from "../api";

interface ChatMessage {
  id: string;
  role: string;
  content: string;
  timestamp: string;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  const loadHistory = useCallback(async () => {
    try {
      const data = await api.getChatHistory(100);
      setMessages(data.messages || []);
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || sending) return;
    const userMsg: ChatMessage = { id: "temp-user", role: "user", content: input, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);
    setSending(true);
    const currentInput = input;
    setInput("");
    try {
      const result = await api.chat(currentInput);
      setMessages((prev) => [...prev, { id: result.id || "bot", role: "assistant", content: result.reply || "Error", timestamp: result.timestamp || new Date().toISOString() }]);
    } catch {
      setMessages((prev) => [...prev, { id: "err", role: "assistant", content: "Connection error — is the backend running?", timestamp: new Date().toISOString() }]);
    }
    setSending(false);
  };

  return (
    <Stack gap="md" h="100%" className="pitbull-fade-in">
      <Card withBorder padding="lg" radius="md" className="pitbull-stat-card" style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <Group mb="md" justify="space-between">
          <Group gap="sm">
            <div style={{ position: "relative" }}>
              <IconAtom size={28} style={{ color: "var(--pitbull-cyan)", filter: "drop-shadow(0 0 12px var(--pitbull-cyan-glow))" }} />
              <span className="pitbull-pulse-dot" style={{ color: "var(--pitbull-green)", position: "absolute", top: 0, right: 0 }} />
            </div>
            <div>
              <Text fw={700} size="lg" className="pitbull-display" c="cyan.3">CHAT WITH PITBULL</Text>
              <Text size="xs" c="dimmed" className="pitbull-mono">Autonomous digital explorer · v0.6.0</Text>
            </div>
          </Group>
          <Badge variant="light" color="cyan" className="pitbull-display">ONLINE</Badge>
        </Group>
        <div className="pitbull-divider" />

        <ScrollArea.Autosize mah="calc(100vh - 340px)" viewportRef={scrollRef}>
          <Stack gap="md">
            {loading && <Group justify="center"><Loader color="cyan" /></Group>}
            {messages.length === 0 && !loading && (
              <Stack align="center" justify="center" py="xl" gap="sm">
                <IconAtom size={48} style={{ color: "var(--pitbull-text-dim)", opacity: 0.3 }} />
                <Text c="dimmed" size="sm">Start a conversation with PITBULL</Text>
                <Text size="xs" c="dimmed" style={{ opacity: 0.6 }}>Ask about its explorations, findings, or opinions</Text>
              </Stack>
            )}
            {messages.map((msg, i) => (
              <Group key={i} gap="sm" align="flex-start" justify={msg.role === "user" ? "flex-end" : "flex-start"}>
                {msg.role === "assistant" && (
                  <Avatar style={{ background: "rgba(34,211,238,0.15)", border: "1px solid var(--pitbull-border-bright)", boxShadow: "0 0 12px var(--pitbull-cyan-glow)" }} size="sm" radius="xl">
                    <IconAtom size={16} style={{ color: "var(--pitbull-cyan)" }} />
                  </Avatar>
                )}
                <div style={{
                  maxWidth: "75%",
                  padding: "12px 16px",
                  borderRadius: msg.role === "user" ? "16px 16px 4px 16px" : "16px 16px 16px 4px",
                  background: msg.role === "user" ? "rgba(34,211,238,0.12)" : "rgba(15,20,25,0.6)",
                  border: "1px solid var(--pitbull-border)",
                  backdropFilter: "blur(8px)",
                }}>
                  <Text size="sm" style={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: msg.role === "assistant" ? "var(--pitbull-text-bright)" : "var(--pitbull-text)" }}>{msg.content}</Text>
                  <Text size="xs" c="dimmed" mt={4} className="pitbull-mono" style={{ opacity: 0.5 }}>{msg.timestamp?.slice(11, 19)}</Text>
                </div>
                {msg.role === "user" && (
                  <Avatar color="gray" variant="light" size="sm" radius="xl"><IconUser size={16} /></Avatar>
                )}
              </Group>
            ))}
            {sending && (
              <Group gap="sm" align="flex-start">
                <Avatar style={{ background: "rgba(34,211,238,0.15)", border: "1px solid var(--pitbull-border-bright)" }} size="sm" radius="xl"><IconAtom size={16} style={{ color: "var(--pitbull-cyan)" }} /></Avatar>
                <div style={{ padding: "12px 16px", borderRadius: "16px 16px 16px 4px", background: "rgba(15,20,25,0.6)", border: "1px solid var(--pitbull-border)" }}>
                  <Group gap="xs"><span className="pitbull-pulse-dot" style={{ color: "var(--pitbull-cyan)" }} /><span className="pitbull-pulse-dot" style={{ color: "var(--pitbull-cyan)", animationDelay: "0.3s" }} /><span className="pitbull-pulse-dot" style={{ color: "var(--pitbull-cyan)", animationDelay: "0.6s" }} /></Group>
                </div>
              </Group>
            )}
          </Stack>
        </ScrollArea.Autosize>
      </Card>

      <Group gap="sm">
        <TextInput
          placeholder="Ask PITBULL anything..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          style={{ flex: 1 }}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          disabled={sending}
          className="pitbull-mono"
          styles={{ input: { background: "rgba(15,20,25,0.6)", border: "1px solid var(--pitbull-border)", color: "var(--pitbull-text)", fontSize: "14px" } }}
        />
        <Button onClick={handleSend} loading={sending} leftSection={<IconSend size={16} />} size="md" radius="md" className="pitbull-display">
          SEND
        </Button>
      </Group>
    </Stack>
  );
}