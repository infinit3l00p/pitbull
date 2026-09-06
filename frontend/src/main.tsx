import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MantineProvider, createTheme } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "./pitbull.css";
import App from "./App";

const theme = createTheme({
  primaryColor: "cyan",
  primaryShade: { light: 5, dark: 5 },
  fontFamily: "Inter, system-ui, -apple-system, sans-serif",
  headings: { fontFamily: "Orbitron, Inter, sans-serif", fontWeight: "700" },
  colors: {
    dark: [
      "#C1C2C5", "#a6a7ab", "#909296", "#5c5f66", "#373A40",
      "#2C2E33", "#25262b", "#1A1B1E", "#141517", "#0a0e14",
    ],
  },
  defaultRadius: "md",
  components: {
    Card: {
      defaultProps: {
        bg: "transparent",
        withBorder: true,
      },
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <Notifications />
      <App />
    </MantineProvider>
  </StrictMode>
);