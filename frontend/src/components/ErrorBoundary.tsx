import { Component, ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("PITBULL ErrorBoundary caught:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "60vh",
          gap: "16px",
          color: "#e0e0e0",
          fontFamily: "monospace",
        }}>
          <div style={{ fontSize: "48px", opacity: 0.3 }}>⚠️</div>
          <div style={{ fontSize: "18px", fontWeight: 700, color: "#ff4444" }}>
            Page crashed — but PITBULL is still running
          </div>
          <div style={{
            fontSize: "12px",
            color: "#888",
            maxWidth: "600px",
            textAlign: "center",
            padding: "12px 16px",
            background: "rgba(255,0,0,0.05)",
            border: "1px solid rgba(255,0,0,0.15)",
            borderRadius: "8px",
            whiteSpace: "pre-wrap",
          }}>
            {this.state.error?.message || "Unknown error"}
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              background: "rgba(34,211,238,0.1)",
              border: "1px solid rgba(34,211,238,0.3)",
              color: "#22d3ee",
              padding: "8px 20px",
              borderRadius: "6px",
              cursor: "pointer",
              fontFamily: "monospace",
              fontSize: "13px",
            }}
          >
            ↻ Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}