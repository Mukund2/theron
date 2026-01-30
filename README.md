# Theron

Security proxy for agentic AI systems. Detects prompt injection, sandboxes dangerous actions, and learns agent behavior - all without modifying your AI agent's code.

## The Problem

AI agents (Claude Code, AutoGPT, Moltbot) can execute shell commands, send emails, and access files. When they process untrusted content (emails, web pages, documents), prompt injection attacks can hijack them into executing malicious commands.

**Theron's principle:** Content the AI reads should never have the same privilege level as commands the user issues.

## Features

### Core Security
- **Prompt Injection Detection** - 50+ patterns detecting instruction overrides, role injection, delimiter attacks, exfiltration attempts
- **4-Tier Risk Classification** - Tools classified from Safe (read_file) to Critical (sudo, transfer_funds)
- **Source-Based Gating** - Actions allowed/blocked based on trust level of input content
- **Docker Sandboxing** - Dangerous commands run in isolated containers with no network, read-only FS, memory limits

### Intelligence Layer
- **Causal Chain Tracking** - Trace how untrusted content leads to dangerous actions
- **Exfiltration Detection** - Detect sensitive data (credentials, keys, PII) flowing to outbound tools
- **Hijack Detection** - Detect when agent tasks drift from original user intent
- **Honeypot Injection** - Seed fake credentials, detect if agent uses them (indicates compromise)
- **Taint Tracking** - Track which knowledge came from untrusted sources

### Learning & Autonomy
- **Behavioral Baseline** - Learn normal patterns per agent, flag anomalies with zero config
- **Task-Scoped Permissions** - Dynamically restrict tools based on inferred task (coding vs email)
- **Shadow Execution** - Run actions in isolation, auto-commit/discard based on behavior analysis
- **Graceful Degradation** - Automatically reduce agent autonomy when threats detected

### Agent Management
- **Agent Registry** - Modular agent definitions with risk levels and capabilities
- **Guided Installation** - Safe onboarding with warnings and automatic Theron configuration
- **Protected Runner** - Launch any agent with Theron protection via `theron run`

## Installation

**One command. That's it.**

```bash
curl -fsSL https://get.theron.dev | sh
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
irm https://get.theron.dev/install.ps1 | iex
```
</details>

<details>
<summary>Manual installation</summary>

If you prefer to install manually:
```bash
pip install theron
theron setup
```
</details>

Restart your terminal. **Done.** All your AI agents are now protected.

## What Happens

After `theron setup`:
- Theron starts automatically when you log in
- All AI agents that use Anthropic or OpenAI APIs are automatically routed through Theron
- Dangerous actions from untrusted content are blocked
- No configuration needed

Just use your AI agents normally:
```bash
claude        # Protected
moltbot       # Protected
your-agent    # Protected
```

## Manual Mode (Advanced)

If you prefer not to use automatic setup:

```bash
theron                    # Start proxy + dashboard manually
```

Then set environment variables:
```bash
export ANTHROPIC_API_URL=http://localhost:8081
export OPENAI_API_BASE=http://localhost:8081/v1
```

## How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│                         YOUR COMPUTER                            │
│                                                                  │
│  ┌─────────┐      ┌──────────────┐      ┌─────────────────────┐ │
│  │   AI    │ ───▶ │    THERON    │ ───▶ │ api.anthropic.com   │ │
│  │  Agent  │ ◀─── │    Proxy     │ ◀─── │ api.openai.com      │ │
│  └─────────┘      └──────────────┘      └─────────────────────┘ │
│                          │                                       │
│         ┌────────────────┼────────────────┐                     │
│         │                │                │                     │
│    ┌────▼────┐    ┌──────▼──────┐   ┌─────▼─────┐              │
│    │Dashboard│    │ Intelligence │   │  Sandbox  │              │
│    │  :8080  │    │    Layer     │   │  (Docker) │              │
│    └─────────┘    └─────────────┘   └───────────┘              │
└──────────────────────────────────────────────────────────────────┘
```

1. Agent sends request to `localhost:8081`
2. Theron tags messages with trust levels, detects injection attempts
3. Request forwards to real LLM API
4. Response analyzed - tool calls classified by risk
5. Intelligence layer evaluates: causal chains, exfiltration, hijack, honeypots, taints
6. Dangerous actions from untrusted content get sandboxed or blocked
7. Behavioral baseline updated, anomalies flagged
8. Dashboard shows real-time events and alerts

## Policy Matrix

Actions are allowed/blocked based on source trust × action risk:

| Source ↓ / Risk → | Tier 1 (Safe) | Tier 2 (Moderate) | Tier 3 (Sensitive) | Tier 4 (Critical) |
|-------------------|---------------|-------------------|--------------------|--------------------|
| USER_DIRECT       | Allow         | Allow             | Allow              | Log                |
| USER_INDIRECT     | Allow         | Allow             | Log                | Sandbox            |
| CONTENT_READ      | Allow         | Log               | Sandbox            | Sandbox            |
| TOOL_RESULT       | Allow         | Log               | Sandbox            | Sandbox            |

Enhanced gating adds composite risk scoring from injection detection, honeypot triggers, exfiltration attempts, intent drift, and behavioral anomalies.

## CLI Commands

```bash
# Setup (one-time)
theron setup              # Configure automatic protection
theron setup --status     # Check setup status
theron setup --uninstall  # Remove setup

# Manual mode
theron                    # Start proxy + dashboard
theron proxy              # Just proxy
theron dashboard          # Just dashboard
```

## Testing

```bash
pytest tests/ -v    # 151 tests
```

## Configuration

Config stored at `~/.theron/config.yaml`:

```yaml
proxy:
  listen_port: 8081

detection:
  sensitivity: 5           # 1-10
  injection_threshold: 70  # 0-100

classification:
  unknown_tool_tier: 3     # Default tier for unknown tools

gating:
  whitelist: [get_weather]
  blacklist: [format_disk]

learning:
  enabled: true
  baseline_requests: 25    # Requests before baseline is established
```

## Dashboard

The web dashboard at `http://localhost:8080` provides:

- **Events** - Real-time feed of all security events via WebSocket
- **Blocked Actions** - Log of dangerous actions that were automatically blocked
- **Intelligence** - Causal chains, alerts, honeypot stats, taint reports
- **Profiles** - Per-agent behavioral baselines and anomalies
- **Statistics** - Charts and summaries

**Note:** Theron is fully automatic. Dangerous actions are blocked without requiring user approval - the dashboard is for visibility, not decision-making.

## API Reference

### Proxy (port 8081)
- `POST /v1/messages` - Anthropic API
- `POST /v1/chat/completions` - OpenAI API
- `GET /health` - Health check

### Dashboard (port 8080)
- `GET /api/events` - List events
- `GET /api/sandbox/blocked` - Recently blocked actions
- `GET /api/intelligence/summary` - Intelligence overview
- `GET /api/agents/{id}/profile` - Agent behavioral profile
- `WS /api/events/stream` - Real-time event stream

See [CLAUDE.md](CLAUDE.md) for full API reference.

## License

MIT
