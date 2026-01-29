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

### Autonomous Agent Support
- **Behavioral Baseline** - Learn normal patterns per agent, flag anomalies with zero config
- **Task-Scoped Permissions** - Dynamically restrict tools based on inferred task (coding vs email)
- **Shadow Execution** - Run actions in isolation, auto-commit/discard based on behavior analysis
- **Graceful Degradation** - Automatically reduce agent autonomy when threats detected

## Installation

Theron runs **locally on your machine** as a proxy between your AI agent and the LLM API.

```bash
git clone https://github.com/your-org/theron.git
cd theron
pip install -e .
```

## Usage

```bash
# Start Theron (proxy + dashboard)
theron

# Opens:
#   Proxy:     http://localhost:8081
#   Dashboard: http://localhost:8080
```

Point your AI agent at the proxy:

```bash
# For Anthropic-based agents
export ANTHROPIC_API_URL=http://localhost:8081

# For OpenAI-based agents
export OPENAI_API_BASE=http://localhost:8081/v1

# Run your agent normally - it's now protected
your-agent start
```

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│                    YOUR COMPUTER                          │
│                                                          │
│  ┌─────────┐      ┌─────────┐      ┌─────────────────┐  │
│  │   AI    │ ───▶ │ THERON  │ ───▶ │ api.anthropic.  │  │
│  │  Agent  │ ◀─── │  Proxy  │ ◀─── │ com / openai    │  │
│  └─────────┘      └─────────┘      └─────────────────┘  │
│                        │                                 │
│                   ┌────▼────┐                           │
│                   │Dashboard│                           │
│                   │ :8080   │                           │
│                   └─────────┘                           │
└──────────────────────────────────────────────────────────┘
```

1. Agent sends request to `localhost:8081`
2. Theron analyzes messages, tags trust levels, detects injection
3. Request forwards to real LLM API
4. Response analyzed - tool calls classified by risk
5. Dangerous actions from untrusted content get blocked or sandboxed
6. Dashboard shows real-time events and alerts

## Policy Matrix

Actions are allowed/blocked based on source trust × action risk:

| Source ↓ / Risk → | Tier 1 (Safe) | Tier 2 (Moderate) | Tier 3 (Sensitive) | Tier 4 (Critical) |
|-------------------|---------------|-------------------|--------------------|--------------------|
| USER_DIRECT       | Allow         | Allow             | Allow              | Log                |
| USER_INDIRECT     | Allow         | Allow             | Log                | Block              |
| CONTENT_READ      | Allow         | Log               | Sandbox            | Block              |
| TOOL_RESULT       | Allow         | Log               | Sandbox            | Block              |

## Testing

```bash
pytest tests/ -v    # 127 tests
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
```

## License

MIT
