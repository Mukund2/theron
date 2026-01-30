# Theron

Security proxy for agentic AI systems. Blocks prompt injection attacks automatically.

## Why Theron?

**Other tools scan for bad patterns. Theron enforces privilege separation.**

Most AI security tools try to detect "malicious" prompts with regex or ML. The problem? Attackers constantly find bypasses.

Theron takes a different approach: **content your AI reads should never have the same privilege as commands you issue.** An email can't run shell commands - even if it contains valid-looking instructions.

### What Makes It Different

| Feature | Theron | Other Tools |
|---------|--------|-------------|
| **Source Trust Tagging** | Tags where content came from (user vs email vs web) and enforces different permissions | Treats all input the same |
| **Zero Config** | `curl \| sh`, restart terminal, done. Works with Claude Code, Cursor, etc. | Requires SDK integration into your code |
| **Local-First** | Runs entirely on your machine. No cloud, no data sent anywhere | Most are SaaS or require cloud components |
| **Honeypot Detection** | Seeds fake credentials - if your agent uses them, it's compromised | Pattern matching only |

## Installation

```bash
curl -fsSL https://mukund2.github.io/theron/install.sh | sh
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
irm https://mukund2.github.io/theron/install.ps1 | iex
```
</details>

<details>
<summary>Manual installation</summary>

```bash
pip install theron
theron setup
```
</details>

Restart your terminal. Your AI agents are now protected.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                       YOUR COMPUTER                         │
│                                                             │
│  ┌─────────┐      ┌──────────┐      ┌───────────────────┐  │
│  │   AI    │ ───▶ │  THERON  │ ───▶ │ api.anthropic.com │  │
│  │  Agent  │ ◀─── │  Proxy   │ ◀─── │ api.openai.com    │  │
│  └─────────┘      └──────────┘      └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

1. AI agent sends requests through Theron (automatic after setup)
2. Theron tags each message with its source: `USER_DIRECT`, `CONTENT_READ`, `TOOL_RESULT`
3. Tool calls are classified by risk: safe → moderate → sensitive → critical
4. **Policy matrix decides**: user commands can run shell, but email content cannot
5. Dangerous actions from untrusted sources are blocked automatically

## The Core Idea: Source × Risk

| Content Source | Safe Tools | Sensitive Tools | Critical Tools |
|----------------|------------|-----------------|----------------|
| **You typed it** | Allow | Allow | Allow |
| **From an email/webpage** | Allow | Block | Block |
| **From tool output** | Allow | Block | Block |

This is why Theron stops attacks that pattern-matching misses. The attacker's payload might look legitimate, but it came from untrusted content - so it can't execute dangerous actions.

## Features

- **Source Trust Tagging** - Every message tagged with origin and trust level
- **Prompt Injection Detection** - 50+ patterns across 6 attack categories
- **Risk-Based Gating** - 4-tier tool classification with 100+ tools mapped
- **Honeypot Injection** - Fake credentials seeded in outputs to detect compromise
- **Exfiltration Prevention** - Blocks sensitive data from leaking to external services
- **Behavioral Baselines** - Learns normal patterns, detects anomalies
- **Causal Chain Tracking** - Visualizes attack path: email → parse → shell command

## Dashboard

View protection status at `http://localhost:8080`:

- Threats blocked
- Requests checked
- Recently blocked actions

## CLI

```bash
theron setup              # Configure automatic protection
theron setup --status     # Check if protected
theron setup --uninstall  # Remove protection
theron                    # Start manually
```

## Configuration

Config at `~/.theron/config.yaml`:

```yaml
proxy:
  listen_port: 8081

detection:
  sensitivity: 5           # 1-10
  injection_threshold: 70  # 0-100

gating:
  whitelist: []            # Always allow these tools
  blacklist: []            # Always block these tools
```

## Security Model

Theron runs on localhost only - no authentication needed because only local processes can access it. DNS rebinding and CORS attacks are blocked.

## License

MIT
