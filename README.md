# Theron

Security proxy for agentic AI systems. Detects prompt injection attacks and blocks dangerous actions automatically.

## The Problem

AI agents can execute shell commands, send emails, and access files. When they process untrusted content (emails, web pages, documents), prompt injection attacks can hijack them into executing malicious commands.

**Theron's principle:** Content the AI reads should never have the same privilege level as commands the user issues.

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

Restart your terminal. That's it - your AI agents are now protected.

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

1. Your AI agent sends requests through Theron
2. Theron analyzes messages for injection attacks
3. Tool calls are classified by risk level
4. Dangerous actions from untrusted content are blocked
5. Safe requests pass through normally

## What Gets Protected

- **Prompt Injection Detection** - Detects instruction overrides, role injection, delimiter attacks
- **Risk-Based Blocking** - Dangerous tools (shell, file delete, sudo) blocked when triggered by untrusted content
- **Exfiltration Prevention** - Blocks sensitive data (credentials, keys) from leaking
- **Behavioral Anomaly Detection** - Learns normal patterns, flags unusual activity

## Dashboard

View your protection status at `http://localhost:8080`:

- Threats blocked count
- Requests checked count
- Recently blocked actions

## CLI Commands

```bash
theron setup              # Configure automatic protection
theron setup --status     # Check if protected
theron setup --uninstall  # Remove protection
theron                    # Start manually (if not using auto-setup)
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

## Security

Theron runs on localhost only. This is intentional:

- **No authentication needed** - Only local processes can access it
- **DNS rebinding protected** - Host header validation requires exact `localhost` match
- **CORS restricted** - Only localhost origins allowed

If you need remote access, use SSH tunneling or a reverse proxy with authentication.

## License

MIT
