# Theron

**Security Layer for Agentic AI Systems**

Theron is a security proxy that sits between AI agents and their LLM backends, detecting prompt injection attacks, classifying action risk, and blocking malicious commands before they execute.

## The Problem

Agentic AI systems (Claude Code, Open Interpreter, AutoGPT, custom agents) give LLMs the ability to take real-world actions - execute shell commands, send emails, access files, control devices. When these systems process untrusted content (emails, documents, web pages), prompt injection attacks can hijack the AI into executing malicious commands.

**Theron solves the fundamental problem: content the AI reads should never have the same privilege level as commands the user issues.**

## Features

- **Universal Proxy** - Works with any agent via simple env var change
- **Prompt Injection Detection** - 50+ pattern signatures for common attacks
- **Action Risk Classification** - 4-tier risk system for tool calls
- **Source-Based Gating** - Block dangerous actions from untrusted content
- **Real-time Dashboard** - Web UI for monitoring and configuration
- **Zero Configuration** - Works out of the box with sensible defaults

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/theron.git
cd theron

# Install with pip
pip install -e .

# Or use Docker
docker-compose up -d
```

### Usage

```bash
# Start Theron (proxy + dashboard)
theron

# Or run components separately
theron proxy      # Just the proxy on :8081
theron dashboard  # Just the dashboard on :8080
```

### Configure Your Agent

Simply redirect your agent's LLM API calls through Theron:

```bash
# For Anthropic-based agents
export ANTHROPIC_API_URL=http://localhost:8081

# For OpenAI-based agents
export OPENAI_API_BASE=http://localhost:8081/v1
```

That's it! Your agent now has security protection.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                        USER DEVICE                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────┐                                          │
│   │  AI AGENT    │                                          │
│   │              │        ┌──────────────┐       ┌───────┐  │
│   │  • Claude    │ ─────▶ │   THERON     │ ────▶ │  LLM  │  │
│   │  • GPT       │ ◀───── │    Proxy     │ ◀──── │  API  │  │
│   │  • Custom    │        └──────────────┘       └───────┘  │
│   └──────────────┘               │                          │
│                                  ▼                          │
│                          ┌──────────────┐                   │
│                          │  Dashboard   │                   │
│                          └──────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### Security Pipeline

1. **Source Tagging** - Every message is tagged with its trust level:
   - `USER_DIRECT` - Direct user commands (trusted)
   - `USER_INDIRECT` - User-initiated content processing
   - `CONTENT_READ` - External content (emails, files, web) (untrusted)
   - `TOOL_RESULT` - Output from tool execution

2. **Injection Detection** - Content is scanned for attack patterns:
   - Instruction override attempts ("ignore previous instructions")
   - Role injection ("you are now...")
   - Delimiter attacks (fake XML tags, markdown abuse)
   - Exfiltration commands ("send to...")
   - Dangerous shell commands

3. **Action Classification** - Tool calls are classified by risk:
   - **Tier 1 (Safe)**: `read_file`, `get_weather`, `search_web`
   - **Tier 2 (Moderate)**: `send_email`, `write_file`, `post_message`
   - **Tier 3 (Sensitive)**: `execute_shell`, `delete_file`, `run_script`
   - **Tier 4 (Critical)**: `sudo_*`, `transfer_funds`, `admin_*`

4. **Policy Enforcement** - Actions are allowed/blocked based on trust × risk:

   | Source ↓ / Risk → | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
   |-------------------|--------|--------|--------|--------|
   | USER_DIRECT       | Allow  | Allow  | Allow  | Log    |
   | USER_INDIRECT     | Allow  | Allow  | Log    | Block  |
   | CONTENT_READ      | Allow  | Log    | Block  | Block  |
   | TOOL_RESULT       | Allow  | Log    | Block  | Block  |

## Configuration

Configuration is stored in `~/.theron/config.yaml`:

```yaml
proxy:
  listen_port: 8081
  timeout: 120

detection:
  sensitivity: 5           # 1 (permissive) to 10 (strict)
  injection_threshold: 70  # Threat score to trigger (0-100)
  categories:
    ignore_previous: true
    role_injection: true
    delimiter_attacks: true
    exfiltration: true
    dangerous_commands: true

classification:
  unknown_tool_tier: 3     # Default tier for unknown tools

gating:
  whitelist:
    - get_weather
    - get_time
  blacklist:
    - format_disk
  overrides:
    "CONTENT_READ:send_email": "block"

dashboard:
  enabled: true
  port: 8080
```

## Dashboard

Access the dashboard at `http://localhost:8080` to:

- View real-time event stream
- See blocked actions and injection attempts
- Monitor statistics and trends
- Configure detection settings

## API Endpoints

### Proxy (port 8081)

- `POST /v1/messages` - Anthropic API
- `POST /v1/chat/completions` - OpenAI API
- `GET /health` - Health check

### Dashboard (port 8080)

- `GET /api/events` - List events
- `GET /api/events/stream` - WebSocket live feed
- `GET /api/stats` - Statistics
- `GET /api/config` - Get configuration
- `PUT /api/config` - Update configuration

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/

# Run type checker
mypy src/
```

## Architecture

```
theron/
├── src/theron/
│   ├── proxy/          # Proxy server
│   │   ├── server.py   # FastAPI app
│   │   ├── anthropic.py
│   │   └── openai.py
│   ├── security/       # Security engine
│   │   ├── tagger.py   # Source tagging
│   │   ├── detector.py # Injection detection
│   │   ├── classifier.py # Risk classification
│   │   └── gating.py   # Policy enforcement
│   ├── storage/        # Data persistence
│   ├── dashboard/      # Web UI backend
│   ├── config.py       # Configuration
│   ├── patterns.py     # Detection patterns
│   └── main.py         # CLI
├── static/             # Dashboard frontend
├── tests/
└── config/
```

## License

MIT

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.
