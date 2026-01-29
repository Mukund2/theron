# Theron - Development Context

## What is Theron?

Theron is a **security proxy for agentic AI systems**. It sits between AI agents (Claude Code, Moltbot, AutoGPT, etc.) and their LLM backends, detecting prompt injection attacks and sandboxing dangerous actions.

**Core principle:** Content the AI reads should never have the same privilege level as commands the user issues.

## Current Status: Production Ready

**127 tests passing** across 6 test files covering all subsystems.

### What's Built

#### 1. Core Security Layer

**Universal Proxy Server** (`src/theron/proxy/`)
- Intercepts Anthropic and OpenAI API calls
- Auto-detects API format from request structure
- Forwards requests with security analysis
- Ports: 8081 (proxy), 8080 (dashboard)

**Input Source Tagging** (`src/theron/security/tagger.py`)
- Tags messages with trust levels:
  - `USER_DIRECT` - Direct user commands (trusted)
  - `USER_INDIRECT` - User-initiated content processing
  - `CONTENT_READ` - External content like emails (untrusted)
  - `TOOL_RESULT` - Output from tool execution
  - `SYSTEM` - System prompts
- 35+ classification patterns

**Prompt Injection Detection** (`src/theron/security/detector.py`)
- 50+ regex patterns across 6 categories
- Categories: ignore_previous, role_injection, authority_claims, delimiter_attacks, exfiltration, dangerous_commands
- Structural analysis (imperative density, hidden content, encoding attempts)
- Hidden content detection: HTML comments, zero-width characters, CSS hiding
- Encoding detection: base64, hex, HTML entities
- Threat scoring 0-100 with configurable sensitivity (1-10)

**Action Risk Classification** (`src/theron/security/classifier.py`)
- 4-tier risk system with 100+ tools classified:
  - Tier 1 (Safe): get_weather, read_file, search_web
  - Tier 2 (Moderate): send_email, write_file, post_slack
  - Tier 3 (Sensitive): execute_shell, delete_file, database_query
  - Tier 4 (Critical): sudo_*, transfer_funds, modify_firewall
- Pattern-based matching for unknown tools
- Config overrides and whitelist/blacklist

**Source-Based Gating** (`src/theron/security/gating.py`)
- Policy matrix: source_trust × action_risk → allow/log/sandbox/block
- Enhanced gating with composite risk scoring
- Integrates signals from all intelligence modules
- Response filtering for both Anthropic and OpenAI formats

#### 2. Intelligence Layer (`src/theron/intelligence/`)

**Intelligence Manager** (`manager.py`)
- Unified orchestrator for all intelligence modules
- Per-request tracking and evaluation
- Learns from user approvals/rejections

**Causal Chain Tracking** (`causal.py`)
- Visualizes attack lineage: "Email → Parse → Shell Command"
- Node types: user_input, content_read, tool_result, tool_call
- Risk scoring based on chain composition
- Graph visualization format (nodes + edges)

**Exfiltration Detection** (`exfiltration.py`)
- Detects sensitive data patterns: credentials, private keys, PII, internal paths
- Monitors outbound tools: email, HTTP, webhooks, pastebin
- Blocks when sensitive data flows to external destinations

**Hijack Detection** (`hijack.py`)
- Detects when agent tasks drift from original user intent
- Task inference from conversation (coding, research, communication, etc.)
- Maps expected tools per task type
- Drift scoring 0-1 for unexpected tool usage

**Honeypot Injection** (`honeypot.py`)
- Seeds fake credentials in tool outputs (API keys, passwords, AWS keys, GitHub tokens)
- If agent uses honeypot data → immediately compromised
- Configurable injection rate (default 30%)
- Triggers CRITICAL alerts

**Taint Tracking** (`taint.py`)
- Tracks which knowledge came from untrusted sources
- Content hashing for privacy
- Propagation detection: direct reference, keyword match, semantic similarity
- Reports most influential taints per request

#### 3. Learning Layer (`src/theron/learning/`)

**Behavioral Baseline** (`baseline.py`)
- Per-agent behavioral profiles
- Tracks: tool frequency, hourly patterns, average tools/request, risk tier distribution
- Learns from sandbox approvals/rejections
- Requires 25+ requests to build baseline (configurable)

**Anomaly Scoring** (`anomaly.py`)
- Zero-config anomaly detection once baseline exists
- Factors: tool frequency deviation, time patterns, risk shifts, threat elevation
- Scoring 0-1 with severity levels: none, low, medium, high, critical
- Gracefully degrades without baseline

#### 4. Autonomy Layer (`src/theron/autonomy/`)

**Task-Scoped Permissions** (`permissions.py`)
- Principle of Least Authority (POLA)
- Task scopes: CODING, RESEARCH, COMMUNICATION, FILE_MANAGEMENT, DATA_ANALYSIS, SYSTEM_ADMIN
- Time-limited capabilities with expiration and use limits
- Task inference from conversation keywords
- Decisions: ALLOW, WARN, DENY_SOFT, DENY_HARD

**Graceful Degradation** (`degradation.py`)
- 5 autonomy levels: FULL → CAUTIOUS → RESTRICTED → MINIMAL → SUSPENDED
- Triggers: anomaly detection, policy violations, honeypot triggers, exfiltration attempts
- Risk accumulation with thresholds
- Auto-recovery with cooldown periods

**Shadow Execution** (`shadow.py`)
- "See what happens" security model
- Runs actions in isolation, analyzes behavior
- Commit decisions: COMMIT (safe), DISCARD (malicious), QUARANTINE (uncertain)
- Violation detection: exfiltration patterns, honeypot usage, destructive ops

#### 5. Sandbox Layer (`src/theron/sandbox/`)

**Docker-Based Sandboxing** (`container.py`)
- Security constraints: no network, read-only FS, 256MB memory, 50% CPU, 30s timeout
- All capabilities dropped
- Output limiting (50KB max)
- Automatic container cleanup

**Sandbox Manager**
- Execute, approve, reject workflow
- Pending approval listing
- Expiration cleanup (1 hour TTL)
- Result storage in database

#### 6. Agent Management (`src/theron/agents/`)

**Agent Registry** (`registry.py`)
- Modular agent definitions in YAML
- 3 sources: built-in, user (~/.theron/agents/), project-local (.theron/agents/)
- Metadata: name, description, risk level, capabilities, install methods
- Risk levels: LOW, MEDIUM, HIGH, CRITICAL

**Guided Installer** (`installer.py`)
- Shows agent info and risk warnings
- Checks prerequisites
- Configures Theron protection automatically

**Agent Runner** (`runner.py`)
- Automatic Theron startup if needed
- Environment variable configuration
- Routes API calls through proxy

#### 7. Dashboard (`src/theron/dashboard/`)

**32 API Endpoints** (`api.py`)
- Configuration: GET/PUT /api/config
- Events: GET /api/events, /api/stats, /api/summary, /export/events
- Sandbox: /api/sandbox/*, approve, reject
- Intelligence: /api/intelligence/summary, /causal, /alerts, /honeypots, /taints
- Behavioral: /api/agents/{id}/profile, /anomalies, /profiles
- WebSocket: /api/events/stream

**Static UI** (`static/`)
- Real-time event feed via WebSocket
- Pending approvals tab
- Statistics and charts
- Industrial/cybersecurity aesthetic

#### 8. Storage (`src/theron/storage/`)

**SQLite Database** (`database.py`)
- Location: ~/.theron/theron.db
- Tables: events, sandbox results, patterns, daily stats
- Intelligence: causal chains, honeypots, taints, alerts, anomalies, profiles
- Async access via aiosqlite

## Architecture

```
theron/
├── src/theron/
│   ├── __init__.py
│   ├── main.py              # CLI entry point
│   ├── config.py            # Configuration management
│   ├── patterns.py          # Detection patterns + tool tiers
│   ├── proxy/
│   │   ├── server.py        # FastAPI proxy app
│   │   ├── anthropic.py     # Anthropic API handler
│   │   ├── openai.py        # OpenAI API handler
│   │   └── common.py        # Shared utilities
│   ├── security/
│   │   ├── tagger.py        # Source trust tagging
│   │   ├── detector.py      # Injection detection
│   │   ├── classifier.py    # Tool risk classification
│   │   └── gating.py        # Policy enforcement + enhanced gating
│   ├── intelligence/
│   │   ├── manager.py       # Intelligence orchestrator
│   │   ├── causal.py        # Causal chain tracking
│   │   ├── exfiltration.py  # Data leakage detection
│   │   ├── hijack.py        # Intent drift detection
│   │   ├── honeypot.py      # Canary credential injection
│   │   └── taint.py         # Memory taint tracking
│   ├── learning/
│   │   ├── baseline.py      # Behavioral profiling
│   │   └── anomaly.py       # Anomaly scoring
│   ├── autonomy/
│   │   ├── permissions.py   # Task-scoped POLA
│   │   ├── degradation.py   # Graceful autonomy reduction
│   │   └── shadow.py        # Pre-commit isolation testing
│   ├── sandbox/
│   │   ├── container.py     # Docker sandbox + manager
│   │   └── result.py        # Result models
│   ├── agents/
│   │   ├── registry.py      # Agent definitions
│   │   ├── installer.py     # Guided installation
│   │   └── runner.py        # Protected execution
│   ├── storage/
│   │   ├── database.py      # SQLite operations
│   │   └── models.py        # Pydantic models
│   └── dashboard/
│       ├── api.py           # REST + WebSocket endpoints
│       └── websocket.py     # Event broadcasting
├── static/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── tests/
│   ├── test_detector.py     # 13 tests
│   ├── test_classifier.py   # 13 tests
│   ├── test_gating.py       # 18 tests
│   ├── test_sandbox.py      # 16 tests
│   ├── test_intelligence.py # 32 tests
│   └── test_autonomy.py     # 35 tests
├── config/default.yaml
├── Dockerfile
├── docker-compose.yaml
├── pyproject.toml
└── README.md
```

## CLI Commands

```bash
# Start proxy + dashboard
theron

# Run components separately
theron proxy        # Just proxy on :8081
theron dashboard    # Just dashboard on :8080

# Configuration
theron init         # Create default config

# Agent management
theron agents                # List known agents
theron install {agent}       # Guided installation with safety checks
theron run {agent}           # Run agent with Theron protection
theron new-agent {name}      # Create agent definition template
```

## How to Test

```bash
# Run all tests (127 tests)
pytest tests/ -v

# Test specific modules
pytest tests/test_intelligence.py -v
pytest tests/test_autonomy.py -v

# Test proxy health
curl http://localhost:8081/health

# Test sandbox status
curl http://localhost:8080/api/sandbox/status
```

## User Integration

```bash
# Start Theron
theron &

# Point agent at proxy
export ANTHROPIC_API_URL=http://localhost:8081
export OPENAI_API_BASE=http://localhost:8081/v1

# Run agent normally - it's now protected
your-agent start

# Or use the built-in runner
theron run claude-code
```

## Policy Matrix

| Source ↓ / Risk → | Tier 1 (Safe) | Tier 2 (Moderate) | Tier 3 (Sensitive) | Tier 4 (Critical) |
|-------------------|---------------|-------------------|--------------------|--------------------|
| USER_DIRECT       | Allow         | Allow             | Allow              | Log                |
| USER_INDIRECT     | Allow         | Allow             | Log                | Sandbox            |
| CONTENT_READ      | Allow         | Log               | Sandbox            | Sandbox            |
| TOOL_RESULT       | Allow         | Log               | Sandbox            | Sandbox            |

Enhanced gating adds composite risk scoring from:
- Injection threat score
- Honeypot detection
- Exfiltration detection
- Hijack/intent drift score
- Anomaly score
- Taint influence

## Sandbox Flow

When a dangerous action (Tier 3/4) comes from untrusted content:

1. **Intercepted** - Proxy catches the tool call in LLM response
2. **Classified** - Risk tier + source trust + intelligence signals evaluated
3. **Sandboxed** - Command runs in Docker container:
   - No network access
   - Read-only filesystem + tmpfs
   - 256MB memory limit, 50% CPU
   - 30 second timeout
4. **Stored** - Result saved to SQLite, broadcast to dashboard
5. **User decides** - Review in "Pending Approvals" tab, click Approve or Reject
6. **Learned** - Approval/rejection updates behavioral baseline
7. **Response modified** - LLM response shows sandbox message instead of tool execution

## API Reference

### Proxy Endpoints (port 8081)
- `POST /v1/messages` - Anthropic API (proxied)
- `POST /v1/chat/completions` - OpenAI API (proxied)
- `GET /health` - Health check

### Dashboard Endpoints (port 8080)

**Configuration**
- `GET /api/config` - Get configuration
- `PUT /api/config` - Update configuration

**Events**
- `GET /api/events` - List events with filtering
- `GET /api/events/{id}` - Get specific event
- `GET /api/stats` - Statistics (7 days default)
- `GET /api/summary` - Summary stats
- `GET /export/events` - Export to CSV
- `WS /api/events/stream` - Real-time WebSocket

**Sandbox**
- `GET /api/sandbox/pending` - List pending approvals
- `GET /api/sandbox` - List all results
- `GET /api/sandbox/{id}` - Get specific result
- `POST /api/sandbox/{id}/approve` - Approve
- `POST /api/sandbox/{id}/reject` - Reject
- `GET /api/sandbox/status` - Docker availability

**Intelligence**
- `GET /api/intelligence/summary` - Overall summary
- `GET /api/intelligence/causal` - All causal chains
- `GET /api/intelligence/causal/{request_id}` - Specific chain
- `GET /api/intelligence/alerts` - Alert list
- `POST /api/intelligence/alerts/{id}/acknowledge` - Acknowledge alert
- `POST /api/intelligence/alerts/{id}/resolve` - Resolve alert
- `GET /api/intelligence/honeypots` - Honeypot stats
- `GET /api/intelligence/taints/{request_id}` - Taint report

**Behavioral Analysis**
- `GET /api/agents/{id}/profile` - Agent profile
- `GET /api/agents/{id}/anomalies` - Agent anomalies
- `GET /api/profiles` - All profiles

## Tech Stack

- Python 3.11+
- FastAPI + uvicorn
- SQLite + aiosqlite
- httpx (async HTTP client)
- Docker SDK (for sandboxing)
- Vanilla HTML/CSS/JS (no build step)

## Config Location

- Config: `~/.theron/config.yaml`
- Database: `~/.theron/theron.db`
- Agent definitions: `~/.theron/agents/`
- Default config template: `config/default.yaml`

## Future Ideas

- **Federated Threat Intelligence** - Share injection patterns across Theron instances
- **MicroVM Support** - Firecracker/gVisor for stronger isolation
- **ML-Based Detection** - Train models on injection patterns
- **IDE Integration** - VS Code extension for inline alerts
