# Theron - Development Context

## What is Theron?

Theron is a **security proxy for agentic AI systems**. It sits between AI agents (Claude Code, Moltbot, AutoGPT, etc.) and their LLM backends, detecting prompt injection attacks and sandboxing dangerous actions.

**Core principle:** Content the AI reads should never have the same privilege level as commands the user issues.

## Current Status: VM Sandboxing Complete

### What's Built (Working) - All 60 Tests Passing

1. **Universal Proxy Server** (`src/theron/proxy/`)
   - Intercepts Anthropic and OpenAI API calls
   - Auto-detects API format
   - Forwards requests with security analysis
   - Ports: 8081 (proxy), 8080 (dashboard)

2. **Input Source Tagging** (`src/theron/security/tagger.py`)
   - Tags messages with trust levels:
     - `USER_DIRECT` - Direct user commands (trusted)
     - `USER_INDIRECT` - User-initiated content processing
     - `CONTENT_READ` - External content like emails (untrusted)
     - `TOOL_RESULT` - Output from tool execution

3. **Prompt Injection Detection** (`src/theron/security/detector.py`)
   - 50+ regex patterns across 6 categories
   - Categories: ignore_previous, role_injection, authority_claims, delimiter_attacks, exfiltration, dangerous_commands
   - Structural analysis (imperative density, hidden content, encoding attempts)
   - Threat scoring 0-100

4. **Action Risk Classification** (`src/theron/security/classifier.py`)
   - 4-tier risk system:
     - Tier 1 (Safe): get_weather, read_file, search_web
     - Tier 2 (Moderate): send_email, write_file
     - Tier 3 (Sensitive): execute_shell, delete_file
     - Tier 4 (Critical): sudo_*, transfer_funds

5. **Source-Based Gating** (`src/theron/security/gating.py`)
   - Policy matrix: source_trust × action_risk → allow/log/sandbox/block
   - **SANDBOX action** for sensitive/critical actions from untrusted content
   - Injects block/sandbox explanations into responses

6. **VM Sandboxing** (`src/theron/sandbox/`) - NEW
   - Docker-based isolated execution
   - Security constraints: no network, read-only FS, memory/CPU limits, 30s timeout
   - Results stored in database, broadcast to dashboard via WebSocket
   - Approve/reject workflow for user decision

7. **Dashboard** (`src/theron/dashboard/` + `static/`)
   - Real-time event feed via WebSocket
   - **Pending Approvals tab** - review sandboxed actions, approve/reject
   - Statistics and charts
   - Configuration UI
   - Industrial/cybersecurity aesthetic (Space Grotesk + JetBrains Mono)

8. **Storage** (`src/theron/storage/`)
   - SQLite database at ~/.theron/theron.db
   - Event logging, pattern storage, daily stats
   - **Sandbox results table** with full execution details

9. **Configuration** (`src/theron/config.py`)
   - YAML config at ~/.theron/config.yaml
   - Sensitivity, thresholds, whitelist/blacklist, tool overrides

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
│   │   ├── anthropic.py     # Anthropic API handler (sandbox integration)
│   │   └── openai.py        # OpenAI API handler (sandbox integration)
│   ├── security/
│   │   ├── tagger.py        # Source trust tagging
│   │   ├── detector.py      # Injection detection
│   │   ├── classifier.py    # Tool risk classification
│   │   └── gating.py        # Policy enforcement (ALLOW/LOG/SANDBOX/BLOCK)
│   ├── sandbox/             # NEW - VM Sandboxing
│   │   ├── __init__.py
│   │   ├── container.py     # Docker-based sandbox + SandboxManager
│   │   └── result.py        # SandboxResult, SandboxStatus models
│   ├── storage/
│   │   ├── database.py      # SQLite operations (incl sandbox results)
│   │   └── models.py        # Pydantic models (incl SandboxResultDB)
│   └── dashboard/
│       ├── api.py           # REST + WebSocket + sandbox endpoints
│       └── websocket.py     # Event broadcasting
├── static/
│   ├── index.html           # Includes Approvals tab
│   ├── style.css            # Sandbox card styles
│   └── app.js               # Sandbox approve/reject handlers
├── tests/
│   ├── test_detector.py     # 13 tests
│   ├── test_classifier.py   # 13 tests
│   ├── test_gating.py       # 18 tests (incl SANDBOX)
│   └── test_sandbox.py      # 16 tests
├── config/default.yaml
├── Dockerfile
├── docker-compose.yaml
├── pyproject.toml
└── README.md
```

## How to Run

```bash
# Install
pip install -e .

# Start (runs both proxy and dashboard)
theron

# Or run separately
theron proxy      # Just proxy on :8081
theron dashboard  # Just dashboard on :8080
```

## How to Test

```bash
# Run all tests (60 tests)
python3 -m pytest tests/ -v

# Test proxy health
curl http://localhost:8081/health

# Test sandbox status
curl http://localhost:8080/api/sandbox/status

# Get pending approvals
curl http://localhost:8080/api/sandbox/pending

# Approve/reject a sandbox result
curl -X POST http://localhost:8080/api/sandbox/{sandbox_id}/approve
curl -X POST http://localhost:8080/api/sandbox/{sandbox_id}/reject
```

## User Integration

Users point their AI agent at Theron via env var:

```bash
# Start Theron
theron &

# Point agent at proxy
export ANTHROPIC_API_URL=http://localhost:8081
export OPENAI_API_BASE=http://localhost:8081/v1

# Run agent normally - it's now protected
clawdbot start
```

## Sandbox Flow

When a dangerous action (Tier 3/4) comes from untrusted content (`CONTENT_READ` or `TOOL_RESULT`):

1. **Intercepted** - Proxy catches the tool call in LLM response
2. **Classified** - Risk tier + source trust evaluated
3. **Sandboxed** - Command runs in Docker container:
   - No network access
   - Read-only filesystem + tmpfs
   - 256MB memory limit, 50% CPU
   - 30 second timeout
4. **Stored** - Result saved to SQLite, broadcast to dashboard
5. **User decides** - Review in "Pending Approvals" tab, click Approve or Reject
6. **Response modified** - LLM response shows sandbox message instead of tool execution

## Next Features to Implement

### 1. Personalized Anomaly Detection

Learn user's common patterns to detect abnormalities:

- **Pattern Learning**: Track typical tool usage, argument patterns, timing
- **Baseline Building**: Build per-user behavioral profiles over time
- **Anomaly Scoring**: Flag deviations from normal behavior
- **Adaptive Thresholds**: Adjust sensitivity based on user patterns

Implementation ideas:
- `src/theron/learning/profile.py` - User behavior profiling
- `src/theron/learning/anomaly.py` - Anomaly detection engine
- Store patterns in `~/.theron/profiles/` or SQLite

### 2. Federated Threat Intelligence

When one Theron instance detects a threat, all instances get smarter:

- **Threat Sharing**: New injection patterns shared across Theron network
- **Recursive Self-Improvement**: Detection patterns update automatically
- **Privacy-Preserving**: Share pattern signatures, not user data
- **Consensus Validation**: Multiple detections before global rollout

Implementation ideas:
- `src/theron/network/` - P2P or central server communication
- `src/theron/patterns.py` - Dynamic pattern updates
- Pattern versioning and rollback capability
- Opt-in telemetry with anonymization

### 3. Other Ideas

- **MicroVM Support**: Firecracker/gVisor for stronger isolation
- **File Change Tracking**: Capture filesystem deltas in sandbox
- **Network Traffic Logging**: Monitor sandboxed network attempts
- **ML-Based Detection**: Train models on injection patterns
- **IDE Integration**: VS Code extension for inline alerts

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
- Default config template: `config/default.yaml`

## API Reference

### Proxy Endpoints (port 8081)
- `POST /v1/messages` - Anthropic API (proxied)
- `POST /v1/chat/completions` - OpenAI API (proxied)
- `GET /health` - Health check

### Dashboard Endpoints (port 8080)
- `GET /api/events` - List events with filtering
- `GET /api/stats` - Statistics and summaries
- `GET /api/config` - Get configuration
- `PUT /api/config` - Update configuration
- `WS /api/events/stream` - Real-time event WebSocket

### Sandbox Endpoints (port 8080)
- `GET /api/sandbox/pending` - List pending approvals
- `GET /api/sandbox` - List all sandbox results
- `GET /api/sandbox/{id}` - Get specific result
- `POST /api/sandbox/{id}/approve` - Approve for real execution
- `POST /api/sandbox/{id}/reject` - Reject the action
- `GET /api/sandbox/status` - Check Docker availability
