# Theron: Security Layer for Agentic AI

## Product Requirements Document

**Version:** 1.0
**Date:** January 28, 2026
**Author:** Mukund
**Status:** MVP Definition

---

## Executive Summary

Theron is a security proxy for agentic AI systems. It sits between any AI agent and its LLM backend, detecting prompt injection attacks, classifying action risk, and blocking malicious commands before they execute.

The problem is universal: agentic AI systems (Moltbot, Open Interpreter, AutoGPT, custom agents) give LLMs the ability to take real-world actions—execute shell commands, send emails, access files, control devices. When these systems process untrusted content (emails, documents, web pages), prompt injection attacks can hijack the AI into executing malicious commands.

Theron solves the fundamental problem: **content the AI reads should never have the same privilege level as commands the user issues.**

The architecture is agent-agnostic. Any system that makes API calls to an LLM can route through Theron. We validate with Moltbot first (because it just went viral with 60k+ stars and has active security incidents), but the core engine works with any agentic system.

---

## Problem Statement

### The Vulnerability

Agentic AI systems share common characteristics:
- LLM-powered decision making
- Tool/function calling capabilities (shell, files, APIs)
- Processing of external content (email, documents, web)
- Autonomous or semi-autonomous operation

This creates a universal attack vector: **prompt injection through content**.

Example attack flow:
1. Attacker sends victim an email containing hidden instructions
2. User asks their AI agent to "check my email"
3. AI reads the email, interprets embedded instructions as legitimate
4. AI executes attacker's commands (exfiltrate data, send messages, run code)

This attack has been demonstrated against Moltbot in under 5 minutes, extracting private cryptocurrency keys.

### Why This Is Getting Worse

1. **Proliferation of agents:** Moltbot hit 60k stars in 72 hours. Dozens of similar projects are emerging.
2. **Increasing autonomy:** Users want agents that act without confirmation prompts
3. **Deeper integrations:** Agents connecting to more sensitive systems (banking, smart home, work tools)
4. **Non-technical users:** One-click installs mean security-naive users running powerful agents

### The Gap

No solution exists that:
- Works across multiple agentic AI systems
- Requires zero configuration for basic protection
- Handles prompt injection at the architectural level
- Gives users visibility into what their agent is doing

---

## Solution Overview

Theron is a proxy server that intercepts traffic between any AI agent and its LLM API. Every request passes through Theron, which:

1. **Tags input sources** — distinguishes user commands from content being processed
2. **Detects prompt injection** — identifies embedded instructions in untrusted content
3. **Classifies action risk** — categorizes operations by potential harm
4. **Gates dangerous actions** — blocks high-risk operations from untrusted sources
5. **Learns over time** — improves detection based on patterns (v2)
6. **Logs everything** — provides visibility into what was allowed/blocked

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                           USER DEVICE                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────────┐                                               │
│   │  ANY AI AGENT    │                                               │
│   │                  │                                               │
│   │  • Moltbot       │         ┌──────────────┐         ┌────────┐  │
│   │  • Open Interp.  │ ──────▶ │   THERON     │ ──────▶ │  LLM   │  │
│   │  • AutoGPT       │ ◀────── │    Proxy     │ ◀────── │  API   │  │
│   │  • Custom agent  │         └──────────────┘         └────────┘  │
│   │  • Claude Code   │                │                              │
│   └──────────────────┘                │                              │
│                                       ▼                              │
│                                ┌──────────────┐                      │
│                                │  Theron DB   │                      │
│                                │   (SQLite)   │                      │
│                                └──────────────┘                      │
│                                       │                              │
│                                       ▼                              │
│                                ┌──────────────┐                      │
│                                │  Dashboard   │                      │
│                                │  (Web UI)    │                      │
│                                └──────────────┘                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Agent Integration Model

Theron works with any agent by acting as an LLM API endpoint:

```bash
# Before Theron
ANTHROPIC_API_URL=https://api.anthropic.com

# After Theron
ANTHROPIC_API_URL=http://localhost:8081
```

The agent doesn't know Theron exists. Theron intercepts, analyzes, potentially modifies, then forwards to the real LLM API.

**Supported LLM APIs (MVP):**
- Anthropic (Claude)
- OpenAI (GPT-4, etc.)

**Future:**
- Google (Gemini)
- Local models (Ollama, llama.cpp)
- Any OpenAI-compatible API

---

## MVP Feature Specification

### Feature 1: Universal Proxy Server

**Description:** HTTP/HTTPS proxy that intercepts LLM API traffic from any agent.

**Requirements:**
- Accept connections on configurable port (default: 8081)
- Detect API format automatically (Anthropic vs OpenAI)
- Forward requests to appropriate LLM endpoint
- Return responses to agent
- Add < 100ms latency in pass-through mode
- Handle concurrent connections from multiple agents
- Support HTTPS/TLS for upstream connections

**Technical Implementation:**
- Python FastAPI with async handlers
- Auto-detection of API format from request structure
- Environment variable for API keys (passed through)
- Connection pooling for LLM API calls

**Acceptance Criteria:**
- [ ] Works with Moltbot without code changes (just env var)
- [ ] Works with Open Interpreter without code changes
- [ ] Works with raw curl requests to test
- [ ] Latency overhead < 100ms for simple requests
- [ ] Handles both Anthropic and OpenAI formats

---

### Feature 2: Input Source Tagging

**Description:** Tag every piece of content in the conversation with its trust level based on context analysis.

**Trust Levels:**

| Level | Description | How Detected |
|-------|-------------|--------------|
| `USER_DIRECT` | Direct user instruction | First message, or clear command pattern |
| `USER_INDIRECT` | User-initiated processed content | "Read this file", "Check this URL" |
| `CONTENT_READ` | External content being processed | Email bodies, file contents, web pages |
| `TOOL_RESULT` | Output from tool execution | Follows tool_use in conversation |
| `SYSTEM` | System prompts and configs | role: system |

**Detection Heuristics:**

Since we can't modify the agent, we infer source from conversation structure:
- System messages → `SYSTEM`
- First user message in conversation → `USER_DIRECT`
- Content following "read", "check", "open", "fetch" → `CONTENT_READ`
- Tool results → `TOOL_RESULT`
- Large text blocks (>500 chars) in user messages → likely `CONTENT_READ`

**Requirements:**
- Analyze conversation structure to infer sources
- Inject source context into system prompt (invisible to user)
- Handle multi-turn conversations correctly
- Configurable heuristics

**Technical Implementation:**
- Conversation parser for both API formats
- Heuristic engine with configurable rules
- System prompt injection: prepend Theron context
- Preserve conversation for stateless analysis

**Acceptance Criteria:**
- [ ] Correctly identifies direct user commands
- [ ] Correctly identifies email/document content
- [ ] Works across multi-turn conversations
- [ ] Configurable sensitivity

---

### Feature 3: Prompt Injection Detection

**Description:** Scan content for embedded instructions that could hijack the AI.

**Detection Methods:**

**Tier 1 - Pattern Matching (MVP):**

```python
INJECTION_PATTERNS = {
    # Instruction override attempts
    "ignore_previous": [
        r"ignore\s+(all\s+)?(previous|prior|above)",
        r"disregard\s+(all\s+)?(previous|prior|above)",
        r"forget\s+(all\s+)?(previous|prior|above)",
    ],

    # Role injection
    "role_injection": [
        r"you\s+are\s+now",
        r"act\s+as\s+(if\s+you\s+are|a)",
        r"pretend\s+(to\s+be|you\s+are)",
        r"new\s+(role|identity|persona)",
    ],

    # Authority claims
    "authority_claims": [
        r"admin(istrator)?\s+(mode|override|access)",
        r"developer\s+mode",
        r"debug\s+mode",
        r"maintenance\s+mode",
        r"jailbreak",
        r"DAN\s+mode",
    ],

    # Delimiter attacks
    "delimiter_attacks": [
        r"</?(system|user|assistant|human|ai)>",
        r"```\s*(system|prompt|instruction)",
        r"\[INST\]|\[/INST\]",
        r"<\|im_start\|>|<\|im_end\|>",
    ],

    # Exfiltration attempts
    "exfiltration": [
        r"send\s+(to|all|this|the)\s+.{0,20}@",
        r"forward\s+(to|all|this|the)",
        r"email\s+.{0,30}\s+to\s+.{0,20}@",
        r"post\s+(to|on)\s+(pastebin|gist|hastebin)",
    ],

    # Dangerous commands
    "dangerous_commands": [
        r"(rm|del|delete)\s+(-rf?\s+)?[/~]",
        r"curl\s+.{0,50}\s*\|\s*(ba)?sh",
        r"wget\s+.{0,50}\s*&&",
        r"eval\s*\(",
        r"exec\s*\(",
    ],
}
```

**Tier 2 - Structural Analysis (MVP):**
- Instruction density: count imperative sentences in content
- Formatting anomalies: code blocks, special characters in emails
- Length mismatch: short email with long "signature" containing instructions

**Tier 3 - Semantic Analysis (v2):**
- Secondary LLM call to classify intent
- Fine-tuned classifier for injection detection

**Scoring Algorithm:**

```python
def calculate_threat_score(content: str, source_tag: str) -> int:
    score = 0

    # Pattern matches
    for category, patterns in INJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score += CATEGORY_WEIGHTS[category]

    # Structural signals
    if count_imperatives(content) > 3:
        score += 15
    if has_delimiter_chars(content):
        score += 20
    if instruction_density(content) > 0.3:
        score += 25

    # Source multiplier (untrusted content is riskier)
    if source_tag == "CONTENT_READ":
        score = int(score * 1.5)

    return min(score, 100)
```

**Requirements:**
- Scan all content tagged as `CONTENT_READ` or `TOOL_RESULT`
- Assign threat score (0-100)
- Flag content above threshold (default: 70)
- Log all detections with context
- Configurable patterns and weights

**Acceptance Criteria:**
- [ ] Detects 50+ known injection patterns
- [ ] < 5% false positive rate on legitimate content
- [ ] Configurable threshold
- [ ] Extensible pattern system

---

### Feature 4: Action Risk Classification

**Description:** Categorize every tool/function call by potential harm.

**Risk Tiers:**

| Tier | Level | Examples | Default Policy |
|------|-------|----------|----------------|
| 1 | Safe | `get_weather`, `get_time`, `read_calendar`, `search_web` | Allow |
| 2 | Moderate | `send_email`, `post_message`, `create_event`, `write_file` | Allow + Log |
| 3 | Sensitive | `execute_shell`, `run_script`, `delete_file`, `access_credentials` | Gate |
| 4 | Critical | `sudo_*`, `admin_*`, `bulk_delete`, `transfer_funds` | Block from untrusted |

**Tool Classification (Default):**

```yaml
tier_1_safe:
  - get_weather
  - get_time
  - get_date
  - read_calendar
  - search_web
  - read_file
  - list_directory
  - get_clipboard

tier_2_moderate:
  - send_email
  - send_message
  - post_to_slack
  - post_to_discord
  - create_calendar_event
  - write_file
  - create_file
  - append_file

tier_3_sensitive:
  - execute_shell
  - execute_command
  - run_script
  - run_python
  - delete_file
  - move_file
  - access_keychain
  - read_credentials
  - browser_navigate
  - browser_click

tier_4_critical:
  - sudo_execute
  - admin_command
  - bulk_delete
  - format_disk
  - transfer_funds
  - send_crypto
  - modify_system_config
```

**Unknown Tool Handling:**
- Default to Tier 3 (sensitive) for unknown tools
- Log for review
- User can reclassify via config

**Requirements:**
- Parse tool calls from LLM responses (both API formats)
- Classify each tool by name matching
- Support regex patterns for classification
- Support custom overrides in config

**Acceptance Criteria:**
- [ ] Correctly parses Anthropic tool_use format
- [ ] Correctly parses OpenAI function_call format
- [ ] Unknown tools default to Tier 3
- [ ] Custom classifications work

---

### Feature 5: Source-Based Action Gating

**Description:** Apply security policy based on (action risk × source trust).

**Policy Matrix:**

| Source ↓ / Risk → | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|-------------------|--------|--------|--------|--------|
| `USER_DIRECT` | ✅ Allow | ✅ Allow | ✅ Allow | ⚠️ Log |
| `USER_INDIRECT` | ✅ Allow | ✅ Allow | ⚠️ Log | ❌ Block |
| `CONTENT_READ` | ✅ Allow | ⚠️ Log | ❌ Block | ❌ Block |
| `TOOL_RESULT` | ✅ Allow | ⚠️ Log | ❌ Block | ❌ Block |
| `SYSTEM` | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |

**Gating Actions:**

- **Allow:** Pass through unchanged
- **Log:** Pass through, record in database
- **Block:** Remove tool call from response, inject explanation

**Block Response Injection:**

When blocking, modify LLM response to explain:

```json
{
  "role": "assistant",
  "content": "[Theron Security] Blocked action: execute_shell\nReason: High-risk action (Tier 3) initiated from untrusted content.\nThe AI attempted to run a shell command based on instructions found in external content (email/document). This could be a prompt injection attack.\n\nOriginal request: rm -rf /tmp/data\n\nIf this was intentional, you can:\n1. Run the command directly as a user message\n2. Whitelist this specific action in Theron config"
}
```

**Requirements:**
- Intercept LLM responses before returning to agent
- Apply policy matrix lookup
- For blocked actions: modify response, log details
- Preserve non-blocked tool calls
- Handle multiple tool calls in single response

**Acceptance Criteria:**
- [ ] Blocks shell commands from email content
- [ ] Allows shell commands from direct user requests
- [ ] Explanation injected on block
- [ ] Multiple tool calls handled correctly

---

### Feature 6: Logging & Dashboard

**Description:** Web UI for visibility and configuration.

**Event Log View:**

| Timestamp | Agent | Source | Action | Risk | Threat Score | Status |
|-----------|-------|--------|--------|------|--------------|--------|
| 10:23:45 | moltbot | CONTENT_READ | execute_shell | Tier 3 | 85 | 🛑 Blocked |
| 10:23:42 | moltbot | USER_DIRECT | send_email | Tier 2 | 0 | ✅ Allowed |
| 10:22:18 | interpreter | USER_DIRECT | run_python | Tier 3 | 0 | ✅ Allowed |

**Dashboard Panels:**

1. **Live Feed:** Real-time event stream with filtering
2. **Threat Summary:** Blocked actions, injection attempts, risk distribution
3. **Agent Overview:** Which agents are connected, request volume
4. **Configuration:** Sensitivity, custom rules, whitelist/blacklist

**Requirements:**
- Web UI at `localhost:8080`
- No authentication (local only for MVP)
- Real-time updates via WebSocket
- Filterable by agent, status, risk tier
- Export logs as JSON/CSV

**Technical Implementation:**
- FastAPI serving static files + REST API
- SQLite for persistence
- Vanilla HTML/CSS/JS (no build step)
- WebSocket for live updates

**Acceptance Criteria:**
- [ ] Dashboard loads and shows events
- [ ] Blocked actions highlighted in red
- [ ] Filtering works
- [ ] Real-time updates work

---

### Feature 7: Configuration System

**Config File:** `~/.theron/config.yaml`

```yaml
# Theron Configuration
# Security layer for agentic AI systems

#──────────────────────────────────────────────────────────────────────
# PROXY SETTINGS
#──────────────────────────────────────────────────────────────────────
proxy:
  listen_port: 8081

  endpoints:
    anthropic: "https://api.anthropic.com"
    openai: "https://api.openai.com"

  timeout: 120
  passthrough_auth: true

#──────────────────────────────────────────────────────────────────────
# DETECTION SETTINGS
#──────────────────────────────────────────────────────────────────────
detection:
  # Sensitivity: 1 (permissive) to 10 (strict)
  sensitivity: 5

  # Threat score threshold (0-100)
  injection_threshold: 70

  # Enable/disable detection categories
  categories:
    ignore_previous: true
    role_injection: true
    authority_claims: true
    delimiter_attacks: true
    exfiltration: true
    dangerous_commands: true

  # Custom patterns (regex)
  custom_patterns:
    - pattern: "send.*to.*@protonmail"
      weight: 30
      description: "Suspicious email exfiltration"

#──────────────────────────────────────────────────────────────────────
# ACTION CLASSIFICATION
#──────────────────────────────────────────────────────────────────────
classification:
  unknown_tool_tier: 3

  tool_overrides:
    my_safe_tool: 1
    my_dangerous_tool: 4

#──────────────────────────────────────────────────────────────────────
# GATING POLICY
#──────────────────────────────────────────────────────────────────────
gating:
  whitelist:
    - get_weather
    - get_time

  blacklist:
    - format_disk

  # Override specific combinations: "SOURCE:TOOL" -> "allow|log|block"
  overrides:
    "CONTENT_READ:send_email": "block"

#──────────────────────────────────────────────────────────────────────
# DASHBOARD
#──────────────────────────────────────────────────────────────────────
dashboard:
  enabled: true
  port: 8080

#──────────────────────────────────────────────────────────────────────
# LOGGING
#──────────────────────────────────────────────────────────────────────
logging:
  level: INFO
  retention_days: 30
  log_bodies: false

#──────────────────────────────────────────────────────────────────────
# LEARNING (v2)
#──────────────────────────────────────────────────────────────────────
learning:
  enabled: false
  baseline_days: 7
  anomaly_sensitivity: 5
```

**Acceptance Criteria:**
- [ ] Default config created on first run
- [ ] Invalid config shows helpful error
- [ ] Changes take effect after restart

---

## Technical Specifications

### Tech Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Python 3.11+ | Fast development, good async, ML ecosystem |
| Framework | FastAPI | Async, fast, built-in OpenAPI docs |
| Database | SQLite | Zero config, sufficient for local use |
| Frontend | HTML/CSS/JS | No build step, simple deployment |
| Config | YAML | Human-readable |
| Packaging | Docker + pip | Multiple deployment options |

### Project Structure

```
theron/
├── src/
│   └── theron/
│       ├── __init__.py
│       ├── main.py              # CLI entry point
│       ├── proxy/
│       │   ├── __init__.py
│       │   ├── server.py        # FastAPI proxy server
│       │   ├── anthropic.py     # Anthropic API handling
│       │   └── openai.py        # OpenAI API handling
│       ├── security/
│       │   ├── __init__.py
│       │   ├── tagger.py        # Input source tagging
│       │   ├── detector.py      # Prompt injection detection
│       │   ├── classifier.py    # Action risk classification
│       │   └── gating.py        # Policy enforcement
│       ├── storage/
│       │   ├── __init__.py
│       │   ├── database.py      # SQLite operations
│       │   └── models.py        # Data models
│       ├── dashboard/
│       │   ├── __init__.py
│       │   ├── api.py           # REST endpoints
│       │   └── websocket.py     # Live updates
│       ├── config.py            # Configuration management
│       └── patterns.py          # Detection patterns
├── static/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── tests/
│   ├── test_detector.py
│   ├── test_classifier.py
│   ├── test_gating.py
│   └── fixtures/
│       └── injection_samples.json
├── config/
│   └── default.yaml
├── Dockerfile
├── docker-compose.yaml
├── pyproject.toml
├── requirements.txt
└── README.md
```

### Database Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    request_id TEXT NOT NULL,
    agent_id TEXT,
    source_tag TEXT,
    threat_score INTEGER,
    injection_detected BOOLEAN DEFAULT FALSE,
    injection_patterns TEXT,
    tool_name TEXT,
    risk_tier INTEGER,
    action TEXT NOT NULL,
    block_reason TEXT,
    request_summary TEXT,
    response_summary TEXT,
    llm_provider TEXT,
    model TEXT
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_action ON events(action);

CREATE TABLE patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    category TEXT NOT NULL,
    weight INTEGER DEFAULT 10,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    source TEXT DEFAULT 'default',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE NOT NULL UNIQUE,
    total_requests INTEGER DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    injection_attempts INTEGER DEFAULT 0
);
```

### API Endpoints

**Proxy (port 8081):**
- `POST /v1/messages` — Anthropic API
- `POST /v1/chat/completions` — OpenAI API
- `GET /health` — Health check

**Dashboard (port 8080):**
- `GET /` — Dashboard UI
- `GET /api/events` — List events
- `GET /api/events/stream` — WebSocket live feed
- `GET /api/stats` — Statistics
- `GET /api/config` — Current config
- `PUT /api/config` — Update config

---

## Implementation Plan

### Week 1: Core Infrastructure

**Days 1-2:** Project setup, Dockerfile, README
**Days 3-4:** Proxy server (pass-through for both APIs)
**Days 5-7:** Detection engine with pattern matching

### Week 2: Security + UI

**Days 8-9:** Classification and gating
**Days 10-11:** Source tagging heuristics
**Days 12-13:** Dashboard (SQLite + simple UI)
**Day 14:** Polish, docs, ship

---

## Success Metrics

**MVP (2 weeks):**
- [ ] Works with any agent via env var
- [ ] Blocks 50+ injection patterns
- [ ] < 100ms latency
- [ ] Dashboard shows events

**Month 1:**
- [ ] 500+ GitHub stars
- [ ] < 3% false positive rate
- [ ] 3+ confirmed agent integrations

---

## Out of Scope (v1)

- VM sandboxing
- Cross-user threat intelligence
- Behavioral anomaly detection
- Cloud-hosted version

---

## Appendix: Known Injection Patterns

```
# Instruction Override
- "ignore (all )?(previous|prior|above) (instructions|context|rules)"
- "disregard (everything|all) (before|above)"
- "forget (what|everything) (you were told)"
- "new (instructions|rules|directive):"

# Role Injection
- "you are now (a|an|the)"
- "act as (if you are|a)"
- "pretend (to be|you are)"
- "enable (developer|debug|admin) mode"

# Delimiter Attacks
- "</?(system|user|assistant)>"
- "[INST]|[/INST]"
- "<|im_start|>|<|im_end|>"
- "```(system|prompt|instruction)"

# Exfiltration
- "send (to|all) .*@"
- "forward (to|all)"
- "post (to|on) (pastebin|gist)"

# Dangerous Commands
- "(rm|del) (-rf?\s+)?[/~]"
- "curl .* \| (ba)?sh"
- "(eval|exec)\s*\("
```

---

## References

- Moltbot security incidents (January 2026)
- Simon Willison's prompt injection research
- OWASP LLM Top 10
- CVE-2025-49596, CVE-2025-6514, CVE-2025-52882
