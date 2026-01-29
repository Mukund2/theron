"""Registry of known AI agents with installation and safety info."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AgentRiskLevel(str, Enum):
    """Risk level of an agent based on its capabilities."""
    LOW = "low"           # Read-only, no tool use
    MEDIUM = "medium"     # Limited tool use, sandboxed
    HIGH = "high"         # Shell access, file system access
    CRITICAL = "critical" # Full system access, network, autonomous


@dataclass
class AgentInfo:
    """Information about an AI agent."""

    name: str
    description: str
    risk_level: AgentRiskLevel
    homepage: str
    install_methods: list[str]  # pip, npm, docker, git, etc.

    # What this agent can do
    capabilities: list[str] = field(default_factory=list)

    # Environment variables to route through Theron
    api_env_vars: dict[str, str] = field(default_factory=dict)

    # Recommended Theron settings for this agent
    recommended_config: dict = field(default_factory=dict)

    # Warnings to show user
    warnings: list[str] = field(default_factory=list)

    # Install command templates
    install_commands: dict[str, str] = field(default_factory=dict)

    # Run command template
    run_command: Optional[str] = None


# Registry of known agents
KNOWN_AGENTS: dict[str, AgentInfo] = {
    "claude-code": AgentInfo(
        name="Claude Code",
        description="Anthropic's official CLI for Claude - coding assistant with shell access",
        risk_level=AgentRiskLevel.HIGH,
        homepage="https://github.com/anthropics/claude-code",
        install_methods=["npm"],
        capabilities=[
            "Execute shell commands",
            "Read and write files",
            "Browse the web",
            "Run code in any language",
        ],
        api_env_vars={
            "ANTHROPIC_API_URL": "http://localhost:8081",
        },
        recommended_config={
            "classification": {"unknown_tool_tier": 3},
            "gating": {"blacklist": ["sudo", "rm -rf"]},
        },
        warnings=[
            "Claude Code can execute arbitrary shell commands",
            "It has full access to your file system",
            "Use in a VM or container for maximum safety",
        ],
        install_commands={
            "npm": "npm install -g @anthropic-ai/claude-code",
        },
        run_command="claude",
    ),

    "moltbot": AgentInfo(
        name="Moltbot",
        description="Fully autonomous AI agent that runs 24/7 without human supervision",
        risk_level=AgentRiskLevel.CRITICAL,
        homepage="https://github.com/moltbot/moltbot",
        install_methods=["pip", "docker"],
        capabilities=[
            "Execute shell commands autonomously",
            "Send emails and messages",
            "Access the internet",
            "Run continuously without human approval",
            "Make decisions independently",
        ],
        api_env_vars={
            "ANTHROPIC_API_URL": "http://localhost:8081",
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        recommended_config={
            "detection": {"sensitivity": 8, "injection_threshold": 50},
            "classification": {"unknown_tool_tier": 4},
            "gating": {
                "blacklist": ["sudo", "rm -rf", "curl -X POST", "wget"],
            },
        },
        warnings=[
            "⚠️  CRITICAL: Moltbot runs FULLY AUTONOMOUSLY",
            "It can take actions without asking for permission",
            "It runs 24/7 and makes independent decisions",
            "STRONGLY RECOMMENDED: Run in an isolated VM",
            "STRONGLY RECOMMENDED: Use network restrictions",
            "Do NOT give it access to production systems",
        ],
        install_commands={
            "pip": "pip install moltbot",
            "docker": "docker pull moltbot/moltbot:latest",
        },
        run_command="moltbot start",
    ),

    "aider": AgentInfo(
        name="Aider",
        description="AI pair programming tool that edits code in your local git repo",
        risk_level=AgentRiskLevel.HIGH,
        homepage="https://aider.chat",
        install_methods=["pip"],
        capabilities=[
            "Edit files in your repository",
            "Run shell commands",
            "Create and modify code",
            "Git operations",
        ],
        api_env_vars={
            "ANTHROPIC_API_URL": "http://localhost:8081",
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        recommended_config={
            "classification": {"unknown_tool_tier": 3},
        },
        warnings=[
            "Aider can modify any file in your repository",
            "Always use git to review changes before committing",
            "Consider using in a separate branch",
        ],
        install_commands={
            "pip": "pip install aider-chat",
        },
        run_command="aider",
    ),

    "open-interpreter": AgentInfo(
        name="Open Interpreter",
        description="Natural language interface to your computer's capabilities",
        risk_level=AgentRiskLevel.CRITICAL,
        homepage="https://openinterpreter.com",
        install_methods=["pip"],
        capabilities=[
            "Execute any code (Python, JavaScript, Shell, etc.)",
            "Full file system access",
            "Install packages",
            "Control applications",
            "Access the internet",
        ],
        api_env_vars={
            "ANTHROPIC_API_URL": "http://localhost:8081",
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        recommended_config={
            "detection": {"sensitivity": 8},
            "classification": {"unknown_tool_tier": 4},
        },
        warnings=[
            "⚠️  Open Interpreter has FULL computer access",
            "It can run any code in any language",
            "It can install software and modify system settings",
            "Use --safe-mode flag for restricted execution",
            "RECOMMENDED: Run in a VM or container",
        ],
        install_commands={
            "pip": "pip install open-interpreter",
        },
        run_command="interpreter",
    ),

    "autogpt": AgentInfo(
        name="AutoGPT",
        description="Autonomous AI agent that chains thoughts to accomplish goals",
        risk_level=AgentRiskLevel.CRITICAL,
        homepage="https://github.com/Significant-Gravitas/AutoGPT",
        install_methods=["git", "docker"],
        capabilities=[
            "Autonomous goal pursuit",
            "Web browsing and research",
            "File operations",
            "Code execution",
            "Long-running tasks",
        ],
        api_env_vars={
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        recommended_config={
            "detection": {"sensitivity": 9},
            "classification": {"unknown_tool_tier": 4},
        },
        warnings=[
            "⚠️  AutoGPT runs AUTONOMOUSLY toward goals",
            "It will take actions without asking permission",
            "Can run for extended periods",
            "STRONGLY RECOMMENDED: Set spending limits",
            "STRONGLY RECOMMENDED: Run in isolated environment",
        ],
        install_commands={
            "git": "git clone https://github.com/Significant-Gravitas/AutoGPT.git && cd AutoGPT && pip install -r requirements.txt",
            "docker": "docker pull significantgravitas/auto-gpt",
        },
        run_command="python -m autogpt",
    ),
}


class AgentRegistry:
    """Registry for looking up agent information."""

    def __init__(self):
        self._agents = KNOWN_AGENTS.copy()

    def get(self, name: str) -> Optional[AgentInfo]:
        """Get agent info by name (case-insensitive)."""
        name_lower = name.lower().replace("-", "").replace("_", "").replace(" ", "")
        for key, info in self._agents.items():
            key_normalized = key.lower().replace("-", "").replace("_", "")
            if key_normalized == name_lower:
                return info
            # Also check the display name
            name_normalized = info.name.lower().replace("-", "").replace("_", "").replace(" ", "")
            if name_normalized == name_lower:
                return info
        return None

    def list_all(self) -> list[AgentInfo]:
        """List all known agents."""
        return list(self._agents.values())

    def search(self, query: str) -> list[AgentInfo]:
        """Search agents by name or description."""
        query_lower = query.lower()
        results = []
        for info in self._agents.values():
            if (query_lower in info.name.lower() or
                query_lower in info.description.lower()):
                results.append(info)
        return results
