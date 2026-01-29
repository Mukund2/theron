"""Modular registry for AI agents.

Agents can be defined in:
1. Built-in defaults (shipped with Theron)
2. User-defined YAML files in ~/.theron/agents/
3. Project-local .theron/agents/ directory

This allows anyone to add support for new agents without modifying code.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml


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

    # Source of this definition
    source: str = "builtin"

    @classmethod
    def from_dict(cls, data: dict, source: str = "unknown") -> "AgentInfo":
        """Create AgentInfo from a dictionary (e.g., parsed YAML)."""
        # Handle risk_level as string
        risk_level = data.get("risk_level", "high")
        if isinstance(risk_level, str):
            risk_level = AgentRiskLevel(risk_level.lower())

        return cls(
            name=data["name"],
            description=data.get("description", ""),
            risk_level=risk_level,
            homepage=data.get("homepage", ""),
            install_methods=data.get("install_methods", []),
            capabilities=data.get("capabilities", []),
            api_env_vars=data.get("api_env_vars", {}),
            recommended_config=data.get("recommended_config", {}),
            warnings=data.get("warnings", []),
            install_commands=data.get("install_commands", {}),
            run_command=data.get("run_command"),
            source=source,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "homepage": self.homepage,
            "install_methods": self.install_methods,
            "capabilities": self.capabilities,
            "api_env_vars": self.api_env_vars,
            "recommended_config": self.recommended_config,
            "warnings": self.warnings,
            "install_commands": self.install_commands,
            "run_command": self.run_command,
        }


# Built-in agent definitions (defaults)
BUILTIN_AGENTS: list[dict] = [
    {
        "name": "Claude Code",
        "description": "Anthropic's official CLI for Claude - coding assistant with shell access",
        "risk_level": "high",
        "homepage": "https://github.com/anthropics/claude-code",
        "install_methods": ["npm"],
        "capabilities": [
            "Execute shell commands",
            "Read and write files",
            "Browse the web",
            "Run code in any language",
        ],
        "api_env_vars": {
            "ANTHROPIC_API_URL": "http://localhost:8081",
        },
        "recommended_config": {
            "classification": {"unknown_tool_tier": 3},
        },
        "warnings": [
            "Claude Code can execute arbitrary shell commands",
            "It has full access to your file system",
            "Use in a VM or container for maximum safety",
        ],
        "install_commands": {
            "npm": "npm install -g @anthropic-ai/claude-code",
        },
        "run_command": "claude",
    },
    {
        "name": "Aider",
        "description": "AI pair programming tool that edits code in your local git repo",
        "risk_level": "high",
        "homepage": "https://aider.chat",
        "install_methods": ["pip"],
        "capabilities": [
            "Edit files in your repository",
            "Run shell commands",
            "Create and modify code",
            "Git operations",
        ],
        "api_env_vars": {
            "ANTHROPIC_API_URL": "http://localhost:8081",
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        "warnings": [
            "Aider can modify any file in your repository",
            "Always use git to review changes before committing",
        ],
        "install_commands": {
            "pip": "pip install aider-chat",
        },
        "run_command": "aider",
    },
    {
        "name": "Open Interpreter",
        "description": "Natural language interface to your computer's capabilities",
        "risk_level": "critical",
        "homepage": "https://openinterpreter.com",
        "install_methods": ["pip"],
        "capabilities": [
            "Execute any code (Python, JavaScript, Shell, etc.)",
            "Full file system access",
            "Install packages",
            "Control applications",
            "Access the internet",
        ],
        "api_env_vars": {
            "ANTHROPIC_API_URL": "http://localhost:8081",
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        "warnings": [
            "⚠️  Open Interpreter has FULL computer access",
            "It can run any code in any language",
            "Use --safe-mode flag for restricted execution",
            "RECOMMENDED: Run in a VM or container",
        ],
        "install_commands": {
            "pip": "pip install open-interpreter",
        },
        "run_command": "interpreter",
    },
    {
        "name": "AutoGPT",
        "description": "Autonomous AI agent that chains thoughts to accomplish goals",
        "risk_level": "critical",
        "homepage": "https://github.com/Significant-Gravitas/AutoGPT",
        "install_methods": ["docker", "git"],
        "capabilities": [
            "Autonomous goal pursuit",
            "Web browsing and research",
            "File operations",
            "Code execution",
            "Long-running tasks",
        ],
        "api_env_vars": {
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        "warnings": [
            "⚠️  AutoGPT runs AUTONOMOUSLY toward goals",
            "It will take actions without asking permission",
            "STRONGLY RECOMMENDED: Set spending limits",
            "STRONGLY RECOMMENDED: Run in isolated environment",
        ],
        "install_commands": {
            "git": "git clone https://github.com/Significant-Gravitas/AutoGPT.git && cd AutoGPT && pip install -r requirements.txt",
            "docker": "docker pull significantgravitas/auto-gpt",
        },
        "run_command": "python -m autogpt",
    },
]


class AgentRegistry:
    """Registry for looking up agent information.

    Loads agents from:
    1. Built-in defaults
    2. User directory: ~/.theron/agents/*.yaml
    3. Project directory: .theron/agents/*.yaml
    """

    def __init__(self, load_external: bool = True):
        self._agents: dict[str, AgentInfo] = {}

        # Load built-in agents
        for agent_data in BUILTIN_AGENTS:
            agent = AgentInfo.from_dict(agent_data, source="builtin")
            self._add_agent(agent)

        # Load external agent definitions
        if load_external:
            self._load_external_agents()

    def _add_agent(self, agent: AgentInfo) -> None:
        """Add an agent to the registry."""
        key = self._normalize_name(agent.name)
        self._agents[key] = agent

    def _normalize_name(self, name: str) -> str:
        """Normalize agent name for lookup."""
        return name.lower().replace("-", "").replace("_", "").replace(" ", "")

    def _load_external_agents(self) -> None:
        """Load agent definitions from external YAML files."""
        # User-level agents: ~/.theron/agents/
        user_dir = Path.home() / ".theron" / "agents"
        self._load_from_directory(user_dir, "user")

        # Project-level agents: .theron/agents/
        project_dir = Path.cwd() / ".theron" / "agents"
        self._load_from_directory(project_dir, "project")

    def _load_from_directory(self, directory: Path, source: str) -> None:
        """Load all YAML files from a directory."""
        if not directory.exists():
            return

        for file_path in directory.glob("*.yaml"):
            try:
                self._load_agent_file(file_path, source)
            except Exception as e:
                print(f"Warning: Failed to load {file_path}: {e}")

        for file_path in directory.glob("*.yml"):
            try:
                self._load_agent_file(file_path, source)
            except Exception as e:
                print(f"Warning: Failed to load {file_path}: {e}")

    def _load_agent_file(self, file_path: Path, source: str) -> None:
        """Load a single agent definition file."""
        with open(file_path) as f:
            data = yaml.safe_load(f)

        if not data:
            return

        # File can contain single agent or list of agents
        if isinstance(data, list):
            for agent_data in data:
                agent = AgentInfo.from_dict(agent_data, source=f"{source}:{file_path.name}")
                self._add_agent(agent)
        else:
            agent = AgentInfo.from_dict(data, source=f"{source}:{file_path.name}")
            self._add_agent(agent)

    def get(self, name: str) -> Optional[AgentInfo]:
        """Get agent info by name (case-insensitive, flexible matching)."""
        normalized = self._normalize_name(name)

        # Direct lookup
        if normalized in self._agents:
            return self._agents[normalized]

        # Fuzzy match on display name
        for agent in self._agents.values():
            if self._normalize_name(agent.name) == normalized:
                return agent

        return None

    def list_all(self) -> list[AgentInfo]:
        """List all known agents."""
        return list(self._agents.values())

    def search(self, query: str) -> list[AgentInfo]:
        """Search agents by name or description."""
        query_lower = query.lower()
        results = []
        for agent in self._agents.values():
            if (query_lower in agent.name.lower() or
                query_lower in agent.description.lower()):
                results.append(agent)
        return results

    def add_agent(self, agent: AgentInfo) -> None:
        """Add an agent to the registry at runtime."""
        self._add_agent(agent)

    def save_agent(self, agent: AgentInfo, user_level: bool = True) -> Path:
        """Save an agent definition to a YAML file.

        Args:
            agent: Agent to save
            user_level: If True, save to ~/.theron/agents/, else .theron/agents/

        Returns:
            Path to the saved file
        """
        if user_level:
            directory = Path.home() / ".theron" / "agents"
        else:
            directory = Path.cwd() / ".theron" / "agents"

        directory.mkdir(parents=True, exist_ok=True)

        filename = agent.name.lower().replace(" ", "-") + ".yaml"
        file_path = directory / filename

        with open(file_path, "w") as f:
            yaml.dump(agent.to_dict(), f, default_flow_style=False, sort_keys=False)

        return file_path


def create_agent_template(name: str) -> dict:
    """Create a template for a new agent definition."""
    return {
        "name": name,
        "description": "Description of what this agent does",
        "risk_level": "high",  # low, medium, high, critical
        "homepage": "https://github.com/...",
        "install_methods": ["pip"],  # pip, npm, docker, git, etc.
        "capabilities": [
            "List what this agent can do",
            "Each capability on its own line",
        ],
        "api_env_vars": {
            "ANTHROPIC_API_URL": "http://localhost:8081",
            "OPENAI_API_BASE": "http://localhost:8081/v1",
        },
        "recommended_config": {
            "detection": {"sensitivity": 5},
            "classification": {"unknown_tool_tier": 3},
        },
        "warnings": [
            "Important warnings for users",
            "Security considerations",
        ],
        "install_commands": {
            "pip": "pip install agent-name",
        },
        "run_command": "agent-name",
    }
