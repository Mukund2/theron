"""Agent installation and management for Theron.

Helps non-technical users safely install and run autonomous AI agents
with Theron protection automatically configured.
"""

from .registry import AgentRegistry, AgentInfo
from .installer import AgentInstaller
from .runner import AgentRunner

__all__ = ["AgentRegistry", "AgentInfo", "AgentInstaller", "AgentRunner"]
