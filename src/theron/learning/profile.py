"""Agent profile management for Theron.

This module re-exports from baseline for convenience.
The main AgentProfile class is defined in baseline.py.
"""

from .baseline import AgentProfile, BaselineManager

__all__ = ["AgentProfile", "BaselineManager"]
