"""Autonomous security features for Theron.

This package contains features specifically designed for autonomous AI agents
operating without human supervision:

- Task-Scoped Permissions: Dynamic tool access based on inferred task intent
- Shadow Execution: Run actions in isolation, auto-commit/discard based on behavior
- Graceful Degradation: Automatically reduce autonomy when anomalies detected
"""

from .permissions import (
    TaskScope,
    ToolCapability,
    PermissionManager,
    get_permission_manager,
)
from .shadow import (
    ShadowExecutor,
    ShadowResult,
    CommitDecision,
)
from .degradation import (
    DegradationLevel,
    DegradationManager,
    get_degradation_manager,
)

__all__ = [
    "TaskScope",
    "ToolCapability",
    "PermissionManager",
    "get_permission_manager",
    "ShadowExecutor",
    "ShadowResult",
    "CommitDecision",
    "DegradationLevel",
    "DegradationManager",
    "get_degradation_manager",
]
