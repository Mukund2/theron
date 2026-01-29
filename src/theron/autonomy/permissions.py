"""Task-scoped tool permissions for autonomous agents.

Implements the Principle of Least Authority (POLA) by dynamically restricting
tool access based on inferred task intent. When user says "reply to this email",
the agent gets email tools but NOT shell access.

This addresses the key problem identified in research: AI agents typically have
uniform access to ALL tools, violating least-privilege principles.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
from uuid import uuid4


class TaskScope(Enum):
    """Types of tasks with associated tool permissions."""

    CODING = "coding"
    RESEARCH = "research"
    COMMUNICATION = "communication"
    FILE_MANAGEMENT = "file_management"
    DATA_ANALYSIS = "data_analysis"
    SYSTEM_ADMIN = "system_admin"
    UNKNOWN = "unknown"


@dataclass
class ToolCapability:
    """A time-limited capability to use a specific tool."""

    capability_id: str
    tool_name: str
    request_id: str
    task_scope: TaskScope
    granted_at: datetime
    expires_at: datetime
    max_uses: Optional[int] = None  # None = unlimited
    uses_remaining: Optional[int] = None
    restrictions: dict = field(default_factory=dict)  # e.g., {"path_prefix": "/tmp"}

    @property
    def is_valid(self) -> bool:
        """Check if capability is still valid."""
        if datetime.utcnow() > self.expires_at:
            return False
        if self.uses_remaining is not None and self.uses_remaining <= 0:
            return False
        return True

    def use(self) -> bool:
        """Use the capability once. Returns False if invalid."""
        if not self.is_valid:
            return False
        if self.uses_remaining is not None:
            self.uses_remaining -= 1
        return True


class PermissionDecision(Enum):
    """Decision for tool permission check."""

    ALLOW = "allow"          # Tool is within scope
    WARN = "warn"            # Tool is unusual but allowed with logging
    DENY_SOFT = "deny_soft"  # Block but could be overridden
    DENY_HARD = "deny_hard"  # Never allowed for this task


@dataclass
class PermissionResult:
    """Result of a permission check."""

    decision: PermissionDecision
    reason: str
    task_scope: TaskScope
    expected_tools: list[str]
    capability: Optional[ToolCapability] = None
    alternative_suggestion: Optional[str] = None


# Task-to-tool mappings with permission levels
# Each tool has: (permission_level, restrictions)
# Permission levels: "core" (essential), "allowed" (normal), "unusual" (warn), "forbidden" (deny)
TASK_TOOL_PERMISSIONS = {
    TaskScope.CODING: {
        # Core tools - always allowed
        "read_file": ("core", {}),
        "write_file": ("core", {}),
        "edit_file": ("core", {}),
        "create_file": ("core", {}),
        "list_directory": ("core", {}),
        "search_code": ("core", {}),
        "search_files": ("core", {}),
        "git_status": ("core", {}),
        "git_diff": ("core", {}),
        "git_commit": ("core", {}),
        "git_add": ("core", {}),

        # Allowed tools - normal for coding
        "execute_shell": ("allowed", {"dangerous_commands_blocked": True}),
        "run_command": ("allowed", {"dangerous_commands_blocked": True}),
        "bash": ("allowed", {"dangerous_commands_blocked": True}),
        "run_tests": ("allowed", {}),
        "lint_code": ("allowed", {}),
        "format_code": ("allowed", {}),
        "install_package": ("allowed", {}),
        "git_push": ("allowed", {}),
        "git_pull": ("allowed", {}),

        # Unusual - allowed but logged with warning
        "fetch_url": ("unusual", {}),
        "search_web": ("unusual", {}),

        # Forbidden - never allowed for coding tasks
        "send_email": ("forbidden", {}),
        "send_message": ("forbidden", {}),
        "transfer_funds": ("forbidden", {}),
        "delete_database": ("forbidden", {}),
    },

    TaskScope.RESEARCH: {
        # Core tools
        "search_web": ("core", {}),
        "fetch_url": ("core", {}),
        "browse_web": ("core", {}),
        "read_file": ("core", {}),
        "read_docs": ("core", {}),

        # Allowed
        "list_directory": ("allowed", {}),
        "search_files": ("allowed", {}),
        "search_code": ("allowed", {}),

        # Unusual
        "write_file": ("unusual", {"reason": "Research usually doesn't write files"}),

        # Forbidden
        "execute_shell": ("forbidden", {}),
        "send_email": ("forbidden", {}),
        "delete_file": ("forbidden", {}),
        "transfer_funds": ("forbidden", {}),
    },

    TaskScope.COMMUNICATION: {
        # Core tools
        "send_email": ("core", {}),
        "send_message": ("core", {}),
        "read_email": ("core", {}),
        "list_emails": ("core", {}),
        "post_slack": ("core", {}),
        "post_discord": ("core", {}),

        # Allowed
        "read_file": ("allowed", {"reason": "May need to attach files"}),
        "list_directory": ("allowed", {}),
        "search_files": ("allowed", {}),

        # Unusual
        "write_file": ("unusual", {}),
        "fetch_url": ("unusual", {}),

        # Forbidden - communication tasks should NEVER have shell access
        "execute_shell": ("forbidden", {}),
        "bash": ("forbidden", {}),
        "run_command": ("forbidden", {}),
        "delete_file": ("forbidden", {}),
        "transfer_funds": ("forbidden", {}),
    },

    TaskScope.FILE_MANAGEMENT: {
        # Core tools
        "read_file": ("core", {}),
        "write_file": ("core", {}),
        "delete_file": ("core", {}),
        "move_file": ("core", {}),
        "copy_file": ("core", {}),
        "list_directory": ("core", {}),
        "create_directory": ("core", {}),
        "rename_file": ("core", {}),
        "find_files": ("core", {}),

        # Allowed
        "search_files": ("allowed", {}),
        "execute_shell": ("allowed", {"commands_allowed": ["ls", "find", "du", "df"]}),

        # Forbidden
        "send_email": ("forbidden", {}),
        "transfer_funds": ("forbidden", {}),
        "search_web": ("forbidden", {}),
    },

    TaskScope.DATA_ANALYSIS: {
        # Core tools
        "read_file": ("core", {}),
        "write_file": ("core", {}),
        "list_directory": ("core", {}),
        "run_python": ("core", {}),
        "execute_shell": ("core", {"dangerous_commands_blocked": True}),
        "query_database": ("core", {"read_only": True}),
        "fetch_data": ("core", {}),
        "plot_chart": ("core", {}),

        # Allowed
        "search_files": ("allowed", {}),
        "fetch_url": ("allowed", {}),

        # Forbidden
        "send_email": ("forbidden", {}),
        "delete_database": ("forbidden", {}),
        "transfer_funds": ("forbidden", {}),
    },

    TaskScope.SYSTEM_ADMIN: {
        # This is the highest privilege scope - still has restrictions
        "execute_shell": ("core", {}),
        "run_command": ("core", {}),
        "bash": ("core", {}),
        "read_file": ("core", {}),
        "write_file": ("core", {}),
        "list_directory": ("core", {}),
        "install_package": ("core", {}),
        "configure_system": ("core", {}),
        "check_status": ("core", {}),

        # Even system admin tasks shouldn't do financial operations
        "transfer_funds": ("forbidden", {}),
        "send_payment": ("forbidden", {}),
    },

    TaskScope.UNKNOWN: {
        # Default restrictive permissions for unknown tasks
        "read_file": ("allowed", {}),
        "list_directory": ("allowed", {}),
        "search_files": ("allowed", {}),
        "search_web": ("allowed", {}),

        # Everything else is unusual or forbidden
        "write_file": ("unusual", {}),
        "execute_shell": ("forbidden", {}),
        "send_email": ("forbidden", {}),
        "delete_file": ("forbidden", {}),
        "transfer_funds": ("forbidden", {}),
    },
}

# Tools that are ALWAYS forbidden regardless of task
ALWAYS_FORBIDDEN_TOOLS = {
    "transfer_funds",
    "send_payment",
    "wire_transfer",
    "delete_all",
    "format_disk",
    "drop_database",
    "rm_rf_root",
    "install_backdoor",
    "reverse_shell",
    "keylogger",
    "credential_dump",
}

# Keywords for task inference
TASK_KEYWORDS = {
    TaskScope.CODING: [
        "code", "implement", "fix", "bug", "function", "class", "method",
        "test", "refactor", "debug", "compile", "build", "deploy", "git",
        "commit", "branch", "merge", "lint", "format", "programming",
        "develop", "software", "app", "api", "backend", "frontend",
    ],
    TaskScope.RESEARCH: [
        "search", "find", "look up", "research", "learn", "understand",
        "explore", "investigate", "analyze", "documentation", "docs",
        "what is", "how does", "explain", "information about", "tell me about",
    ],
    TaskScope.COMMUNICATION: [
        "email", "message", "send", "reply", "respond", "contact", "notify",
        "slack", "discord", "teams", "chat", "communicate", "forward",
        "write to", "tell them", "let them know", "reach out",
    ],
    TaskScope.FILE_MANAGEMENT: [
        "file", "folder", "directory", "move", "copy", "delete", "rename",
        "organize", "backup", "archive", "compress", "zip", "unzip",
        "clean up", "sort", "arrange",
    ],
    TaskScope.DATA_ANALYSIS: [
        "data", "analyze", "chart", "graph", "statistics", "csv", "excel",
        "json", "database", "query", "aggregate", "visualize", "report",
        "summary", "metrics", "dashboard", "plot",
    ],
    TaskScope.SYSTEM_ADMIN: [
        "install", "configure", "setup", "server", "system", "service",
        "process", "permission", "user", "admin", "deploy", "docker",
        "kubernetes", "nginx", "apache", "systemd", "cron",
    ],
}


class PermissionManager:
    """Manages task-scoped tool permissions for autonomous agents."""

    def __init__(self, db=None, default_capability_ttl: int = 3600):
        """Initialize the permission manager.

        Args:
            db: Optional database for persistence
            default_capability_ttl: Default time-to-live for capabilities in seconds
        """
        self.db = db
        self.default_capability_ttl = default_capability_ttl

        # Active capabilities per request: request_id -> {tool_name -> ToolCapability}
        self._capabilities: dict[str, dict[str, ToolCapability]] = {}

        # Inferred task scopes per request
        self._task_scopes: dict[str, TaskScope] = {}

        # Permission check history for auditing
        self._check_history: dict[str, list[PermissionResult]] = {}

    def infer_task_scope(
        self,
        request_id: str,
        conversation: list[dict],
    ) -> TaskScope:
        """Infer the task scope from conversation.

        Args:
            request_id: Request identifier
            conversation: Conversation messages

        Returns:
            Inferred TaskScope
        """
        # Extract user messages
        user_text = ""
        for msg in conversation:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(
                        c.get("text", "") for c in content if isinstance(c, dict)
                    )
                user_text += " " + content.lower()

        if not user_text.strip():
            self._task_scopes[request_id] = TaskScope.UNKNOWN
            return TaskScope.UNKNOWN

        # Score each task type
        scores: dict[TaskScope, float] = {}
        for task_scope, keywords in TASK_KEYWORDS.items():
            score = sum(1.0 for kw in keywords if kw in user_text)
            scores[task_scope] = score

        # Find best match
        if not any(scores.values()):
            self._task_scopes[request_id] = TaskScope.UNKNOWN
            return TaskScope.UNKNOWN

        best_scope = max(scores.keys(), key=lambda k: scores[k])

        # Require minimum confidence
        if scores[best_scope] < 2:
            self._task_scopes[request_id] = TaskScope.UNKNOWN
            return TaskScope.UNKNOWN

        self._task_scopes[request_id] = best_scope
        return best_scope

    def get_task_scope(self, request_id: str) -> TaskScope:
        """Get the task scope for a request."""
        return self._task_scopes.get(request_id, TaskScope.UNKNOWN)

    def grant_capability(
        self,
        request_id: str,
        tool_name: str,
        ttl_seconds: Optional[int] = None,
        max_uses: Optional[int] = None,
        restrictions: Optional[dict] = None,
    ) -> ToolCapability:
        """Grant a capability to use a tool.

        Args:
            request_id: Request identifier
            tool_name: Tool to grant access to
            ttl_seconds: Time-to-live in seconds (None = default)
            max_uses: Maximum number of uses (None = unlimited)
            restrictions: Additional restrictions

        Returns:
            Granted ToolCapability
        """
        task_scope = self._task_scopes.get(request_id, TaskScope.UNKNOWN)
        ttl = ttl_seconds or self.default_capability_ttl

        capability = ToolCapability(
            capability_id=str(uuid4()),
            tool_name=tool_name.lower(),
            request_id=request_id,
            task_scope=task_scope,
            granted_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=ttl),
            max_uses=max_uses,
            uses_remaining=max_uses,
            restrictions=restrictions or {},
        )

        if request_id not in self._capabilities:
            self._capabilities[request_id] = {}

        self._capabilities[request_id][tool_name.lower()] = capability
        return capability

    def check_permission(
        self,
        request_id: str,
        tool_name: str,
        args: Optional[dict] = None,
    ) -> PermissionResult:
        """Check if a tool is permitted for this request's task scope.

        Args:
            request_id: Request identifier
            tool_name: Tool being called
            args: Tool arguments (for restriction checking)

        Returns:
            PermissionResult with decision
        """
        tool_lower = tool_name.lower()
        task_scope = self._task_scopes.get(request_id, TaskScope.UNKNOWN)

        # Check always-forbidden tools first
        if tool_lower in ALWAYS_FORBIDDEN_TOOLS:
            result = PermissionResult(
                decision=PermissionDecision.DENY_HARD,
                reason=f"Tool '{tool_name}' is always forbidden (security risk)",
                task_scope=task_scope,
                expected_tools=self._get_expected_tools(task_scope),
            )
            self._log_check(request_id, result)
            return result

        # Check if explicit capability was granted
        request_caps = self._capabilities.get(request_id, {})
        if tool_lower in request_caps:
            cap = request_caps[tool_lower]
            if cap.is_valid:
                # Check restrictions
                if args and not self._check_restrictions(cap.restrictions, args):
                    result = PermissionResult(
                        decision=PermissionDecision.DENY_SOFT,
                        reason=f"Tool '{tool_name}' arguments violate restrictions",
                        task_scope=task_scope,
                        expected_tools=self._get_expected_tools(task_scope),
                        capability=cap,
                    )
                else:
                    cap.use()
                    result = PermissionResult(
                        decision=PermissionDecision.ALLOW,
                        reason=f"Explicit capability granted for '{tool_name}'",
                        task_scope=task_scope,
                        expected_tools=self._get_expected_tools(task_scope),
                        capability=cap,
                    )
                self._log_check(request_id, result)
                return result

        # Check task-based permissions
        task_permissions = TASK_TOOL_PERMISSIONS.get(task_scope, {})

        # Direct match
        if tool_lower in task_permissions:
            level, restrictions = task_permissions[tool_lower]
            return self._make_decision(
                request_id, tool_name, task_scope, level, restrictions, args
            )

        # Partial match (e.g., "execute_shell" matches "shell")
        for perm_tool, (level, restrictions) in task_permissions.items():
            if perm_tool in tool_lower or tool_lower in perm_tool:
                return self._make_decision(
                    request_id, tool_name, task_scope, level, restrictions, args
                )

        # Tool not in task permissions - deny by default
        result = PermissionResult(
            decision=PermissionDecision.DENY_SOFT,
            reason=f"Tool '{tool_name}' not permitted for {task_scope.value} tasks",
            task_scope=task_scope,
            expected_tools=self._get_expected_tools(task_scope),
            alternative_suggestion=self._suggest_alternative(tool_lower, task_scope),
        )
        self._log_check(request_id, result)
        return result

    def _make_decision(
        self,
        request_id: str,
        tool_name: str,
        task_scope: TaskScope,
        level: str,
        restrictions: dict,
        args: Optional[dict],
    ) -> PermissionResult:
        """Make a permission decision based on level."""
        tool_lower = tool_name.lower()

        # Check restrictions if args provided
        if args and restrictions:
            if not self._check_restrictions(restrictions, args):
                result = PermissionResult(
                    decision=PermissionDecision.DENY_SOFT,
                    reason=f"Tool '{tool_name}' arguments violate task restrictions",
                    task_scope=task_scope,
                    expected_tools=self._get_expected_tools(task_scope),
                )
                self._log_check(request_id, result)
                return result

        if level == "core":
            result = PermissionResult(
                decision=PermissionDecision.ALLOW,
                reason=f"Tool '{tool_name}' is core for {task_scope.value} tasks",
                task_scope=task_scope,
                expected_tools=self._get_expected_tools(task_scope),
            )
        elif level == "allowed":
            result = PermissionResult(
                decision=PermissionDecision.ALLOW,
                reason=f"Tool '{tool_name}' is allowed for {task_scope.value} tasks",
                task_scope=task_scope,
                expected_tools=self._get_expected_tools(task_scope),
            )
        elif level == "unusual":
            result = PermissionResult(
                decision=PermissionDecision.WARN,
                reason=f"Tool '{tool_name}' is unusual for {task_scope.value} tasks",
                task_scope=task_scope,
                expected_tools=self._get_expected_tools(task_scope),
            )
        else:  # forbidden
            result = PermissionResult(
                decision=PermissionDecision.DENY_HARD,
                reason=f"Tool '{tool_name}' is forbidden for {task_scope.value} tasks",
                task_scope=task_scope,
                expected_tools=self._get_expected_tools(task_scope),
                alternative_suggestion=self._suggest_alternative(tool_lower, task_scope),
            )

        self._log_check(request_id, result)
        return result

    def _check_restrictions(self, restrictions: dict, args: dict) -> bool:
        """Check if args comply with restrictions."""
        args_str = str(args).lower()

        # Check for dangerous commands if blocked
        if restrictions.get("dangerous_commands_blocked"):
            dangerous = ["rm -rf", "dd if=", "mkfs", "> /dev/", "chmod 777", ":(){ :|:& };:"]
            if any(d in args_str for d in dangerous):
                return False

        # Check allowed commands list
        if "commands_allowed" in restrictions:
            allowed = restrictions["commands_allowed"]
            cmd = args.get("command", args.get("cmd", ""))
            if not any(cmd.startswith(a) for a in allowed):
                return False

        # Check read-only for database
        if restrictions.get("read_only"):
            write_keywords = ["insert", "update", "delete", "drop", "create", "alter"]
            if any(kw in args_str for kw in write_keywords):
                return False

        # Check path prefix
        if "path_prefix" in restrictions:
            path = args.get("path", args.get("file", args.get("file_path", "")))
            if not path.startswith(restrictions["path_prefix"]):
                return False

        return True

    def _get_expected_tools(self, task_scope: TaskScope) -> list[str]:
        """Get list of expected tools for a task scope."""
        permissions = TASK_TOOL_PERMISSIONS.get(task_scope, {})
        return [
            tool for tool, (level, _) in permissions.items()
            if level in ("core", "allowed")
        ]

    def _suggest_alternative(self, tool: str, task_scope: TaskScope) -> Optional[str]:
        """Suggest an alternative tool that IS allowed."""
        # Map forbidden tools to alternatives
        alternatives = {
            "execute_shell": "Consider using task-specific tools instead",
            "send_email": "This task doesn't require email access",
            "delete_file": "File deletion not permitted for this task",
            "transfer_funds": "Financial operations are never allowed",
        }
        return alternatives.get(tool)

    def _log_check(self, request_id: str, result: PermissionResult) -> None:
        """Log permission check for auditing."""
        if request_id not in self._check_history:
            self._check_history[request_id] = []
        self._check_history[request_id].append(result)

    def get_permission_history(self, request_id: str) -> list[PermissionResult]:
        """Get permission check history for a request."""
        return self._check_history.get(request_id, [])

    def get_denied_count(self, request_id: str) -> int:
        """Get count of denied permissions for a request."""
        history = self._check_history.get(request_id, [])
        return sum(
            1 for r in history
            if r.decision in (PermissionDecision.DENY_SOFT, PermissionDecision.DENY_HARD)
        )

    def clear_request(self, request_id: str) -> None:
        """Clear all data for a request."""
        self._capabilities.pop(request_id, None)
        self._task_scopes.pop(request_id, None)
        self._check_history.pop(request_id, None)

    def get_scope_summary(self, request_id: str) -> dict:
        """Get summary of permissions for a request."""
        task_scope = self._task_scopes.get(request_id, TaskScope.UNKNOWN)
        history = self._check_history.get(request_id, [])

        return {
            "task_scope": task_scope.value,
            "expected_tools": self._get_expected_tools(task_scope),
            "checks_performed": len(history),
            "allowed": sum(1 for r in history if r.decision == PermissionDecision.ALLOW),
            "warned": sum(1 for r in history if r.decision == PermissionDecision.WARN),
            "denied": sum(1 for r in history if r.decision in (
                PermissionDecision.DENY_SOFT, PermissionDecision.DENY_HARD
            )),
            "capabilities_granted": len(self._capabilities.get(request_id, {})),
        }


# Global permission manager instance
_permission_manager: Optional[PermissionManager] = None


def get_permission_manager(db=None) -> PermissionManager:
    """Get the global permission manager instance."""
    global _permission_manager
    if _permission_manager is None:
        _permission_manager = PermissionManager(db)
    return _permission_manager


def reset_permission_manager() -> None:
    """Reset the global permission manager."""
    global _permission_manager
    _permission_manager = None
