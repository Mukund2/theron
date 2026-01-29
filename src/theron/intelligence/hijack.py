"""Loop hijack detection for Theron.

Detects when an agent's autonomous loop gets redirected from its original task.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4


@dataclass
class InferredIntent:
    """Inferred intent from conversation analysis."""

    request_id: str
    primary_task: str  # coding, research, communication, file_management, data_analysis, system_admin
    expected_tools: list[str]
    keywords: list[str]
    confidence: float  # 0.0 to 1.0
    inferred_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class HijackAlert:
    """Alert for potential loop hijacking."""

    alert_id: str
    request_id: str
    severity: str  # low, medium, high, critical
    expected_task: str
    unexpected_tool: str
    drift_score: float  # 0.0 to 1.0
    evidence: dict
    detected_at: datetime = field(default_factory=datetime.utcnow)


# Task types and their expected tools
TASK_TOOL_MAP = {
    "coding": {
        "tools": [
            "read_file", "write_file", "edit_file", "create_file",
            "execute_shell", "run_command", "bash", "search_code",
            "list_directory", "git_commit", "git_push", "run_tests",
            "lint_code", "format_code", "install_package",
        ],
        "keywords": [
            "code", "implement", "fix", "bug", "function", "class",
            "test", "refactor", "debug", "compile", "build", "deploy",
            "git", "commit", "branch", "merge", "lint", "format",
        ],
    },
    "research": {
        "tools": [
            "search_web", "read_file", "fetch_url", "browse_web",
            "list_directory", "search_code", "read_docs",
        ],
        "keywords": [
            "search", "find", "look", "research", "learn", "understand",
            "explore", "investigate", "analyze", "read", "documentation",
            "what is", "how does", "explain",
        ],
    },
    "communication": {
        "tools": [
            "send_email", "send_message", "post_slack", "post_discord",
            "send_sms", "post_teams", "read_email", "list_emails",
        ],
        "keywords": [
            "email", "message", "send", "reply", "contact", "notify",
            "slack", "discord", "teams", "chat", "communicate",
        ],
    },
    "file_management": {
        "tools": [
            "read_file", "write_file", "delete_file", "move_file",
            "copy_file", "list_directory", "create_directory",
            "rename_file", "find_files",
        ],
        "keywords": [
            "file", "folder", "directory", "move", "copy", "delete",
            "rename", "organize", "backup", "archive", "compress",
        ],
    },
    "data_analysis": {
        "tools": [
            "read_file", "write_file", "execute_shell", "run_python",
            "query_database", "fetch_data", "plot_chart",
        ],
        "keywords": [
            "data", "analyze", "chart", "graph", "statistics", "csv",
            "json", "database", "query", "aggregate", "visualize",
            "report", "summary",
        ],
    },
    "system_admin": {
        "tools": [
            "execute_shell", "run_command", "bash", "sudo_execute",
            "install_package", "configure_system", "check_status",
            "read_file", "write_file", "list_directory",
        ],
        "keywords": [
            "install", "configure", "setup", "server", "system",
            "service", "process", "permission", "user", "admin",
            "deploy", "docker", "kubernetes",
        ],
    },
}

# Tools that are suspicious regardless of task
ALWAYS_SUSPICIOUS_TOOLS = {
    "transfer_funds": "financial",
    "send_payment": "financial",
    "bulk_delete": "destructive",
    "format_disk": "destructive",
    "drop_database": "destructive",
    "modify_firewall": "security",
    "add_user": "security",
    "change_password": "security",
    "install_backdoor": "security",
    "reverse_shell": "security",
}


class HijackDetector:
    """Detects potential hijacking of agent loops."""

    def __init__(self, db=None):
        """Initialize the hijack detector.

        Args:
            db: Optional database instance for persistence.
        """
        self.db = db
        # Track inferred intents per request
        self._intents: dict[str, InferredIntent] = {}
        # Track tool history per request for drift detection
        self._tool_history: dict[str, list[str]] = {}

    def infer_intent(
        self,
        request_id: str,
        conversation: list[dict],
    ) -> InferredIntent:
        """Analyze conversation to infer what the user actually wants.

        Args:
            request_id: Request identifier
            conversation: List of conversation messages

        Returns:
            InferredIntent with task classification
        """
        # Extract user messages (focus on early messages for original intent)
        user_messages = []
        for msg in conversation:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if isinstance(content, list):
                # Handle structured content
                content = " ".join(
                    c.get("text", "") for c in content if isinstance(c, dict)
                )
            if role == "user" and content:
                user_messages.append(content.lower())

        if not user_messages:
            # No user messages - can't infer intent
            intent = InferredIntent(
                request_id=request_id,
                primary_task="unknown",
                expected_tools=[],
                keywords=[],
                confidence=0.0,
            )
            self._intents[request_id] = intent
            return intent

        # Focus on the first few user messages (original intent)
        initial_messages = " ".join(user_messages[:3])

        # Score each task type
        task_scores: dict[str, float] = {}
        matched_keywords: dict[str, list[str]] = {}

        for task_type, task_info in TASK_TOOL_MAP.items():
            score = 0.0
            keywords_found = []

            for keyword in task_info["keywords"]:
                if keyword in initial_messages:
                    score += 1.0
                    keywords_found.append(keyword)

            task_scores[task_type] = score
            matched_keywords[task_type] = keywords_found

        # Find best matching task
        if not any(task_scores.values()):
            # No keywords matched - default to general
            best_task = "unknown"
            confidence = 0.3
            expected_tools = []
            keywords = []
        else:
            best_task = max(task_scores.keys(), key=lambda k: task_scores[k])
            max_score = task_scores[best_task]

            # Calculate confidence based on keyword matches
            confidence = min(max_score / 5.0, 1.0)

            expected_tools = TASK_TOOL_MAP[best_task]["tools"]
            keywords = matched_keywords[best_task]

        intent = InferredIntent(
            request_id=request_id,
            primary_task=best_task,
            expected_tools=expected_tools,
            keywords=keywords,
            confidence=confidence,
        )

        self._intents[request_id] = intent
        return intent

    def check_tool_alignment(
        self,
        request_id: str,
        tool_name: str,
        args: dict,
    ) -> Optional[HijackAlert]:
        """Check if a tool call aligns with inferred intent.

        Args:
            request_id: Request identifier
            tool_name: Name of the tool being called
            args: Arguments to the tool

        Returns:
            HijackAlert if misalignment detected, None otherwise
        """
        intent = self._intents.get(request_id)

        # Track tool usage
        if request_id not in self._tool_history:
            self._tool_history[request_id] = []
        self._tool_history[request_id].append(tool_name)

        # Check for always-suspicious tools
        if tool_name.lower() in ALWAYS_SUSPICIOUS_TOOLS:
            category = ALWAYS_SUSPICIOUS_TOOLS[tool_name.lower()]
            return HijackAlert(
                alert_id=str(uuid4()),
                request_id=request_id,
                severity="critical",
                expected_task=intent.primary_task if intent else "unknown",
                unexpected_tool=tool_name,
                drift_score=1.0,
                evidence={
                    "reason": f"Tool '{tool_name}' is inherently suspicious ({category})",
                    "category": category,
                    "args_preview": str(args)[:200],
                },
            )

        if not intent or intent.confidence < 0.3:
            # Low confidence intent - can't reliably detect drift
            return None

        # Normalize tool name for comparison
        tool_lower = tool_name.lower()

        # Check if tool is expected for the task
        expected_tools_lower = [t.lower() for t in intent.expected_tools]

        # Direct match
        if tool_lower in expected_tools_lower:
            return None

        # Partial match (e.g., "execute_shell" matches "shell")
        for expected in expected_tools_lower:
            if expected in tool_lower or tool_lower in expected:
                return None

        # Tool not expected - check if arguments relate to original keywords
        args_str = str(args).lower()
        keyword_matches = sum(1 for kw in intent.keywords if kw in args_str)

        if keyword_matches >= 2:
            # Arguments contain original keywords - might be related
            return None

        # Calculate drift score
        drift_score = self._calculate_drift(intent, tool_name, args)

        if drift_score < 0.4:
            # Drift not significant enough
            return None

        # Determine severity
        if drift_score >= 0.8:
            severity = "critical"
        elif drift_score >= 0.6:
            severity = "high"
        elif drift_score >= 0.4:
            severity = "medium"
        else:
            severity = "low"

        return HijackAlert(
            alert_id=str(uuid4()),
            request_id=request_id,
            severity=severity,
            expected_task=intent.primary_task,
            unexpected_tool=tool_name,
            drift_score=drift_score,
            evidence={
                "expected_tools": intent.expected_tools[:5],
                "original_keywords": intent.keywords[:10],
                "keyword_matches_in_args": keyword_matches,
                "args_preview": str(args)[:200],
                "tool_history": self._tool_history.get(request_id, [])[-5:],
            },
        )

    def _calculate_drift(
        self,
        intent: InferredIntent,
        tool_name: str,
        args: dict,
    ) -> float:
        """Calculate how far an action drifts from original intent.

        Args:
            intent: The inferred intent
            tool_name: Tool being called
            args: Tool arguments

        Returns:
            Drift score from 0.0 to 1.0
        """
        drift_factors = []

        # Factor 1: Tool unexpectedness (0.4 weight)
        # Check how different this tool is from expected tools
        tool_lower = tool_name.lower()
        expected_tools_lower = [t.lower() for t in intent.expected_tools]

        if tool_lower not in expected_tools_lower:
            # Check similarity to any expected tool
            similarity_scores = []
            for expected in expected_tools_lower:
                # Simple word overlap
                tool_words = set(tool_lower.replace("_", " ").split())
                expected_words = set(expected.replace("_", " ").split())
                overlap = len(tool_words & expected_words)
                total = len(tool_words | expected_words)
                similarity_scores.append(overlap / total if total > 0 else 0)

            max_similarity = max(similarity_scores) if similarity_scores else 0
            tool_drift = 1.0 - max_similarity
            drift_factors.append(tool_drift * 0.4)
        else:
            drift_factors.append(0.0)

        # Factor 2: Keyword mismatch (0.3 weight)
        args_str = str(args).lower()
        keyword_matches = sum(1 for kw in intent.keywords if kw in args_str)
        keyword_ratio = keyword_matches / len(intent.keywords) if intent.keywords else 0
        keyword_drift = 1.0 - keyword_ratio
        drift_factors.append(keyword_drift * 0.3)

        # Factor 3: Task category mismatch (0.3 weight)
        # Check if tool belongs to a different task category
        tool_task = None
        for task_type, task_info in TASK_TOOL_MAP.items():
            if any(tool_lower in t.lower() or t.lower() in tool_lower
                   for t in task_info["tools"]):
                tool_task = task_type
                break

        if tool_task and tool_task != intent.primary_task:
            # Tool belongs to a different task category
            category_drift = 0.8
        elif tool_task is None:
            # Unknown tool category
            category_drift = 0.5
        else:
            category_drift = 0.0

        drift_factors.append(category_drift * 0.3)

        return sum(drift_factors)

    def get_intent(self, request_id: str) -> Optional[InferredIntent]:
        """Get the inferred intent for a request.

        Args:
            request_id: Request identifier

        Returns:
            InferredIntent if exists
        """
        return self._intents.get(request_id)

    def get_tool_history(self, request_id: str) -> list[str]:
        """Get tool history for a request.

        Args:
            request_id: Request identifier

        Returns:
            List of tool names used
        """
        return self._tool_history.get(request_id, [])

    def get_drift_summary(self, request_id: str) -> dict:
        """Get summary of drift analysis for a request.

        Args:
            request_id: Request identifier

        Returns:
            Summary dictionary
        """
        intent = self._intents.get(request_id)
        tools = self._tool_history.get(request_id, [])

        if not intent:
            return {"has_intent": False}

        # Count unexpected tools
        expected_tools_lower = [t.lower() for t in intent.expected_tools]
        unexpected_count = sum(
            1 for t in tools
            if t.lower() not in expected_tools_lower
        )

        return {
            "has_intent": True,
            "primary_task": intent.primary_task,
            "confidence": intent.confidence,
            "total_tools_used": len(tools),
            "unexpected_tools": unexpected_count,
            "drift_ratio": unexpected_count / len(tools) if tools else 0,
            "keywords": intent.keywords[:5],
        }

    def clear_request(self, request_id: str) -> None:
        """Clear tracking data for a request.

        Args:
            request_id: Request to clear
        """
        self._intents.pop(request_id, None)
        self._tool_history.pop(request_id, None)

    async def persist_alert(self, alert: HijackAlert) -> None:
        """Persist a hijack alert to database.

        Args:
            alert: Alert to persist
        """
        if not self.db:
            return

        from ..storage.models import AlertCreate

        alert_create = AlertCreate(
            alert_id=alert.alert_id,
            alert_type="hijack",
            severity=alert.severity,
            request_id=alert.request_id,
            tool_name=alert.unexpected_tool,
            description=f"Intent drift detected: expected {alert.expected_task}, got {alert.unexpected_tool}",
            details=alert.evidence,
        )

        await self.db.create_alert(alert_create)
