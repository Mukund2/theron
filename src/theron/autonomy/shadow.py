"""Shadow execution mode for autonomous agents.

Runs potentially dangerous actions in isolation, captures results, and
automatically decides whether to commit or discard based on behavior analysis.

This enables "see what happens" security without requiring human approval -
critical for fully autonomous agents like Moltbot that operate 24/7.

Key insight: Instead of asking "is this safe?" before execution, we ask
"did this behave safely?" after execution in isolation.
"""

import json
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from uuid import uuid4


class CommitDecision(Enum):
    """Decision on whether to commit shadow execution results."""

    COMMIT = "commit"           # Safe to use results
    DISCARD = "discard"         # Results show malicious behavior
    QUARANTINE = "quarantine"   # Uncertain - store for analysis


@dataclass
class ShadowViolation:
    """A violation detected during shadow execution."""

    violation_type: str  # exfiltration, honeypot, destructive, suspicious_output
    severity: str        # low, medium, high, critical
    description: str
    evidence: dict


@dataclass
class ShadowResult:
    """Result of shadow execution with automatic analysis."""

    shadow_id: str
    request_id: str
    tool_name: str
    tool_args: dict
    started_at: datetime
    completed_at: Optional[datetime] = None  # Set when execution completes

    # Execution results
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: int = 0

    # Analysis results
    violations: list[ShadowViolation] = field(default_factory=list)
    decision: CommitDecision = CommitDecision.QUARANTINE
    decision_reason: str = ""
    risk_score: float = 0.0

    # Filesystem changes (if tracked)
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)

    # Network activity (if tracked)
    network_attempts: list[dict] = field(default_factory=list)


# Patterns that indicate exfiltration in output
EXFILTRATION_PATTERNS = [
    # Sending data to external services
    r"curl\s+.*-d\s+",  # curl with data
    r"curl\s+.*--data",
    r"wget\s+.*--post-data",
    r"nc\s+-e",  # netcat reverse shell
    r"base64.*\|\s*(curl|wget|nc)",  # encoded exfiltration

    # Cloud provider credential patterns in output
    r"AKIA[A-Z0-9]{16}",  # AWS access key
    r"ghp_[a-zA-Z0-9]{36}",  # GitHub token
    r"sk-[a-zA-Z0-9]{48}",  # OpenAI key
    r"xox[baprs]-[a-zA-Z0-9-]+",  # Slack token
]

# Patterns that indicate destructive behavior
DESTRUCTIVE_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+~",
    r"rm\s+-rf\s+\*",
    r"dd\s+if=.*of=/dev/",
    r"mkfs\s+",
    r"format\s+[a-zA-Z]:",
    r"del\s+/[sS]\s+/[qQ]",
    r">\s*/dev/sd[a-z]",
    r"chmod\s+-R\s+777\s+/",
    r"chown\s+-R.*:\s*/",
]

# Patterns indicating reverse shell or backdoor
BACKDOOR_PATTERNS = [
    r"bash\s+-i\s+>&\s*/dev/tcp",
    r"nc\s+.*-e\s+/bin/(ba)?sh",
    r"python.*socket.*connect",
    r"perl.*socket.*INET",
    r"ruby.*TCPSocket",
    r"php.*fsockopen",
    r"0<&\d+-",  # file descriptor redirection
    r"\|\s*nc\s+",
]

# Suspicious output patterns
SUSPICIOUS_OUTPUT_PATTERNS = [
    # Password/credential dumps
    r"password[:\s]+\S+",
    r"passwd[:\s]+\S+",
    r"credential[s]?[:\s]+",
    r"secret[:\s]+\S+",

    # System information gathering
    r"/etc/passwd",
    r"/etc/shadow",
    r"~/.ssh/",
    r"\.aws/credentials",
]


class ShadowExecutor:
    """Executes actions in shadow mode with automatic decision-making."""

    def __init__(
        self,
        sandbox_manager=None,
        intelligence_manager=None,
        auto_commit_threshold: float = 0.2,
        auto_discard_threshold: float = 0.6,
    ):
        """Initialize the shadow executor.

        Args:
            sandbox_manager: Sandbox manager for isolated execution
            intelligence_manager: Intelligence manager for exfiltration/honeypot checks
            auto_commit_threshold: Risk score below which to auto-commit
            auto_discard_threshold: Risk score above which to auto-discard
        """
        self.sandbox_manager = sandbox_manager
        self.intelligence_manager = intelligence_manager
        self.auto_commit_threshold = auto_commit_threshold
        self.auto_discard_threshold = auto_discard_threshold

        # Shadow execution history
        self._executions: dict[str, ShadowResult] = {}

        # Compiled patterns for efficiency
        self._exfil_patterns = [re.compile(p, re.IGNORECASE) for p in EXFILTRATION_PATTERNS]
        self._destructive_patterns = [re.compile(p) for p in DESTRUCTIVE_PATTERNS]
        self._backdoor_patterns = [re.compile(p) for p in BACKDOOR_PATTERNS]
        self._suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_OUTPUT_PATTERNS]

    async def execute_shadow(
        self,
        request_id: str,
        tool_name: str,
        tool_args: dict,
        timeout_seconds: int = 30,
    ) -> ShadowResult:
        """Execute a tool in shadow mode and analyze results.

        Args:
            request_id: Request identifier
            tool_name: Tool to execute
            tool_args: Tool arguments
            timeout_seconds: Execution timeout

        Returns:
            ShadowResult with decision
        """
        shadow_id = str(uuid4())

        result = ShadowResult(
            shadow_id=shadow_id,
            request_id=request_id,
            tool_name=tool_name,
            tool_args=tool_args,
            started_at=datetime.utcnow(),
        )

        # Execute in sandbox if available
        if self.sandbox_manager:
            try:
                sandbox_result = await self.sandbox_manager.execute(
                    tool_name=tool_name,
                    args=tool_args,
                    timeout=timeout_seconds,
                    network_disabled=True,  # Always disable network in shadow mode
                )

                result.exit_code = sandbox_result.exit_code
                result.stdout = sandbox_result.stdout or ""
                result.stderr = sandbox_result.stderr or ""
                result.execution_time_ms = sandbox_result.execution_time_ms
                result.files_created = sandbox_result.files_created or []
                result.files_modified = sandbox_result.files_modified or []
                result.files_deleted = sandbox_result.files_deleted or []

            except Exception as e:
                result.stderr = f"Shadow execution failed: {str(e)}"
                result.exit_code = -1
        else:
            # Simulate execution for analysis
            result = self._simulate_execution(result)

        result.completed_at = datetime.utcnow()

        # Analyze the results
        self._analyze_results(result)

        # Make automatic decision
        self._make_decision(result)

        # Store for reference
        self._executions[shadow_id] = result

        return result

    def _simulate_execution(self, result: ShadowResult) -> ShadowResult:
        """Simulate execution when no sandbox available (analyze args only)."""
        # For shell commands, we can analyze the command itself
        if result.tool_name in ("execute_shell", "bash", "run_command"):
            cmd = result.tool_args.get("command", result.tool_args.get("cmd", ""))
            result.stdout = f"[SIMULATED] Would execute: {cmd}"

        return result

    def _analyze_results(self, result: ShadowResult) -> None:
        """Analyze execution results for violations."""
        # Combine all output for analysis
        all_output = f"{result.stdout}\n{result.stderr}"
        args_str = json.dumps(result.tool_args, default=str)
        combined = f"{all_output}\n{args_str}"

        # Check for exfiltration patterns
        for pattern in self._exfil_patterns:
            if pattern.search(combined):
                result.violations.append(ShadowViolation(
                    violation_type="exfiltration",
                    severity="critical",
                    description=f"Exfiltration pattern detected: {pattern.pattern}",
                    evidence={"pattern": pattern.pattern, "matched_in": "output/args"},
                ))

        # Check for destructive patterns
        for pattern in self._destructive_patterns:
            if pattern.search(combined):
                result.violations.append(ShadowViolation(
                    violation_type="destructive",
                    severity="critical",
                    description=f"Destructive command detected: {pattern.pattern}",
                    evidence={"pattern": pattern.pattern},
                ))

        # Check for backdoor patterns
        for pattern in self._backdoor_patterns:
            if pattern.search(combined):
                result.violations.append(ShadowViolation(
                    violation_type="backdoor",
                    severity="critical",
                    description=f"Backdoor/reverse shell pattern detected",
                    evidence={"pattern": pattern.pattern},
                ))

        # Check for suspicious output
        for pattern in self._suspicious_patterns:
            if pattern.search(all_output):
                result.violations.append(ShadowViolation(
                    violation_type="suspicious_output",
                    severity="high",
                    description=f"Suspicious output pattern: {pattern.pattern}",
                    evidence={"pattern": pattern.pattern},
                ))

        # Check honeypot usage if intelligence manager available
        if self.intelligence_manager:
            honeypot_alert = self.intelligence_manager.honeypot_mgr.check_for_honeypot_use(
                result.tool_name, result.tool_args
            )
            if honeypot_alert:
                result.violations.append(ShadowViolation(
                    violation_type="honeypot",
                    severity="critical",
                    description="Honeypot credential used - agent is compromised",
                    evidence={
                        "honeypot_type": honeypot_alert.honeypot_type,
                        "token_prefix": honeypot_alert.token[:8],
                    },
                ))

            # Also check if output contains honeypots
            for token in self.intelligence_manager.honeypot_mgr._active_honeypots.keys():
                if token in all_output:
                    result.violations.append(ShadowViolation(
                        violation_type="honeypot_in_output",
                        severity="high",
                        description="Honeypot token appears in output",
                        evidence={"token_prefix": token[:8]},
                    ))

        # Check for excessive file operations
        total_file_ops = (
            len(result.files_created) +
            len(result.files_modified) +
            len(result.files_deleted)
        )
        if total_file_ops > 100:
            result.violations.append(ShadowViolation(
                violation_type="excessive_file_ops",
                severity="medium",
                description=f"Excessive file operations: {total_file_ops}",
                evidence={"count": total_file_ops},
            ))

        # Check for sensitive file access
        sensitive_paths = ["/etc/passwd", "/etc/shadow", ".ssh/", ".aws/", ".env"]
        for path in result.files_created + result.files_modified:
            if any(s in path for s in sensitive_paths):
                result.violations.append(ShadowViolation(
                    violation_type="sensitive_file_access",
                    severity="high",
                    description=f"Sensitive file accessed: {path}",
                    evidence={"path": path},
                ))

        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result.violations)

    def _calculate_risk_score(self, violations: list[ShadowViolation]) -> float:
        """Calculate overall risk score from violations."""
        if not violations:
            return 0.0

        severity_weights = {
            "critical": 1.0,
            "high": 0.6,
            "medium": 0.3,
            "low": 0.1,
        }

        total = sum(severity_weights.get(v.severity, 0.5) for v in violations)

        # Normalize to 0-1 range, with diminishing returns
        return min(1.0, total / 2.0)

    def _make_decision(self, result: ShadowResult) -> None:
        """Make automatic commit/discard decision."""
        # Critical violations = always discard
        critical_violations = [v for v in result.violations if v.severity == "critical"]
        if critical_violations:
            result.decision = CommitDecision.DISCARD
            result.decision_reason = f"Critical violations: {[v.violation_type for v in critical_violations]}"
            return

        # Check risk score thresholds
        if result.risk_score < self.auto_commit_threshold:
            result.decision = CommitDecision.COMMIT
            result.decision_reason = f"Risk score {result.risk_score:.2f} below threshold {self.auto_commit_threshold}"
        elif result.risk_score > self.auto_discard_threshold:
            result.decision = CommitDecision.DISCARD
            result.decision_reason = f"Risk score {result.risk_score:.2f} above threshold {self.auto_discard_threshold}"
        else:
            result.decision = CommitDecision.QUARANTINE
            result.decision_reason = f"Risk score {result.risk_score:.2f} in uncertain range"

        # Additional heuristics for edge cases

        # Non-zero exit code with no violations might be legitimate error
        if result.exit_code != 0 and not result.violations:
            result.decision = CommitDecision.COMMIT
            result.decision_reason = "Execution failed but no security violations"

        # Empty output for destructive commands = suspicious
        if not result.stdout and not result.stderr:
            destructive_tools = ["delete_file", "remove", "rm", "drop_database"]
            if any(d in result.tool_name.lower() for d in destructive_tools):
                result.decision = CommitDecision.QUARANTINE
                result.decision_reason = "Destructive operation with no output"

    def get_shadow_result(self, shadow_id: str) -> Optional[ShadowResult]:
        """Get a shadow execution result."""
        return self._executions.get(shadow_id)

    def get_request_shadows(self, request_id: str) -> list[ShadowResult]:
        """Get all shadow executions for a request."""
        return [r for r in self._executions.values() if r.request_id == request_id]

    def get_committed_results(self, request_id: str) -> list[ShadowResult]:
        """Get results that were committed (safe to use)."""
        return [
            r for r in self._executions.values()
            if r.request_id == request_id and r.decision == CommitDecision.COMMIT
        ]

    def get_discarded_results(self, request_id: str) -> list[ShadowResult]:
        """Get results that were discarded (malicious)."""
        return [
            r for r in self._executions.values()
            if r.request_id == request_id and r.decision == CommitDecision.DISCARD
        ]

    def should_shadow_execute(
        self,
        tool_name: str,
        risk_tier: int,
        composite_risk: float,
    ) -> bool:
        """Determine if a tool should be shadow-executed.

        Args:
            tool_name: Tool being called
            risk_tier: Risk tier (1-4)
            composite_risk: Composite risk score from intelligence

        Returns:
            True if shadow execution recommended
        """
        # Always shadow Tier 3-4 tools
        if risk_tier >= 3:
            return True

        # Shadow if composite risk is elevated
        if composite_risk > 0.4:
            return True

        # Shadow shell commands
        shell_tools = ["execute_shell", "bash", "run_command", "shell", "exec"]
        if any(s in tool_name.lower() for s in shell_tools):
            return True

        # Shadow file deletion
        if "delete" in tool_name.lower() or "remove" in tool_name.lower():
            return True

        return False

    def get_execution_summary(self) -> dict:
        """Get summary of all shadow executions."""
        all_results = list(self._executions.values())

        return {
            "total_executions": len(all_results),
            "committed": sum(1 for r in all_results if r.decision == CommitDecision.COMMIT),
            "discarded": sum(1 for r in all_results if r.decision == CommitDecision.DISCARD),
            "quarantined": sum(1 for r in all_results if r.decision == CommitDecision.QUARANTINE),
            "violations_detected": sum(len(r.violations) for r in all_results),
            "avg_risk_score": (
                sum(r.risk_score for r in all_results) / len(all_results)
                if all_results else 0.0
            ),
        }

    def clear_request(self, request_id: str) -> int:
        """Clear shadow results for a request."""
        to_remove = [
            sid for sid, r in self._executions.items()
            if r.request_id == request_id
        ]
        for sid in to_remove:
            del self._executions[sid]
        return len(to_remove)
