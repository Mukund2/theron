"""Exfiltration detection for Theron.

Detects patterns like: read sensitive file -> send outbound message
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4


@dataclass
class SensitiveMatch:
    """A match of sensitive data in content."""

    data_type: str  # credentials, private_keys, personal_data, internal_paths
    pattern_name: str
    matched_text: str
    position: int
    risk_level: str  # low, medium, high, critical


@dataclass
class SensitiveAccess:
    """Record of sensitive data being accessed."""

    access_id: str
    request_id: str
    data_type: str
    source: str  # file path, tool name, etc.
    content_hash: str
    matches: list[SensitiveMatch]
    accessed_at: datetime
    risk_level: str


@dataclass
class ExfiltrationAlert:
    """Alert for potential data exfiltration."""

    alert_id: str
    severity: str  # low, medium, high, critical
    sensitive_type: str
    source: str
    destination: str  # tool name that would send data
    evidence: dict
    request_id: str
    detected_at: datetime = field(default_factory=datetime.utcnow)


# Sensitive data patterns
SENSITIVE_PATTERNS = {
    "credentials": {
        "password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{4,})",
        "api_key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{16,})",
        "secret": r"(?i)(secret|token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{16,})",
        "aws_key": r"(?i)(AKIA[A-Z0-9]{16})",
        "github_token": r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})",
        "slack_token": r"(xox[baprs]-[a-zA-Z0-9-]+)",
    },
    "private_keys": {
        "pem_key": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        "ssh_private": r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
        "pgp_private": r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY-----",
    },
    "personal_data": {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "email_sensitive": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+1[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b",
    },
    "internal_paths": {
        "env_file": r"\.env(?:\.local|\.production|\.development)?",
        "ssh_dir": r"~?/\.ssh/",
        "aws_creds": r"~?/\.aws/credentials",
        "kube_config": r"~?/\.kube/config",
        "passwd": r"/etc/(?:passwd|shadow)",
        "private_dir": r"~?/\.[a-zA-Z]+/",
    },
}

# Risk levels for each category
CATEGORY_RISK = {
    "credentials": "critical",
    "private_keys": "critical",
    "personal_data": "high",
    "internal_paths": "medium",
}

# Tools that can send data outbound
OUTBOUND_TOOLS = {
    # High risk - direct data transmission
    "send_email": "critical",
    "send_message": "critical",
    "post_slack": "critical",
    "post_discord": "critical",
    "post_teams": "critical",
    "send_sms": "critical",

    # Medium risk - HTTP requests
    "http_request": "high",
    "curl": "high",
    "wget": "high",
    "fetch_url": "high",
    "webhook": "high",
    "upload_file": "high",

    # Lower risk but still monitored
    "execute_shell": "medium",
    "run_command": "medium",
    "bash": "medium",
}


class ExfiltrationDetector:
    """Detects potential data exfiltration patterns."""

    def __init__(self, db=None):
        """Initialize the exfiltration detector.

        Args:
            db: Optional database instance for persistence.
        """
        self.db = db
        # Track sensitive data accessed per request
        self._sensitive_accessed: dict[str, list[SensitiveAccess]] = {}
        # Compiled patterns for efficiency
        self._compiled_patterns: dict[str, dict[str, re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency."""
        for category, patterns in SENSITIVE_PATTERNS.items():
            self._compiled_patterns[category] = {}
            for name, pattern in patterns.items():
                try:
                    self._compiled_patterns[category][name] = re.compile(pattern)
                except re.error:
                    pass  # Skip invalid patterns

    def _hash_content(self, content: str) -> str:
        """Create a hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def track_content_access(
        self,
        request_id: str,
        content: str,
        source: str,
    ) -> Optional[SensitiveAccess]:
        """Track when content is accessed and scan for sensitive data.

        Args:
            request_id: Request identifier
            content: The content to scan
            source: Source of the content (file path, tool name, etc.)

        Returns:
            SensitiveAccess record if sensitive data found, None otherwise
        """
        matches = self._scan_for_sensitive(content)
        if not matches:
            return None

        # Determine highest risk level from matches
        risk_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_risk = "low"
        for match in matches:
            if risk_levels.get(match.risk_level, 0) > risk_levels.get(max_risk, 0):
                max_risk = match.risk_level

        access = SensitiveAccess(
            access_id=str(uuid4()),
            request_id=request_id,
            data_type=matches[0].data_type,  # Primary type
            source=source,
            content_hash=self._hash_content(content),
            matches=matches,
            accessed_at=datetime.utcnow(),
            risk_level=max_risk,
        )

        if request_id not in self._sensitive_accessed:
            self._sensitive_accessed[request_id] = []

        self._sensitive_accessed[request_id].append(access)

        return access

    def _scan_for_sensitive(self, content: str) -> list[SensitiveMatch]:
        """Scan content for sensitive data patterns.

        Args:
            content: Content to scan

        Returns:
            List of sensitive matches found
        """
        matches = []

        for category, patterns in self._compiled_patterns.items():
            for pattern_name, pattern in patterns.items():
                for match in pattern.finditer(content):
                    # Redact the actual matched text for safety
                    matched_text = match.group()
                    if len(matched_text) > 20:
                        redacted = matched_text[:8] + "..." + matched_text[-4:]
                    else:
                        redacted = matched_text[:4] + "***"

                    matches.append(SensitiveMatch(
                        data_type=category,
                        pattern_name=pattern_name,
                        matched_text=redacted,
                        position=match.start(),
                        risk_level=CATEGORY_RISK.get(category, "medium"),
                    ))

        return matches

    def check_outbound_action(
        self,
        request_id: str,
        tool_name: str,
        args: dict,
    ) -> Optional[ExfiltrationAlert]:
        """Check if an outbound action might be exfiltrating sensitive data.

        Args:
            request_id: Request identifier
            tool_name: Name of the tool being called
            args: Arguments to the tool

        Returns:
            ExfiltrationAlert if exfiltration detected, None otherwise
        """
        # Check if this is an outbound tool
        tool_lower = tool_name.lower()
        if tool_lower not in OUTBOUND_TOOLS:
            # Also check for partial matches
            outbound_match = None
            for outbound_tool in OUTBOUND_TOOLS:
                if outbound_tool in tool_lower or tool_lower in outbound_tool:
                    outbound_match = outbound_tool
                    break
            if not outbound_match:
                return None
            tool_lower = outbound_match

        # Get sensitive data accessed in this request
        accessed = self._sensitive_accessed.get(request_id, [])
        if not accessed:
            return None

        # Serialize args for scanning
        args_str = json.dumps(args, default=str).lower()

        # Check if any sensitive data appears in the outbound args
        for access in accessed:
            if self._data_appears_in_args(access, args_str):
                # Calculate severity based on tool and data risk
                tool_risk = OUTBOUND_TOOLS.get(tool_lower, "medium")
                data_risk = access.risk_level

                severity = self._combine_risk(tool_risk, data_risk)

                return ExfiltrationAlert(
                    alert_id=str(uuid4()),
                    severity=severity,
                    sensitive_type=access.data_type,
                    source=access.source,
                    destination=tool_name,
                    evidence={
                        "access_id": access.access_id,
                        "data_types": [m.data_type for m in access.matches],
                        "patterns_matched": [m.pattern_name for m in access.matches],
                        "tool_args_preview": args_str[:200] + "..." if len(args_str) > 200 else args_str,
                    },
                    request_id=request_id,
                )

        return None

    def _data_appears_in_args(self, access: SensitiveAccess, args_str: str) -> bool:
        """Check if sensitive data from an access appears in tool arguments.

        Uses multiple detection methods:
        1. Content hash comparison
        2. Keyword matching from patterns
        3. Structural similarity

        Args:
            access: The sensitive access record
            args_str: Serialized tool arguments (lowercase)

        Returns:
            True if data appears to be included
        """
        # Check for content hash (if someone is sending the hash directly)
        if access.content_hash.lower() in args_str:
            return True

        # Check for pattern keywords
        sensitive_keywords = {
            "credentials": ["password", "api_key", "secret", "token", "bearer"],
            "private_keys": ["private key", "ssh", "rsa", "pem"],
            "personal_data": ["ssn", "credit", "card", "phone"],
            "internal_paths": [".env", ".ssh", ".aws", "credentials"],
        }

        keywords = sensitive_keywords.get(access.data_type, [])
        keyword_count = sum(1 for kw in keywords if kw in args_str)

        # If multiple keywords from the sensitive category appear, flag it
        if keyword_count >= 2:
            return True

        # Check if the pattern type appears in args
        for match in access.matches:
            # Re-run the pattern on args to see if similar data exists
            if match.pattern_name in self._compiled_patterns.get(match.data_type, {}):
                pattern = self._compiled_patterns[match.data_type][match.pattern_name]
                if pattern.search(args_str):
                    return True

        return False

    def _combine_risk(self, tool_risk: str, data_risk: str) -> str:
        """Combine tool and data risk into overall severity.

        Args:
            tool_risk: Risk level of the outbound tool
            data_risk: Risk level of the sensitive data

        Returns:
            Combined severity level
        """
        risk_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        tool_score = risk_scores.get(tool_risk, 2)
        data_score = risk_scores.get(data_risk, 2)

        combined = (tool_score + data_score) / 2

        if combined >= 3.5:
            return "critical"
        elif combined >= 2.5:
            return "high"
        elif combined >= 1.5:
            return "medium"
        else:
            return "low"

    def get_sensitive_summary(self, request_id: str) -> dict:
        """Get summary of sensitive data accessed in a request.

        Args:
            request_id: Request identifier

        Returns:
            Summary dictionary
        """
        accessed = self._sensitive_accessed.get(request_id, [])
        if not accessed:
            return {"has_sensitive": False, "count": 0}

        return {
            "has_sensitive": True,
            "count": len(accessed),
            "types": list({a.data_type for a in accessed}),
            "sources": list({a.source for a in accessed}),
            "max_risk": max(
                accessed,
                key=lambda a: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(
                    a.risk_level, 0
                ),
            ).risk_level,
        }

    def clear_request(self, request_id: str) -> None:
        """Clear tracked data for a request.

        Args:
            request_id: Request to clear
        """
        self._sensitive_accessed.pop(request_id, None)

    async def persist_alert(self, alert: ExfiltrationAlert) -> None:
        """Persist an exfiltration alert to database.

        Args:
            alert: Alert to persist
        """
        if not self.db:
            return

        from ..storage.models import AlertCreate

        alert_create = AlertCreate(
            alert_id=alert.alert_id,
            alert_type="exfiltration",
            severity=alert.severity,
            request_id=alert.request_id,
            tool_name=alert.destination,
            description=f"Potential exfiltration of {alert.sensitive_type} via {alert.destination}",
            details=alert.evidence,
        )

        await self.db.create_alert(alert_create)
