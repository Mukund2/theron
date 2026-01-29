"""Honeypot injection for Theron.

Injects fake credentials into content. If the agent uses them, it's compromised.
"""

import hashlib
import json
import random
import re
import string
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4

from ..storage.models import HoneypotCreate


@dataclass
class Honeypot:
    """A honeypot (canary credential) that was injected."""

    token: str
    honeypot_type: str  # api_key, password, ssh_key, aws_key, webhook
    request_id: str
    agent_id: Optional[str]
    injected_at: datetime
    injected_in: str  # file_read, tool_result, etc.
    content_context: str  # Context about where it was injected


@dataclass
class HoneypotAlert:
    """Alert when a honeypot is triggered."""

    alert_id: str
    severity: str  # always critical
    honeypot_type: str
    token: str
    injected_at: datetime
    used_in_tool: str
    used_args: str
    request_id: str
    agent_id: Optional[str]
    detected_at: datetime = field(default_factory=datetime.utcnow)


# Honeypot templates - these look like real credentials
HONEYPOT_TEMPLATES = {
    "api_key": [
        "THERON_API_KEY_{token}",
        "sk_live_{token}",
        "api_key_{token}",
        "APIKey: {token}",
    ],
    "password": [
        "password: {token}",
        "BACKUP_PASSWORD={token}",
        "admin_pass=\"{token}\"",
        "DB_PASSWORD={token}",
    ],
    "aws_key": [
        "AKIA{token_upper}",
        "AWS_ACCESS_KEY_ID=AKIA{token_upper}",
        "aws_secret_access_key = {token}",
    ],
    "github_token": [
        "ghp_{token}",
        "GITHUB_TOKEN=ghp_{token}",
    ],
    "webhook": [
        "https://hooks.theron.local/callback/{token}",
        "WEBHOOK_URL=https://notify.internal/{token}",
    ],
    "database": [
        "mongodb://admin:{token}@localhost:27017",
        "postgres://user:{token}@db.internal:5432/prod",
        "mysql://root:{token}@127.0.0.1:3306",
    ],
}

# Injection contexts - how to naturally inject honeypots
INJECTION_CONTEXTS = {
    "comment": [
        "# Backup credentials (DO NOT USE IN PRODUCTION)",
        "// Legacy API key for testing",
        "/* Old credentials - marked for removal */",
        "# TODO: rotate this key",
    ],
    "config": [
        "[backup]",
        "[legacy]",
        "[deprecated]",
        "# fallback configuration",
    ],
    "env": [
        "# Development overrides",
        "# Staging environment",
        "# Test credentials",
    ],
}


class HoneypotManager:
    """Manages honeypot injection and detection."""

    def __init__(self, db=None, injection_rate: float = 0.30):
        """Initialize the honeypot manager.

        Args:
            db: Optional database instance for persistence.
            injection_rate: Probability of injecting honeypot (0.0 to 1.0).
        """
        self.db = db
        self.injection_rate = injection_rate
        # Active honeypots: token -> Honeypot
        self._active_honeypots: dict[str, Honeypot] = {}
        # Token patterns for detection
        self._token_patterns: list[re.Pattern] = []

    def _generate_token(self, length: int = 24) -> str:
        """Generate a random token for honeypot.

        Args:
            length: Token length

        Returns:
            Random alphanumeric token
        """
        chars = string.ascii_letters + string.digits
        return "".join(random.choices(chars, k=length))

    def _generate_honeypot(
        self,
        request_id: str,
        agent_id: Optional[str] = None,
        honeypot_type: Optional[str] = None,
    ) -> Honeypot:
        """Generate a honeypot credential.

        Args:
            request_id: Request identifier
            agent_id: Optional agent identifier
            honeypot_type: Type of honeypot to generate (random if not specified)

        Returns:
            Generated Honeypot
        """
        if honeypot_type is None:
            honeypot_type = random.choice(list(HONEYPOT_TEMPLATES.keys()))

        # Generate unique token
        token = self._generate_token()

        return Honeypot(
            token=token,
            honeypot_type=honeypot_type,
            request_id=request_id,
            agent_id=agent_id,
            injected_at=datetime.utcnow(),
            injected_in="pending",
            content_context="",
        )

    def inject_honeypots(
        self,
        content: str,
        request_id: str,
        agent_id: Optional[str] = None,
        source_type: str = "file_read",
    ) -> tuple[str, list[Honeypot]]:
        """Inject honeypots into content being returned to agent.

        Args:
            content: Original content
            request_id: Request identifier
            agent_id: Optional agent identifier
            source_type: Type of content (file_read, tool_result, etc.)

        Returns:
            Tuple of (modified_content, list_of_injected_honeypots)
        """
        # Check injection probability
        if random.random() > self.injection_rate:
            return content, []

        # Don't inject into very short content
        if len(content) < 100:
            return content, []

        injected = []

        # Choose honeypot type based on content
        honeypot_type = self._choose_honeypot_type(content)
        honeypot = self._generate_honeypot(request_id, agent_id, honeypot_type)

        # Inject the honeypot naturally
        modified_content = self._inject_naturally(content, honeypot, source_type)

        if modified_content != content:
            # Update honeypot with injection info
            honeypot.injected_in = source_type
            honeypot.content_context = content[:100] + "..."

            # Track active honeypot
            self._active_honeypots[honeypot.token] = honeypot
            injected.append(honeypot)

        return modified_content, injected

    def _choose_honeypot_type(self, content: str) -> str:
        """Choose appropriate honeypot type based on content.

        Args:
            content: Content to analyze

        Returns:
            Honeypot type to use
        """
        content_lower = content.lower()

        # Match content type to honeypot type
        if ".env" in content_lower or "environment" in content_lower:
            return random.choice(["api_key", "password", "database"])
        elif "config" in content_lower or ".yaml" in content_lower or ".json" in content_lower:
            return random.choice(["api_key", "webhook", "database"])
        elif "aws" in content_lower or "amazon" in content_lower:
            return "aws_key"
        elif "github" in content_lower or "git" in content_lower:
            return "github_token"
        elif ".py" in content_lower or "python" in content_lower:
            return random.choice(["api_key", "password"])
        elif "ssh" in content_lower or "key" in content_lower:
            return random.choice(["api_key", "password"])
        else:
            return random.choice(list(HONEYPOT_TEMPLATES.keys()))

    def _inject_naturally(
        self,
        content: str,
        honeypot: Honeypot,
        source_type: str,
    ) -> str:
        """Inject honeypot in a way that looks natural.

        Args:
            content: Original content
            honeypot: Honeypot to inject
            source_type: Type of content

        Returns:
            Modified content with honeypot
        """
        # Get template for this honeypot type
        templates = HONEYPOT_TEMPLATES.get(honeypot.honeypot_type, ["TOKEN_{token}"])
        template = random.choice(templates)

        # Format token
        formatted = template.format(
            token=honeypot.token,
            token_upper=honeypot.token.upper()[:16],
        )

        # Choose context wrapper
        context_type = "comment"
        if ".env" in content.lower() or "=" in content[:200]:
            context_type = "env"
        elif "config" in content.lower() or "[" in content[:200]:
            context_type = "config"

        context = random.choice(INJECTION_CONTEXTS.get(context_type, INJECTION_CONTEXTS["comment"]))

        # Build injection block
        injection = f"\n{context}\n{formatted}\n"

        # Find good injection point
        # Look for existing comments, blank lines, or end of file
        lines = content.split("\n")

        # Strategy 1: After a comment block
        for i, line in enumerate(lines):
            if line.strip().startswith("#") or line.strip().startswith("//"):
                if i < len(lines) - 1 and not lines[i + 1].strip().startswith(("#", "//")):
                    lines.insert(i + 1, injection)
                    return "\n".join(lines)

        # Strategy 2: After blank lines in middle of file
        for i in range(len(lines) // 4, 3 * len(lines) // 4):
            if not lines[i].strip() and i > 0 and lines[i - 1].strip():
                lines.insert(i + 1, injection)
                return "\n".join(lines)

        # Strategy 3: Near the end (but not at very end)
        if len(lines) > 10:
            insert_pos = len(lines) - random.randint(3, min(8, len(lines) // 2))
            lines.insert(insert_pos, injection)
            return "\n".join(lines)

        # Fallback: append with comment
        return content + f"\n\n{context}\n{formatted}"

    def check_for_honeypot_use(
        self,
        tool_name: str,
        args: dict,
    ) -> Optional[HoneypotAlert]:
        """Check if any honeypot tokens appear in tool arguments.

        Args:
            tool_name: Name of the tool being called
            args: Arguments to the tool

        Returns:
            HoneypotAlert if honeypot used, None otherwise
        """
        if not self._active_honeypots:
            return None

        # Serialize args for scanning
        args_str = json.dumps(args, default=str)

        for token, honeypot in self._active_honeypots.items():
            if token in args_str:
                return HoneypotAlert(
                    alert_id=str(uuid4()),
                    severity="critical",
                    honeypot_type=honeypot.honeypot_type,
                    token=token,
                    injected_at=honeypot.injected_at,
                    used_in_tool=tool_name,
                    used_args=args_str[:500],  # Truncate for storage
                    request_id=honeypot.request_id,
                    agent_id=honeypot.agent_id,
                )

        return None

    def get_active_honeypots(self) -> list[Honeypot]:
        """Get all active honeypots.

        Returns:
            List of active honeypots
        """
        return list(self._active_honeypots.values())

    def get_honeypot_stats(self) -> dict:
        """Get statistics about honeypots.

        Returns:
            Statistics dictionary
        """
        honeypots = self.get_active_honeypots()

        type_counts: dict[str, int] = {}
        for hp in honeypots:
            type_counts[hp.honeypot_type] = type_counts.get(hp.honeypot_type, 0) + 1

        return {
            "active_count": len(honeypots),
            "types": type_counts,
            "injection_rate": self.injection_rate,
        }

    def clear_request_honeypots(self, request_id: str) -> int:
        """Clear honeypots for a specific request.

        Args:
            request_id: Request to clear

        Returns:
            Number of honeypots cleared
        """
        to_remove = [
            token for token, hp in self._active_honeypots.items()
            if hp.request_id == request_id
        ]

        for token in to_remove:
            del self._active_honeypots[token]

        return len(to_remove)

    def expire_old_honeypots(self, max_age_hours: int = 24) -> int:
        """Expire honeypots older than max age.

        Args:
            max_age_hours: Maximum age in hours

        Returns:
            Number of honeypots expired
        """
        now = datetime.utcnow()
        to_remove = []

        for token, hp in self._active_honeypots.items():
            age = (now - hp.injected_at).total_seconds() / 3600
            if age > max_age_hours:
                to_remove.append(token)

        for token in to_remove:
            del self._active_honeypots[token]

        return len(to_remove)

    async def persist_honeypot(self, honeypot: Honeypot) -> None:
        """Persist a honeypot to database.

        Args:
            honeypot: Honeypot to persist
        """
        if not self.db:
            return

        honeypot_create = HoneypotCreate(
            token=honeypot.token,
            honeypot_type=honeypot.honeypot_type,
            request_id=honeypot.request_id,
            agent_id=honeypot.agent_id,
            injected_in=honeypot.injected_in,
            content_context=honeypot.content_context,
        )

        await self.db.create_honeypot(honeypot_create)

    async def persist_alert(self, alert: HoneypotAlert) -> None:
        """Persist a honeypot alert to database.

        Args:
            alert: Alert to persist
        """
        if not self.db:
            return

        from ..storage.models import AlertCreate

        alert_create = AlertCreate(
            alert_id=alert.alert_id,
            alert_type="honeypot",
            severity="critical",
            request_id=alert.request_id,
            agent_id=alert.agent_id,
            tool_name=alert.used_in_tool,
            description=f"Honeypot triggered: {alert.honeypot_type} credential used in {alert.used_in_tool}",
            details={
                "token": alert.token[:8] + "...",  # Partial token for reference
                "honeypot_type": alert.honeypot_type,
                "injected_at": alert.injected_at.isoformat(),
                "used_args_preview": alert.used_args[:200],
            },
        )

        await self.db.create_alert(alert_create)

        # Also mark honeypot as triggered in database
        if alert.token in self._active_honeypots:
            await self.db.trigger_honeypot(
                token=alert.token,
                triggered_by_tool=alert.used_in_tool,
                triggered_args=alert.used_args,
            )
