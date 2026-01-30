"""Shared utilities for proxy handlers."""

import json
import shlex
from typing import Any, Optional

from ..dashboard.api import broadcast_sandbox_blocked
from ..sandbox import get_sandbox_manager
from ..security.tagger import SourceTag
from ..storage import get_database
from ..storage.models import SandboxResultCreate


def _safe_quote(value: Any) -> str:
    """Safely quote a value for shell use. SECURITY: prevents command injection."""
    s = str(value) if value is not None else ""
    # Truncate very long values
    if len(s) > 10000:
        s = s[:10000]
    return shlex.quote(s)


def get_dominant_source(tagged_messages: list) -> SourceTag:
    """Get the most untrusted source tag from recent messages.

    Priority: CONTENT_READ > TOOL_RESULT > USER_INDIRECT > USER_DIRECT
    """
    priority = {
        SourceTag.CONTENT_READ: 4,
        SourceTag.TOOL_RESULT: 3,
        SourceTag.USER_INDIRECT: 2,
        SourceTag.USER_DIRECT: 1,
        SourceTag.SYSTEM: 0,
    }

    recent_user = [m for m in tagged_messages if m.role == "user"][-3:]

    if not recent_user:
        return SourceTag.USER_DIRECT

    max_priority = 0
    dominant = SourceTag.USER_DIRECT

    for msg in recent_user:
        p = priority.get(msg.source_tag, 0)
        if p > max_priority:
            max_priority = p
            dominant = msg.source_tag

    return dominant


def build_command_from_tool(tool_call) -> str:
    """Build a shell command from a tool call for sandbox execution.

    SECURITY: All values are quoted with shlex.quote() to prevent command injection.
    """
    tool_name = str(tool_call.name) if tool_call.name else "unknown"
    args = tool_call.arguments or {}

    # Shell execution tools - quote the entire command
    if tool_name in ("execute_shell", "run_command", "bash", "shell"):
        cmd = args.get("command", args.get("cmd", ""))
        # For shell commands, we echo what would run (don't actually execute user command)
        return f"echo {_safe_quote(f'Would execute: {cmd}')}"

    # File operations - quote all paths and content
    if tool_name in ("write_file", "create_file"):
        path = _safe_quote(args.get("path", args.get("filename", "/tmp/output")))
        content = _safe_quote(args.get("content", ""))
        return f"echo {content} > {path}"

    if tool_name in ("delete_file", "remove_file"):
        path = _safe_quote(args.get("path", args.get("filename", "")))
        return f"rm -f {path}"

    if tool_name in ("read_file", "cat"):
        path = _safe_quote(args.get("path", args.get("filename", "")))
        return f"cat {path}"

    # Network operations - quote all values
    if tool_name in ("curl", "http_request", "fetch"):
        url = _safe_quote(args.get("url", ""))
        method = _safe_quote(args.get("method", "GET").upper()[:10])
        return f"curl -X {method} {url}"

    if tool_name in ("send_email", "email"):
        to = args.get("to", args.get("recipient", ""))
        subject = args.get("subject", "")
        body = args.get("body", args.get("content", ""))
        msg = f"Would send email to: {to}, Subject: {subject}, Body: {body[:100]}..."
        return f"echo {_safe_quote(msg)}"

    # Default: just echo the tool call info (safely quoted)
    info = f"Tool: {tool_name}, Args: {json.dumps(args)[:200]}"
    return f"echo {_safe_quote(info)}"


async def execute_sandbox(
    decision,
    request_id: str,
    agent_id: Optional[str],
    source_tag: str,
    threat_score: int,
) -> None:
    """Execute a tool call in the sandbox and store the result."""
    sandbox_mgr = get_sandbox_manager()

    command = build_command_from_tool(decision.tool_call)

    result = await sandbox_mgr.execute(
        sandbox_id=decision.sandbox_id,
        tool_name=decision.tool_call.name,
        tool_arguments=decision.tool_call.arguments,
        command=command,
        source_tag=source_tag,
        risk_tier=decision.classification.risk_tier.value,
        threat_score=threat_score,
        agent_id=agent_id,
        request_id=request_id,
    )

    # Auto-reject: dangerous actions are blocked automatically, no user approval needed
    await sandbox_mgr.reject(result.sandbox_id)

    db = await get_database()
    await db.create_sandbox_result(
        SandboxResultCreate(
            sandbox_id=result.sandbox_id,
            tool_name=result.tool_name,
            tool_arguments=result.tool_arguments,
            command=result.command,
            status="rejected",  # Always rejected - no user approval workflow
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            file_changes=[fc.__dict__ for fc in result.file_changes] if result.file_changes else None,
            duration_ms=result.duration_ms,
            completed_at=result.completed_at,
            error_message=result.error_message,
            source_tag=result.source_tag,
            risk_tier=result.risk_tier,
            threat_score=result.threat_score,
            agent_id=result.agent_id,
            request_id=result.request_id,
        )
    )

    await broadcast_sandbox_blocked(result.to_dict())
