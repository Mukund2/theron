"""Sandbox execution result models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class SandboxStatus(str, Enum):
    """Status of a sandbox execution."""

    PENDING = "pending"      # Queued for execution
    RUNNING = "running"      # Currently executing
    COMPLETED = "completed"  # Execution finished
    APPROVED = "approved"    # User approved the action
    REJECTED = "rejected"    # User rejected the action
    EXPIRED = "expired"      # Timed out waiting for approval
    FAILED = "failed"        # Execution failed


@dataclass
class FileChange:
    """Represents a file change in the sandbox."""

    path: str
    action: str  # 'created', 'modified', 'deleted'
    content_preview: Optional[str] = None  # First N bytes of content
    size_bytes: int = 0


@dataclass
class SandboxResult:
    """Result of a sandboxed execution."""

    sandbox_id: str
    tool_name: str
    tool_arguments: dict[str, Any]
    command: str  # The actual command that was run
    status: SandboxStatus = SandboxStatus.PENDING
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    file_changes: list[FileChange] = field(default_factory=list)
    duration_ms: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    rejected_at: Optional[datetime] = None
    error_message: Optional[str] = None

    # Context from the original request
    source_tag: Optional[str] = None
    risk_tier: Optional[int] = None
    threat_score: int = 0
    agent_id: Optional[str] = None
    request_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sandbox_id": self.sandbox_id,
            "tool_name": self.tool_name,
            "tool_arguments": self.tool_arguments,
            "command": self.command,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "file_changes": [
                {
                    "path": fc.path,
                    "action": fc.action,
                    "content_preview": fc.content_preview,
                    "size_bytes": fc.size_bytes,
                }
                for fc in self.file_changes
            ],
            "duration_ms": self.duration_ms,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "rejected_at": self.rejected_at.isoformat() if self.rejected_at else None,
            "error_message": self.error_message,
            "source_tag": self.source_tag,
            "risk_tier": self.risk_tier,
            "threat_score": self.threat_score,
            "agent_id": self.agent_id,
            "request_id": self.request_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SandboxResult":
        """Create from dictionary."""
        file_changes = [
            FileChange(
                path=fc["path"],
                action=fc["action"],
                content_preview=fc.get("content_preview"),
                size_bytes=fc.get("size_bytes", 0),
            )
            for fc in data.get("file_changes", [])
        ]

        return cls(
            sandbox_id=data["sandbox_id"],
            tool_name=data["tool_name"],
            tool_arguments=data.get("tool_arguments", {}),
            command=data.get("command", ""),
            status=SandboxStatus(data.get("status", "pending")),
            exit_code=data.get("exit_code"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            file_changes=file_changes,
            duration_ms=data.get("duration_ms", 0),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.utcnow(),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            approved_at=datetime.fromisoformat(data["approved_at"]) if data.get("approved_at") else None,
            rejected_at=datetime.fromisoformat(data["rejected_at"]) if data.get("rejected_at") else None,
            error_message=data.get("error_message"),
            source_tag=data.get("source_tag"),
            risk_tier=data.get("risk_tier"),
            threat_score=data.get("threat_score", 0),
            agent_id=data.get("agent_id"),
            request_id=data.get("request_id"),
        )
