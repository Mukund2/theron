"""Data models for Theron storage."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ActionStatus(str, Enum):
    """Status of an action."""

    ALLOWED = "allowed"
    LOGGED = "logged"
    SANDBOXED = "sandboxed"
    BLOCKED = "blocked"


class SandboxStatus(str, Enum):
    """Status of a sandbox execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FAILED = "failed"


class SourceTag(str, Enum):
    """Trust level tags for input sources."""

    USER_DIRECT = "USER_DIRECT"
    USER_INDIRECT = "USER_INDIRECT"
    CONTENT_READ = "CONTENT_READ"
    TOOL_RESULT = "TOOL_RESULT"
    SYSTEM = "SYSTEM"


class Event(BaseModel):
    """Event log entry."""

    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: str
    agent_id: Optional[str] = None
    source_tag: Optional[str] = None
    threat_score: int = 0
    injection_detected: bool = False
    injection_patterns: Optional[str] = None
    tool_name: Optional[str] = None
    risk_tier: Optional[int] = None
    action: str
    block_reason: Optional[str] = None
    request_summary: Optional[str] = None
    response_summary: Optional[str] = None
    llm_provider: Optional[str] = None
    model: Optional[str] = None


class Pattern(BaseModel):
    """Detection pattern."""

    id: Optional[int] = None
    pattern: str
    category: str
    weight: int = 10
    description: Optional[str] = None
    enabled: bool = True
    source: str = "default"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Stats(BaseModel):
    """Daily statistics."""

    id: Optional[int] = None
    date: str
    total_requests: int = 0
    blocked_requests: int = 0
    injection_attempts: int = 0


class EventCreate(BaseModel):
    """Event creation model."""

    request_id: str
    agent_id: Optional[str] = None
    source_tag: Optional[str] = None
    threat_score: int = 0
    injection_detected: bool = False
    injection_patterns: Optional[str] = None
    tool_name: Optional[str] = None
    risk_tier: Optional[int] = None
    action: str
    block_reason: Optional[str] = None
    request_summary: Optional[str] = None
    response_summary: Optional[str] = None
    llm_provider: Optional[str] = None
    model: Optional[str] = None


class EventFilter(BaseModel):
    """Event filter parameters."""

    agent_id: Optional[str] = None
    action: Optional[str] = None
    source_tag: Optional[str] = None
    risk_tier: Optional[int] = None
    injection_detected: Optional[bool] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


class SandboxResultDB(BaseModel):
    """Sandbox result stored in database."""

    id: Optional[int] = None
    sandbox_id: str
    tool_name: str
    tool_arguments: str  # JSON string
    command: str
    status: str = "pending"
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    file_changes: Optional[str] = None  # JSON string
    duration_ms: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    rejected_at: Optional[datetime] = None
    error_message: Optional[str] = None
    source_tag: Optional[str] = None
    risk_tier: Optional[int] = None
    threat_score: int = 0
    agent_id: Optional[str] = None
    request_id: Optional[str] = None


class SandboxResultCreate(BaseModel):
    """Model for creating a sandbox result."""

    sandbox_id: str
    tool_name: str
    tool_arguments: dict  # Will be JSON serialized
    command: str
    status: str = "pending"
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    file_changes: Optional[list] = None
    duration_ms: int = 0
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    source_tag: Optional[str] = None
    risk_tier: Optional[int] = None
    threat_score: int = 0
    agent_id: Optional[str] = None
    request_id: Optional[str] = None


class SandboxFilter(BaseModel):
    """Filter for sandbox results."""

    status: Optional[str] = None
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    limit: int = 50
    offset: int = 0


# ============== Intelligence Models ==============


class CausalNodeType(str, Enum):
    """Types of nodes in a causal chain."""

    USER_INPUT = "user_input"
    CONTENT_READ = "content_read"
    TOOL_RESULT = "tool_result"
    TOOL_CALL = "tool_call"
    ASSISTANT_MESSAGE = "assistant_message"


class CausalNodeDB(BaseModel):
    """Causal node stored in database."""

    id: Optional[int] = None
    node_id: str
    request_id: str
    parent_id: Optional[str] = None
    node_type: str
    source_tag: str
    content_hash: Optional[str] = None
    content_preview: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    threat_score: float = 0.0
    metadata: Optional[str] = None  # JSON string


class CausalNodeCreate(BaseModel):
    """Model for creating a causal node."""

    node_id: str
    request_id: str
    parent_id: Optional[str] = None
    node_type: str
    source_tag: str
    content_hash: Optional[str] = None
    content_preview: Optional[str] = None
    threat_score: float = 0.0
    metadata: Optional[dict] = None


class AlertType(str, Enum):
    """Types of security alerts."""

    EXFILTRATION = "exfiltration"
    HIJACK = "hijack"
    HONEYPOT = "honeypot"
    ANOMALY = "anomaly"
    TAINT_PROPAGATION = "taint_propagation"


class AlertSeverity(str, Enum):
    """Severity levels for alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertDB(BaseModel):
    """Alert stored in database."""

    id: Optional[int] = None
    alert_id: str
    alert_type: str
    severity: str
    request_id: Optional[str] = None
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    description: str
    details: Optional[str] = None  # JSON string
    created_at: datetime = Field(default_factory=datetime.utcnow)
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


class AlertCreate(BaseModel):
    """Model for creating an alert."""

    alert_id: str
    alert_type: str
    severity: str
    request_id: Optional[str] = None
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    description: str
    details: Optional[dict] = None


class AlertFilter(BaseModel):
    """Filter for alerts."""

    alert_type: Optional[str] = None
    severity: Optional[str] = None
    agent_id: Optional[str] = None
    acknowledged: Optional[bool] = None
    resolved: Optional[bool] = None
    limit: int = 50
    offset: int = 0


class HoneypotDB(BaseModel):
    """Honeypot stored in database."""

    id: Optional[int] = None
    token: str
    honeypot_type: str
    request_id: str
    agent_id: Optional[str] = None
    injected_at: datetime = Field(default_factory=datetime.utcnow)
    injected_in: Optional[str] = None
    content_context: Optional[str] = None
    triggered_at: Optional[datetime] = None
    triggered_by_tool: Optional[str] = None
    triggered_args: Optional[str] = None


class HoneypotCreate(BaseModel):
    """Model for creating a honeypot."""

    token: str
    honeypot_type: str
    request_id: str
    agent_id: Optional[str] = None
    injected_in: Optional[str] = None
    content_context: Optional[str] = None


class TaintDB(BaseModel):
    """Tainted memory entry stored in database."""

    id: Optional[int] = None
    taint_id: str
    request_id: str
    content_hash: str
    source_tag: str
    source_description: Optional[str] = None
    tainted_at: datetime = Field(default_factory=datetime.utcnow)
    keywords: Optional[str] = None  # JSON string
    content_preview: Optional[str] = None


class TaintCreate(BaseModel):
    """Model for creating a taint entry."""

    taint_id: str
    request_id: str
    content_hash: str
    source_tag: str
    source_description: Optional[str] = None
    keywords: Optional[list[str]] = None
    content_preview: Optional[str] = None


class TaintPropagationDB(BaseModel):
    """Taint propagation record stored in database."""

    id: Optional[int] = None
    propagation_id: str
    source_taint_id: str
    request_id: str
    propagated_to: str
    propagation_type: str
    confidence: float = 0.0
    tool_name: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)


class TaintPropagationCreate(BaseModel):
    """Model for creating a taint propagation record."""

    propagation_id: str
    source_taint_id: str
    request_id: str
    propagated_to: str
    propagation_type: str
    confidence: float = 0.0
    tool_name: Optional[str] = None


# ============== Learning Models ==============


class AgentProfileDB(BaseModel):
    """Agent profile stored in database."""

    id: Optional[int] = None
    agent_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    total_requests: int = 0
    profile_data: str  # JSON string containing detailed statistics


class AgentProfileCreate(BaseModel):
    """Model for creating an agent profile."""

    agent_id: str
    profile_data: dict


class ProfileSnapshotDB(BaseModel):
    """Profile snapshot stored in database."""

    id: Optional[int] = None
    snapshot_id: str
    agent_id: str
    snapshot_at: datetime = Field(default_factory=datetime.utcnow)
    profile_data: str  # JSON string
