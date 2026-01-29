"""Data models for Theron storage."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ActionStatus(str, Enum):
    """Status of an action."""

    ALLOWED = "allowed"
    LOGGED = "logged"
    BLOCKED = "blocked"


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
