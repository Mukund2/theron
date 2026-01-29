"""Database operations for Theron."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiosqlite

from ..config import get_config_dir
from .models import (
    AlertCreate,
    AlertDB,
    AlertFilter,
    AgentProfileCreate,
    AgentProfileDB,
    CausalNodeCreate,
    CausalNodeDB,
    Event,
    EventCreate,
    EventFilter,
    HoneypotCreate,
    HoneypotDB,
    Pattern,
    ProfileSnapshotDB,
    SandboxFilter,
    SandboxResultCreate,
    SandboxResultDB,
    Stats,
    TaintCreate,
    TaintDB,
    TaintPropagationCreate,
    TaintPropagationDB,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    request_id TEXT NOT NULL,
    agent_id TEXT,
    source_tag TEXT,
    threat_score INTEGER DEFAULT 0,
    injection_detected BOOLEAN DEFAULT FALSE,
    injection_patterns TEXT,
    tool_name TEXT,
    risk_tier INTEGER,
    action TEXT NOT NULL,
    block_reason TEXT,
    request_summary TEXT,
    response_summary TEXT,
    llm_provider TEXT,
    model TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id);

CREATE TABLE IF NOT EXISTS patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    category TEXT NOT NULL,
    weight INTEGER DEFAULT 10,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    source TEXT DEFAULT 'default',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE NOT NULL UNIQUE,
    total_requests INTEGER DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    injection_attempts INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sandbox_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id TEXT NOT NULL UNIQUE,
    tool_name TEXT NOT NULL,
    tool_arguments TEXT,
    command TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    file_changes TEXT,
    duration_ms INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    approved_at DATETIME,
    rejected_at DATETIME,
    error_message TEXT,
    source_tag TEXT,
    risk_tier INTEGER,
    threat_score INTEGER DEFAULT 0,
    agent_id TEXT,
    request_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_sandbox_status ON sandbox_results(status);
CREATE INDEX IF NOT EXISTS idx_sandbox_created ON sandbox_results(created_at);
CREATE INDEX IF NOT EXISTS idx_sandbox_agent ON sandbox_results(agent_id);

-- Causal chain tracking
CREATE TABLE IF NOT EXISTS causal_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL,
    parent_id TEXT,
    node_type TEXT NOT NULL,
    source_tag TEXT NOT NULL,
    content_hash TEXT,
    content_preview TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_score REAL DEFAULT 0,
    metadata TEXT,
    FOREIGN KEY (parent_id) REFERENCES causal_nodes(node_id)
);
CREATE INDEX IF NOT EXISTS idx_causal_request ON causal_nodes(request_id);
CREATE INDEX IF NOT EXISTS idx_causal_parent ON causal_nodes(parent_id);
CREATE INDEX IF NOT EXISTS idx_causal_timestamp ON causal_nodes(timestamp);

-- Agent behavioral profiles
CREATE TABLE IF NOT EXISTS agent_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_requests INTEGER DEFAULT 0,
    profile_data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profile_agent ON agent_profiles(agent_id);

-- Profile snapshots for historical analysis
CREATE TABLE IF NOT EXISTS profile_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL UNIQUE,
    agent_id TEXT NOT NULL,
    snapshot_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    profile_data TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agent_profiles(agent_id)
);
CREATE INDEX IF NOT EXISTS idx_snapshot_agent ON profile_snapshots(agent_id);

-- Honeypot tracking
CREATE TABLE IF NOT EXISTS honeypots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    honeypot_type TEXT NOT NULL,
    request_id TEXT NOT NULL,
    agent_id TEXT,
    injected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    injected_in TEXT,
    content_context TEXT,
    triggered_at DATETIME,
    triggered_by_tool TEXT,
    triggered_args TEXT
);
CREATE INDEX IF NOT EXISTS idx_honeypot_token ON honeypots(token);
CREATE INDEX IF NOT EXISTS idx_honeypot_request ON honeypots(request_id);
CREATE INDEX IF NOT EXISTS idx_honeypot_agent ON honeypots(agent_id);

-- Memory taint tracking
CREATE TABLE IF NOT EXISTS taints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taint_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    source_tag TEXT NOT NULL,
    source_description TEXT,
    tainted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    keywords TEXT,
    content_preview TEXT
);
CREATE INDEX IF NOT EXISTS idx_taint_request ON taints(request_id);
CREATE INDEX IF NOT EXISTS idx_taint_hash ON taints(content_hash);

-- Taint propagation tracking
CREATE TABLE IF NOT EXISTS taint_propagations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    propagation_id TEXT NOT NULL UNIQUE,
    source_taint_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    propagated_to TEXT NOT NULL,
    propagation_type TEXT NOT NULL,
    confidence REAL DEFAULT 0,
    tool_name TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_taint_id) REFERENCES taints(taint_id)
);
CREATE INDEX IF NOT EXISTS idx_propagation_taint ON taint_propagations(source_taint_id);
CREATE INDEX IF NOT EXISTS idx_propagation_request ON taint_propagations(request_id);

-- Alerts for exfiltration, hijack, honeypot triggers
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL UNIQUE,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    request_id TEXT,
    agent_id TEXT,
    tool_name TEXT,
    description TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at DATETIME,
    resolved_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_alert_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alert_created ON alerts(created_at);
"""


class Database:
    """Async database manager for Theron."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or get_config_dir() / "theron.db"
        self._connection: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Connect to the database and initialize schema."""
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._connection.executescript(SCHEMA)
        await self._connection.commit()

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None

    async def __aenter__(self) -> "Database":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    @property
    def connection(self) -> aiosqlite.Connection:
        if self._connection is None:
            raise RuntimeError("Database not connected")
        return self._connection

    # Event operations
    async def create_event(self, event: EventCreate) -> int:
        """Create a new event and return its ID."""
        cursor = await self.connection.execute(
            """
            INSERT INTO events (
                request_id, agent_id, source_tag, threat_score,
                injection_detected, injection_patterns, tool_name,
                risk_tier, action, block_reason, request_summary,
                response_summary, llm_provider, model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.request_id,
                event.agent_id,
                event.source_tag,
                event.threat_score,
                event.injection_detected,
                event.injection_patterns,
                event.tool_name,
                event.risk_tier,
                event.action,
                event.block_reason,
                event.request_summary,
                event.response_summary,
                event.llm_provider,
                event.model,
            ),
        )
        await self.connection.commit()

        # Update daily stats
        await self._update_stats(event)

        return cursor.lastrowid  # type: ignore

    async def _update_stats(self, event: EventCreate) -> None:
        """Update daily statistics."""
        today = datetime.utcnow().strftime("%Y-%m-%d")

        # Upsert stats
        await self.connection.execute(
            """
            INSERT INTO stats (date, total_requests, blocked_requests, injection_attempts)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(date) DO UPDATE SET
                total_requests = total_requests + 1,
                blocked_requests = blocked_requests + ?,
                injection_attempts = injection_attempts + ?
            """,
            (
                today,
                1 if event.action == "blocked" else 0,
                1 if event.injection_detected else 0,
                1 if event.action == "blocked" else 0,
                1 if event.injection_detected else 0,
            ),
        )
        await self.connection.commit()

    async def get_event(self, event_id: int) -> Optional[Event]:
        """Get an event by ID."""
        cursor = await self.connection.execute(
            "SELECT * FROM events WHERE id = ?", (event_id,)
        )
        row = await cursor.fetchone()
        if row:
            return Event(**dict(row))
        return None

    async def get_events(self, filter: Optional[EventFilter] = None) -> list[Event]:
        """Get events with optional filtering."""
        filter = filter or EventFilter()

        query = "SELECT * FROM events WHERE 1=1"
        params: list = []

        if filter.agent_id:
            query += " AND agent_id = ?"
            params.append(filter.agent_id)

        if filter.action:
            query += " AND action = ?"
            params.append(filter.action)

        if filter.source_tag:
            query += " AND source_tag = ?"
            params.append(filter.source_tag)

        if filter.risk_tier:
            query += " AND risk_tier = ?"
            params.append(filter.risk_tier)

        if filter.injection_detected is not None:
            query += " AND injection_detected = ?"
            params.append(filter.injection_detected)

        if filter.start_date:
            query += " AND timestamp >= ?"
            params.append(filter.start_date.isoformat())

        if filter.end_date:
            query += " AND timestamp <= ?"
            params.append(filter.end_date.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([filter.limit, filter.offset])

        cursor = await self.connection.execute(query, params)
        rows = await cursor.fetchall()
        return [Event(**dict(row)) for row in rows]

    async def get_recent_events(self, limit: int = 50) -> list[Event]:
        """Get most recent events."""
        return await self.get_events(EventFilter(limit=limit))

    # Stats operations
    async def get_stats(self, days: int = 7) -> list[Stats]:
        """Get statistics for the last N days."""
        cursor = await self.connection.execute(
            """
            SELECT * FROM stats
            ORDER BY date DESC
            LIMIT ?
            """,
            (days,),
        )
        rows = await cursor.fetchall()
        return [Stats(**dict(row)) for row in rows]

    async def get_summary_stats(self) -> dict:
        """Get summary statistics."""
        cursor = await self.connection.execute(
            """
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
                SUM(CASE WHEN injection_detected THEN 1 ELSE 0 END) as injection_count,
                COUNT(DISTINCT agent_id) as unique_agents
            FROM events
            """
        )
        row = await cursor.fetchone()
        return dict(row) if row else {}

    # Pattern operations
    async def add_pattern(self, pattern: Pattern) -> int:
        """Add a custom pattern."""
        cursor = await self.connection.execute(
            """
            INSERT INTO patterns (pattern, category, weight, description, enabled, source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                pattern.pattern,
                pattern.category,
                pattern.weight,
                pattern.description,
                pattern.enabled,
                pattern.source,
            ),
        )
        await self.connection.commit()
        return cursor.lastrowid  # type: ignore

    async def get_patterns(self, enabled_only: bool = True) -> list[Pattern]:
        """Get all patterns."""
        query = "SELECT * FROM patterns"
        if enabled_only:
            query += " WHERE enabled = TRUE"

        cursor = await self.connection.execute(query)
        rows = await cursor.fetchall()
        return [Pattern(**dict(row)) for row in rows]

    async def delete_old_events(self, retention_days: int) -> int:
        """Delete events older than retention period."""
        cursor = await self.connection.execute(
            """
            DELETE FROM events
            WHERE timestamp < datetime('now', ?)
            """,
            (f"-{retention_days} days",),
        )
        await self.connection.commit()
        return cursor.rowcount

    # Sandbox operations
    async def create_sandbox_result(self, result: SandboxResultCreate) -> str:
        """Create a new sandbox result and return its sandbox_id."""
        tool_args_json = json.dumps(result.tool_arguments)
        file_changes_json = json.dumps(result.file_changes) if result.file_changes else None

        await self.connection.execute(
            """
            INSERT INTO sandbox_results (
                sandbox_id, tool_name, tool_arguments, command, status,
                exit_code, stdout, stderr, file_changes, duration_ms,
                completed_at, error_message, source_tag, risk_tier,
                threat_score, agent_id, request_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.sandbox_id,
                result.tool_name,
                tool_args_json,
                result.command,
                result.status,
                result.exit_code,
                result.stdout,
                result.stderr,
                file_changes_json,
                result.duration_ms,
                result.completed_at.isoformat() if result.completed_at else None,
                result.error_message,
                result.source_tag,
                result.risk_tier,
                result.threat_score,
                result.agent_id,
                result.request_id,
            ),
        )
        await self.connection.commit()
        return result.sandbox_id

    async def get_sandbox_result(self, sandbox_id: str) -> Optional[SandboxResultDB]:
        """Get a sandbox result by ID."""
        cursor = await self.connection.execute(
            "SELECT * FROM sandbox_results WHERE sandbox_id = ?", (sandbox_id,)
        )
        row = await cursor.fetchone()
        if row:
            return SandboxResultDB(**dict(row))
        return None

    async def get_sandbox_results(
        self, filter: Optional[SandboxFilter] = None
    ) -> list[SandboxResultDB]:
        """Get sandbox results with optional filtering."""
        filter = filter or SandboxFilter()

        query = "SELECT * FROM sandbox_results WHERE 1=1"
        params: list = []

        if filter.status:
            query += " AND status = ?"
            params.append(filter.status)

        if filter.agent_id:
            query += " AND agent_id = ?"
            params.append(filter.agent_id)

        if filter.tool_name:
            query += " AND tool_name = ?"
            params.append(filter.tool_name)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([filter.limit, filter.offset])

        cursor = await self.connection.execute(query, params)
        rows = await cursor.fetchall()
        return [SandboxResultDB(**dict(row)) for row in rows]

    async def get_pending_sandbox_results(self) -> list[SandboxResultDB]:
        """Get all pending sandbox results awaiting approval."""
        return await self.get_sandbox_results(SandboxFilter(status="completed"))

    async def update_sandbox_status(
        self,
        sandbox_id: str,
        status: str,
        approved_at: Optional[datetime] = None,
        rejected_at: Optional[datetime] = None,
    ) -> bool:
        """Update the status of a sandbox result."""
        if status == "approved" and approved_at:
            cursor = await self.connection.execute(
                "UPDATE sandbox_results SET status = ?, approved_at = ? WHERE sandbox_id = ?",
                (status, approved_at.isoformat(), sandbox_id),
            )
        elif status == "rejected" and rejected_at:
            cursor = await self.connection.execute(
                "UPDATE sandbox_results SET status = ?, rejected_at = ? WHERE sandbox_id = ?",
                (status, rejected_at.isoformat(), sandbox_id),
            )
        else:
            cursor = await self.connection.execute(
                "UPDATE sandbox_results SET status = ? WHERE sandbox_id = ?",
                (status, sandbox_id),
            )
        await self.connection.commit()
        return cursor.rowcount > 0

    async def delete_old_sandbox_results(self, retention_days: int = 7) -> int:
        """Delete sandbox results older than retention period."""
        cursor = await self.connection.execute(
            """
            DELETE FROM sandbox_results
            WHERE created_at < datetime('now', ?)
            """,
            (f"-{retention_days} days",),
        )
        await self.connection.commit()
        return cursor.rowcount

    # ============== Causal Chain Operations ==============

    async def create_causal_node(self, node: CausalNodeCreate) -> str:
        """Create a new causal node and return its node_id."""
        metadata_json = json.dumps(node.metadata) if node.metadata else None

        await self.connection.execute(
            """
            INSERT INTO causal_nodes (
                node_id, request_id, parent_id, node_type, source_tag,
                content_hash, content_preview, threat_score, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                node.node_id,
                node.request_id,
                node.parent_id,
                node.node_type,
                node.source_tag,
                node.content_hash,
                node.content_preview,
                node.threat_score,
                metadata_json,
            ),
        )
        await self.connection.commit()
        return node.node_id

    async def get_causal_nodes(self, request_id: str) -> list[CausalNodeDB]:
        """Get all causal nodes for a request."""
        cursor = await self.connection.execute(
            "SELECT * FROM causal_nodes WHERE request_id = ? ORDER BY timestamp",
            (request_id,),
        )
        rows = await cursor.fetchall()
        return [CausalNodeDB(**dict(row)) for row in rows]

    async def get_causal_node(self, node_id: str) -> Optional[CausalNodeDB]:
        """Get a specific causal node."""
        cursor = await self.connection.execute(
            "SELECT * FROM causal_nodes WHERE node_id = ?", (node_id,)
        )
        row = await cursor.fetchone()
        return CausalNodeDB(**dict(row)) if row else None

    async def get_causal_chain_roots(self, limit: int = 50) -> list[CausalNodeDB]:
        """Get root nodes (requests) for chain visualization."""
        cursor = await self.connection.execute(
            """
            SELECT * FROM causal_nodes
            WHERE parent_id IS NULL
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        return [CausalNodeDB(**dict(row)) for row in rows]

    # ============== Alert Operations ==============

    async def create_alert(self, alert: AlertCreate) -> str:
        """Create a new alert and return its alert_id."""
        details_json = json.dumps(alert.details) if alert.details else None

        await self.connection.execute(
            """
            INSERT INTO alerts (
                alert_id, alert_type, severity, request_id, agent_id,
                tool_name, description, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.alert_type,
                alert.severity,
                alert.request_id,
                alert.agent_id,
                alert.tool_name,
                alert.description,
                details_json,
            ),
        )
        await self.connection.commit()
        return alert.alert_id

    async def get_alerts(self, filter: Optional[AlertFilter] = None) -> list[AlertDB]:
        """Get alerts with optional filtering."""
        filter = filter or AlertFilter()

        query = "SELECT * FROM alerts WHERE 1=1"
        params: list = []

        if filter.alert_type:
            query += " AND alert_type = ?"
            params.append(filter.alert_type)

        if filter.severity:
            query += " AND severity = ?"
            params.append(filter.severity)

        if filter.agent_id:
            query += " AND agent_id = ?"
            params.append(filter.agent_id)

        if filter.acknowledged is not None:
            if filter.acknowledged:
                query += " AND acknowledged_at IS NOT NULL"
            else:
                query += " AND acknowledged_at IS NULL"

        if filter.resolved is not None:
            if filter.resolved:
                query += " AND resolved_at IS NOT NULL"
            else:
                query += " AND resolved_at IS NULL"

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([filter.limit, filter.offset])

        cursor = await self.connection.execute(query, params)
        rows = await cursor.fetchall()
        return [AlertDB(**dict(row)) for row in rows]

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        cursor = await self.connection.execute(
            "UPDATE alerts SET acknowledged_at = ? WHERE alert_id = ?",
            (datetime.utcnow().isoformat(), alert_id),
        )
        await self.connection.commit()
        return cursor.rowcount > 0

    async def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        cursor = await self.connection.execute(
            "UPDATE alerts SET resolved_at = ? WHERE alert_id = ?",
            (datetime.utcnow().isoformat(), alert_id),
        )
        await self.connection.commit()
        return cursor.rowcount > 0

    # ============== Honeypot Operations ==============

    async def create_honeypot(self, honeypot: HoneypotCreate) -> str:
        """Create a new honeypot and return its token."""
        await self.connection.execute(
            """
            INSERT INTO honeypots (
                token, honeypot_type, request_id, agent_id,
                injected_in, content_context
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                honeypot.token,
                honeypot.honeypot_type,
                honeypot.request_id,
                honeypot.agent_id,
                honeypot.injected_in,
                honeypot.content_context,
            ),
        )
        await self.connection.commit()
        return honeypot.token

    async def get_honeypot(self, token: str) -> Optional[HoneypotDB]:
        """Get a honeypot by token."""
        cursor = await self.connection.execute(
            "SELECT * FROM honeypots WHERE token = ?", (token,)
        )
        row = await cursor.fetchone()
        return HoneypotDB(**dict(row)) if row else None

    async def get_active_honeypots(self, agent_id: Optional[str] = None) -> list[HoneypotDB]:
        """Get all active (non-triggered) honeypots."""
        query = "SELECT * FROM honeypots WHERE triggered_at IS NULL"
        params: list = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        query += " ORDER BY injected_at DESC"

        cursor = await self.connection.execute(query, params)
        rows = await cursor.fetchall()
        return [HoneypotDB(**dict(row)) for row in rows]

    async def trigger_honeypot(
        self, token: str, triggered_by_tool: str, triggered_args: str
    ) -> bool:
        """Mark a honeypot as triggered."""
        cursor = await self.connection.execute(
            """
            UPDATE honeypots
            SET triggered_at = ?, triggered_by_tool = ?, triggered_args = ?
            WHERE token = ?
            """,
            (datetime.utcnow().isoformat(), triggered_by_tool, triggered_args, token),
        )
        await self.connection.commit()
        return cursor.rowcount > 0

    async def get_triggered_honeypots(self, limit: int = 50) -> list[HoneypotDB]:
        """Get triggered honeypots."""
        cursor = await self.connection.execute(
            """
            SELECT * FROM honeypots
            WHERE triggered_at IS NOT NULL
            ORDER BY triggered_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        return [HoneypotDB(**dict(row)) for row in rows]

    # ============== Taint Operations ==============

    async def create_taint(self, taint: TaintCreate) -> str:
        """Create a new taint entry and return its taint_id."""
        keywords_json = json.dumps(taint.keywords) if taint.keywords else None

        await self.connection.execute(
            """
            INSERT INTO taints (
                taint_id, request_id, content_hash, source_tag,
                source_description, keywords, content_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                taint.taint_id,
                taint.request_id,
                taint.content_hash,
                taint.source_tag,
                taint.source_description,
                keywords_json,
                taint.content_preview,
            ),
        )
        await self.connection.commit()
        return taint.taint_id

    async def get_taints(self, request_id: str) -> list[TaintDB]:
        """Get all taints for a request."""
        cursor = await self.connection.execute(
            "SELECT * FROM taints WHERE request_id = ? ORDER BY tainted_at",
            (request_id,),
        )
        rows = await cursor.fetchall()
        return [TaintDB(**dict(row)) for row in rows]

    async def create_taint_propagation(self, propagation: TaintPropagationCreate) -> str:
        """Create a taint propagation record."""
        await self.connection.execute(
            """
            INSERT INTO taint_propagations (
                propagation_id, source_taint_id, request_id, propagated_to,
                propagation_type, confidence, tool_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                propagation.propagation_id,
                propagation.source_taint_id,
                propagation.request_id,
                propagation.propagated_to,
                propagation.propagation_type,
                propagation.confidence,
                propagation.tool_name,
            ),
        )
        await self.connection.commit()
        return propagation.propagation_id

    async def get_taint_propagations(self, request_id: str) -> list[TaintPropagationDB]:
        """Get all taint propagations for a request."""
        cursor = await self.connection.execute(
            "SELECT * FROM taint_propagations WHERE request_id = ? ORDER BY detected_at",
            (request_id,),
        )
        rows = await cursor.fetchall()
        return [TaintPropagationDB(**dict(row)) for row in rows]

    # ============== Agent Profile Operations ==============

    async def create_or_update_profile(self, profile: AgentProfileCreate) -> str:
        """Create or update an agent profile."""
        profile_json = json.dumps(profile.profile_data)

        await self.connection.execute(
            """
            INSERT INTO agent_profiles (agent_id, profile_data)
            VALUES (?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                last_updated = CURRENT_TIMESTAMP,
                total_requests = total_requests + 1,
                profile_data = ?
            """,
            (profile.agent_id, profile_json, profile_json),
        )
        await self.connection.commit()
        return profile.agent_id

    async def get_agent_profile(self, agent_id: str) -> Optional[AgentProfileDB]:
        """Get an agent profile."""
        cursor = await self.connection.execute(
            "SELECT * FROM agent_profiles WHERE agent_id = ?", (agent_id,)
        )
        row = await cursor.fetchone()
        return AgentProfileDB(**dict(row)) if row else None

    async def get_all_agent_profiles(self) -> list[AgentProfileDB]:
        """Get all agent profiles."""
        cursor = await self.connection.execute(
            "SELECT * FROM agent_profiles ORDER BY last_updated DESC"
        )
        rows = await cursor.fetchall()
        return [AgentProfileDB(**dict(row)) for row in rows]

    async def create_profile_snapshot(
        self, snapshot_id: str, agent_id: str, profile_data: dict
    ) -> str:
        """Create a profile snapshot for historical analysis."""
        profile_json = json.dumps(profile_data)

        await self.connection.execute(
            """
            INSERT INTO profile_snapshots (snapshot_id, agent_id, profile_data)
            VALUES (?, ?, ?)
            """,
            (snapshot_id, agent_id, profile_json),
        )
        await self.connection.commit()
        return snapshot_id

    async def get_profile_snapshots(
        self, agent_id: str, limit: int = 30
    ) -> list[ProfileSnapshotDB]:
        """Get profile snapshots for an agent."""
        cursor = await self.connection.execute(
            """
            SELECT * FROM profile_snapshots
            WHERE agent_id = ?
            ORDER BY snapshot_at DESC
            LIMIT ?
            """,
            (agent_id, limit),
        )
        rows = await cursor.fetchall()
        return [ProfileSnapshotDB(**dict(row)) for row in rows]

    # ============== Intelligence Summary Operations ==============

    async def get_intelligence_summary(self) -> dict:
        """Get summary of all intelligence data."""
        # Get alert counts by type
        alert_cursor = await self.connection.execute(
            """
            SELECT alert_type, severity, COUNT(*) as count
            FROM alerts
            WHERE resolved_at IS NULL
            GROUP BY alert_type, severity
            """
        )
        alert_rows = await alert_cursor.fetchall()

        # Get honeypot stats
        honeypot_cursor = await self.connection.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN triggered_at IS NOT NULL THEN 1 ELSE 0 END) as triggered
            FROM honeypots
            """
        )
        honeypot_row = await honeypot_cursor.fetchone()

        # Get taint stats
        taint_cursor = await self.connection.execute(
            "SELECT COUNT(*) as total FROM taints"
        )
        taint_row = await taint_cursor.fetchone()

        # Get propagation stats
        prop_cursor = await self.connection.execute(
            "SELECT COUNT(*) as total FROM taint_propagations"
        )
        prop_row = await prop_cursor.fetchone()

        # Get profile count
        profile_cursor = await self.connection.execute(
            "SELECT COUNT(*) as total FROM agent_profiles"
        )
        profile_row = await profile_cursor.fetchone()

        return {
            "alerts": [dict(row) for row in alert_rows],
            "honeypots": dict(honeypot_row) if honeypot_row else {"total": 0, "triggered": 0},
            "taints": dict(taint_row) if taint_row else {"total": 0},
            "propagations": dict(prop_row) if prop_row else {"total": 0},
            "profiles": dict(profile_row) if profile_row else {"total": 0},
        }


# Global database instance
_database: Optional[Database] = None


async def get_database() -> Database:
    """Get the global database instance."""
    global _database
    if _database is None:
        _database = Database()
        await _database.connect()
    return _database


async def close_database() -> None:
    """Close the global database connection."""
    global _database
    if _database:
        await _database.close()
        _database = None
