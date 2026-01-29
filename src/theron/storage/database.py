"""Database operations for Theron."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiosqlite

from ..config import get_config_dir
from .models import Event, EventCreate, EventFilter, Pattern, Stats

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
