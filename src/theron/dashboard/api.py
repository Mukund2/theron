"""Dashboard REST API for Theron."""

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from ..config import TheronConfig, get_config, save_config
from ..storage import get_database
from ..storage.models import EventFilter

logger = logging.getLogger(__name__)

# Get the static files directory
STATIC_DIR = Path(__file__).parent.parent.parent.parent / "static"


class ConnectionManager:
    """Manages WebSocket connections for live updates."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)


# Global connection manager
manager = ConnectionManager()


async def broadcast_event(event: dict):
    """Broadcast a new event to all connected dashboard clients."""
    await manager.broadcast({"type": "new_event", "data": event})


def create_dashboard_app(config: TheronConfig | None = None) -> FastAPI:
    """Create the FastAPI dashboard application."""
    config = config or get_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        await get_database()
        yield
        # Shutdown
        pass

    app = FastAPI(
        title="Theron Dashboard",
        description="Security dashboard for agentic AI systems",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Serve static files if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_root():
        """Serve the dashboard HTML."""
        index_path = STATIC_DIR / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return HTMLResponse(
            content="<h1>Theron Dashboard</h1><p>Static files not found. Please ensure the static directory is properly configured.</p>",
            status_code=200,
        )

    @app.get("/api/events")
    async def get_events(
        agent_id: Optional[str] = Query(None),
        action: Optional[str] = Query(None),
        source_tag: Optional[str] = Query(None),
        risk_tier: Optional[int] = Query(None),
        injection_detected: Optional[bool] = Query(None),
        limit: int = Query(100, le=1000),
        offset: int = Query(0),
    ):
        """Get events with optional filtering."""
        db = await get_database()

        filter = EventFilter(
            agent_id=agent_id,
            action=action,
            source_tag=source_tag,
            risk_tier=risk_tier,
            injection_detected=injection_detected,
            limit=limit,
            offset=offset,
        )

        events = await db.get_events(filter)
        return {
            "events": [e.model_dump() for e in events],
            "count": len(events),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/events/{event_id}")
    async def get_event(event_id: int):
        """Get a single event by ID."""
        db = await get_database()
        event = await db.get_event(event_id)
        if event:
            return event.model_dump()
        return {"error": "Event not found"}, 404

    @app.get("/api/stats")
    async def get_stats(days: int = Query(7, le=30)):
        """Get statistics for the dashboard."""
        db = await get_database()

        daily_stats = await db.get_stats(days)
        summary = await db.get_summary_stats()

        return {
            "summary": summary,
            "daily": [s.model_dump() for s in daily_stats],
        }

    @app.get("/api/stats/summary")
    async def get_summary_stats():
        """Get summary statistics."""
        db = await get_database()
        return await db.get_summary_stats()

    @app.get("/api/config")
    async def get_current_config():
        """Get the current configuration."""
        current_config = get_config()
        return current_config.model_dump()

    @app.put("/api/config")
    async def update_config(new_config: dict):
        """Update the configuration."""
        try:
            current = get_config()
            # Merge with new config
            updated_data = current.model_dump()
            for key, value in new_config.items():
                if key in updated_data:
                    if isinstance(value, dict) and isinstance(updated_data[key], dict):
                        updated_data[key].update(value)
                    else:
                        updated_data[key] = value

            updated = TheronConfig(**updated_data)
            save_config(updated)
            return {"status": "success", "message": "Configuration updated"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @app.websocket("/api/events/stream")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket endpoint for live event streaming."""
        await manager.connect(websocket)
        try:
            # Send initial connection message
            await websocket.send_json({
                "type": "connected",
                "message": "Connected to Theron event stream",
            })

            # Keep connection alive and handle incoming messages
            while True:
                try:
                    data = await websocket.receive_text()
                    # Handle ping/pong for keepalive
                    if data == "ping":
                        await websocket.send_text("pong")
                except WebSocketDisconnect:
                    break
                except Exception:
                    break
        finally:
            manager.disconnect(websocket)

    @app.get("/api/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "theron-dashboard",
            "timestamp": datetime.utcnow().isoformat(),
        }

    @app.get("/api/agents")
    async def get_agents():
        """Get list of unique agents that have connected."""
        db = await get_database()
        # Query unique agent IDs from events
        cursor = await db.connection.execute(
            "SELECT DISTINCT agent_id FROM events WHERE agent_id IS NOT NULL"
        )
        rows = await cursor.fetchall()
        return {"agents": [row[0] for row in rows]}

    @app.post("/api/events/export")
    async def export_events(
        format: str = Query("json", regex="^(json|csv)$"),
        agent_id: Optional[str] = Query(None),
        action: Optional[str] = Query(None),
        limit: int = Query(1000, le=10000),
    ):
        """Export events to JSON or CSV format."""
        db = await get_database()

        filter = EventFilter(agent_id=agent_id, action=action, limit=limit)
        events = await db.get_events(filter)

        if format == "csv":
            import csv
            import io

            output = io.StringIO()
            if events:
                writer = csv.DictWriter(output, fieldnames=events[0].model_dump().keys())
                writer.writeheader()
                for event in events:
                    writer.writerow(event.model_dump())

            return {
                "format": "csv",
                "data": output.getvalue(),
                "count": len(events),
            }
        else:
            return {
                "format": "json",
                "data": [e.model_dump() for e in events],
                "count": len(events),
            }

    return app
