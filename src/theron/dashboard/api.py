"""Dashboard REST API for Theron."""

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import TheronConfig, get_config, save_config
from ..intelligence import get_intelligence_manager
from ..sandbox import get_sandbox_manager
from ..storage import get_database
from ..storage.models import AlertFilter, EventFilter, SandboxFilter, SandboxResultCreate

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


async def broadcast_sandbox_blocked(sandbox_data: dict):
    """Broadcast a blocked action that was sandboxed and auto-rejected."""
    await manager.broadcast({"type": "sandbox_blocked", "data": sandbox_data})


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

    # Sandbox endpoints
    @app.get("/api/sandbox/blocked")
    async def get_blocked_sandbox():
        """Get recently blocked actions that were sandboxed and auto-rejected."""
        db = await get_database()
        # Get recently rejected sandbox results
        filter = SandboxFilter(status="rejected", limit=50)
        results = await db.get_sandbox_results(filter)
        return {
            "results": [_sandbox_result_to_dict(r) for r in results],
            "count": len(results),
        }

    @app.get("/api/sandbox/pending")
    async def get_pending_sandbox():
        """Legacy endpoint - returns empty since all actions are auto-rejected."""
        return {
            "results": [],
            "count": 0,
            "message": "Theron auto-rejects dangerous actions. See /api/sandbox/blocked for blocked actions.",
        }

    @app.get("/api/sandbox")
    async def get_sandbox_results(
        status: Optional[str] = Query(None),
        agent_id: Optional[str] = Query(None),
        tool_name: Optional[str] = Query(None),
        limit: int = Query(50, le=500),
        offset: int = Query(0),
    ):
        """Get sandbox results with optional filtering."""
        db = await get_database()

        filter = SandboxFilter(
            status=status,
            agent_id=agent_id,
            tool_name=tool_name,
            limit=limit,
            offset=offset,
        )

        results = await db.get_sandbox_results(filter)
        return {
            "results": [_sandbox_result_to_dict(r) for r in results],
            "count": len(results),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/sandbox/{sandbox_id}")
    async def get_sandbox_result(sandbox_id: str):
        """Get a single sandbox result by ID."""
        db = await get_database()
        result = await db.get_sandbox_result(sandbox_id)
        if not result:
            raise HTTPException(status_code=404, detail="Sandbox result not found")
        return _sandbox_result_to_dict(result)

    @app.post("/api/sandbox/{sandbox_id}/approve")
    async def approve_sandbox(sandbox_id: str):
        """Manual approval is disabled - Theron auto-rejects dangerous actions."""
        raise HTTPException(
            status_code=400,
            detail="Manual approval is disabled. Theron automatically blocks dangerous actions from untrusted sources."
        )

    @app.post("/api/sandbox/{sandbox_id}/reject")
    async def reject_sandbox(sandbox_id: str):
        """Manual rejection is not needed - Theron auto-rejects dangerous actions."""
        raise HTTPException(
            status_code=400,
            detail="Manual rejection is not needed. Theron automatically blocks dangerous actions from untrusted sources."
        )

    @app.get("/api/sandbox/status")
    async def get_sandbox_status():
        """Get sandbox system status."""
        sandbox_mgr = get_sandbox_manager()
        db = await get_database()

        docker_available = await sandbox_mgr.is_available()

        # Get count of recently blocked actions
        filter = SandboxFilter(status="rejected", limit=100)
        blocked = await db.get_sandbox_results(filter)

        return {
            "docker_available": docker_available,
            "blocked_count": len(blocked),
            "mode": "auto-reject",
        }

    # ============== Intelligence Endpoints ==============

    @app.get("/api/intelligence/summary")
    async def get_intelligence_summary():
        """Get overall intelligence summary."""
        db = await get_database()
        intel_mgr = get_intelligence_manager(db)

        db_summary = await db.get_intelligence_summary()
        mgr_summary = intel_mgr.get_intelligence_summary()

        return {
            "database": db_summary,
            "runtime": mgr_summary,
        }

    @app.get("/api/chains")
    async def get_causal_chains(
        limit: int = Query(50, le=200),
    ):
        """Get recent causal chain roots for visualization."""
        db = await get_database()
        roots = await db.get_causal_chain_roots(limit)
        return {
            "chains": [r.model_dump() for r in roots],
            "count": len(roots),
        }

    @app.get("/api/chains/{request_id}")
    async def get_causal_chain(request_id: str):
        """Get a specific causal chain by request ID."""
        db = await get_database()
        nodes = await db.get_causal_nodes(request_id)

        if not nodes:
            raise HTTPException(status_code=404, detail="Causal chain not found")

        # Build graph structure for visualization
        node_list = []
        edge_list = []

        for node in nodes:
            node_data = node.model_dump()
            if node_data.get("metadata"):
                try:
                    node_data["metadata"] = json.loads(node_data["metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            node_list.append(node_data)

            if node.parent_id:
                edge_list.append({
                    "source": node.parent_id,
                    "target": node.node_id,
                })

        return {
            "request_id": request_id,
            "nodes": node_list,
            "edges": edge_list,
            "total_nodes": len(nodes),
        }

    @app.get("/api/alerts")
    async def get_alerts(
        alert_type: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        agent_id: Optional[str] = Query(None),
        acknowledged: Optional[bool] = Query(None),
        resolved: Optional[bool] = Query(None),
        limit: int = Query(50, le=500),
        offset: int = Query(0),
    ):
        """Get security alerts with optional filtering."""
        db = await get_database()

        filter = AlertFilter(
            alert_type=alert_type,
            severity=severity,
            agent_id=agent_id,
            acknowledged=acknowledged,
            resolved=resolved,
            limit=limit,
            offset=offset,
        )

        alerts = await db.get_alerts(filter)
        return {
            "alerts": [_alert_to_dict(a) for a in alerts],
            "count": len(alerts),
            "limit": limit,
            "offset": offset,
        }

    @app.post("/api/alerts/{alert_id}/acknowledge")
    async def acknowledge_alert(alert_id: str):
        """Acknowledge an alert."""
        db = await get_database()
        success = await db.acknowledge_alert(alert_id)

        if success:
            await manager.broadcast({
                "type": "alert_acknowledged",
                "data": {"alert_id": alert_id},
            })
            return {"status": "success", "message": "Alert acknowledged"}
        else:
            raise HTTPException(status_code=404, detail="Alert not found")

    @app.post("/api/alerts/{alert_id}/resolve")
    async def resolve_alert(alert_id: str):
        """Resolve an alert."""
        db = await get_database()
        success = await db.resolve_alert(alert_id)

        if success:
            await manager.broadcast({
                "type": "alert_resolved",
                "data": {"alert_id": alert_id},
            })
            return {"status": "success", "message": "Alert resolved"}
        else:
            raise HTTPException(status_code=404, detail="Alert not found")

    @app.get("/api/agents/{agent_id}/profile")
    async def get_agent_profile(agent_id: str):
        """Get behavioral profile for an agent."""
        db = await get_database()
        intel_mgr = get_intelligence_manager(db)

        # Try to get from runtime first
        profile = intel_mgr.baseline_mgr.get_baseline(agent_id)
        if profile:
            return {
                "source": "runtime",
                "profile": intel_mgr.baseline_mgr.get_profile_summary(agent_id),
                "has_baseline": True,
            }

        # Fall back to database
        db_profile = await db.get_agent_profile(agent_id)
        if db_profile:
            profile_data = json.loads(db_profile.profile_data)
            return {
                "source": "database",
                "profile": profile_data,
                "has_baseline": db_profile.total_requests >= 25,
            }

        return {
            "source": None,
            "profile": None,
            "has_baseline": False,
            "message": "No profile found for this agent",
        }

    @app.get("/api/agents/{agent_id}/anomalies")
    async def get_agent_anomalies(
        agent_id: str,
        limit: int = Query(50, le=200),
    ):
        """Get anomaly history for an agent."""
        db = await get_database()

        # Get events where this agent had high threat scores or was blocked/sandboxed
        filter = EventFilter(
            agent_id=agent_id,
            limit=limit,
        )
        events = await db.get_events(filter)

        # Filter to potentially anomalous events
        anomalous = [
            e.model_dump() for e in events
            if e.threat_score > 50 or e.action in ("blocked", "sandboxed")
        ]

        return {
            "agent_id": agent_id,
            "anomalous_events": anomalous,
            "count": len(anomalous),
        }

    @app.get("/api/honeypots")
    async def get_honeypots(
        triggered: Optional[bool] = Query(None),
        limit: int = Query(50, le=200),
    ):
        """Get honeypot tracking data."""
        db = await get_database()
        intel_mgr = get_intelligence_manager(db)

        # Get active honeypots from runtime
        active = intel_mgr.honeypot_mgr.get_active_honeypots()
        stats = intel_mgr.honeypot_mgr.get_honeypot_stats()

        # Get triggered honeypots from database
        triggered_list = await db.get_triggered_honeypots(limit)

        return {
            "active_count": len(active),
            "stats": stats,
            "triggered": [h.model_dump() for h in triggered_list],
        }

    @app.get("/api/taints/{request_id}")
    async def get_taints(request_id: str):
        """Get taint tracking data for a request."""
        db = await get_database()

        taints = await db.get_taints(request_id)
        propagations = await db.get_taint_propagations(request_id)

        return {
            "request_id": request_id,
            "taints": [_taint_to_dict(t) for t in taints],
            "propagations": [p.model_dump() for p in propagations],
            "taint_count": len(taints),
            "propagation_count": len(propagations),
        }

    @app.get("/api/profiles")
    async def get_all_profiles():
        """Get all agent profiles."""
        db = await get_database()
        profiles = await db.get_all_agent_profiles()

        return {
            "profiles": [
                {
                    "agent_id": p.agent_id,
                    "total_requests": p.total_requests,
                    "created_at": p.created_at.isoformat() if p.created_at else None,
                    "last_updated": p.last_updated.isoformat() if p.last_updated else None,
                    "has_baseline": p.total_requests >= 25,
                }
                for p in profiles
            ],
            "count": len(profiles),
        }

    return app


def _alert_to_dict(alert) -> dict:
    """Convert an AlertDB to a dictionary for API response."""
    data = alert.model_dump()

    # Parse JSON details
    if data.get("details"):
        try:
            data["details"] = json.loads(data["details"])
        except (json.JSONDecodeError, TypeError):
            pass

    return data


def _taint_to_dict(taint) -> dict:
    """Convert a TaintDB to a dictionary for API response."""
    data = taint.model_dump()

    # Parse JSON keywords
    if data.get("keywords"):
        try:
            data["keywords"] = json.loads(data["keywords"])
        except (json.JSONDecodeError, TypeError):
            pass

    return data


def _sandbox_result_to_dict(result) -> dict:
    """Convert a SandboxResultDB to a dictionary for API response."""
    data = result.model_dump()

    # Parse JSON fields
    if data.get("tool_arguments"):
        try:
            data["tool_arguments"] = json.loads(data["tool_arguments"])
        except (json.JSONDecodeError, TypeError):
            pass

    if data.get("file_changes"):
        try:
            data["file_changes"] = json.loads(data["file_changes"])
        except (json.JSONDecodeError, TypeError):
            pass

    return data
