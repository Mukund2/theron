"""Main proxy server for Theron."""

import logging
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from ..config import TheronConfig, get_config
from ..security import ActionClassifier, ActionGate, InjectionDetector, SourceTagger
from ..storage import get_database
from .anthropic import AnthropicHandler
from .openai import OpenAIHandler

logger = logging.getLogger(__name__)


class ProxyServer:
    """Main proxy server that routes requests to appropriate handlers."""

    def __init__(self, config: TheronConfig):
        self.config = config
        self.tagger = SourceTagger(sensitivity=config.detection.sensitivity)
        self.detector = InjectionDetector(config)
        self.classifier = ActionClassifier(config)
        self.gate = ActionGate(config)

        self.anthropic_handler = AnthropicHandler(
            config, self.tagger, self.detector, self.classifier, self.gate
        )
        self.openai_handler = OpenAIHandler(
            config, self.tagger, self.detector, self.classifier, self.gate
        )

        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        """Start the proxy server."""
        self._client = httpx.AsyncClient(timeout=self.config.proxy.timeout)
        logger.info(f"Proxy server started on port {self.config.proxy.listen_port}")

    async def stop(self) -> None:
        """Stop the proxy server."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Proxy server not started")
        return self._client

    def detect_provider(self, request_data: dict[str, Any]) -> str:
        """Detect the LLM provider from request data."""
        if self.anthropic_handler.detect_api_format(request_data):
            return "anthropic"
        if self.openai_handler.detect_api_format(request_data):
            return "openai"
        # Default to OpenAI-compatible
        return "openai"

    async def handle_messages(
        self, request: Request, request_data: dict[str, Any]
    ) -> Response:
        """Handle a /v1/messages endpoint (Anthropic-style)."""
        headers = dict(request.headers)
        is_streaming = request_data.get("stream", False)

        if is_streaming:
            return StreamingResponse(
                self.anthropic_handler.process_request_streaming(
                    request_data, headers, self.client
                ),
                media_type="text/event-stream",
            )

        response_data, events = await self.anthropic_handler.process_request(
            request_data, headers, self.client
        )

        # Log events
        db = await get_database()
        for event in events:
            await db.create_event(event)

        return Response(
            content=self._json_dumps(response_data),
            media_type="application/json",
        )

    async def handle_chat_completions(
        self, request: Request, request_data: dict[str, Any]
    ) -> Response:
        """Handle a /v1/chat/completions endpoint (OpenAI-style)."""
        headers = dict(request.headers)
        is_streaming = request_data.get("stream", False)

        if is_streaming:
            return StreamingResponse(
                self.openai_handler.process_request_streaming(
                    request_data, headers, self.client
                ),
                media_type="text/event-stream",
            )

        response_data, events = await self.openai_handler.process_request(
            request_data, headers, self.client
        )

        # Log events
        db = await get_database()
        for event in events:
            await db.create_event(event)

        return Response(
            content=self._json_dumps(response_data),
            media_type="application/json",
        )

    async def handle_generic(
        self, request: Request, request_data: dict[str, Any]
    ) -> Response:
        """Handle a generic request by auto-detecting provider."""
        provider = self.detect_provider(request_data)

        if provider == "anthropic":
            return await self.handle_messages(request, request_data)
        else:
            return await self.handle_chat_completions(request, request_data)

    def _json_dumps(self, data: Any) -> bytes:
        """Serialize data to JSON bytes."""
        import json

        return json.dumps(data).encode()


def create_proxy_app(config: TheronConfig | None = None) -> FastAPI:
    """Create the FastAPI proxy application."""
    config = config or get_config()
    proxy = ProxyServer(config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        await proxy.start()
        await get_database()  # Initialize database
        yield
        # Shutdown
        await proxy.stop()

    app = FastAPI(
        title="Theron Proxy",
        description="Security proxy for agentic AI systems",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "theron-proxy"}

    @app.post("/v1/messages")
    async def messages_endpoint(request: Request):
        """Anthropic Messages API endpoint."""
        request_data = await request.json()
        return await proxy.handle_messages(request, request_data)

    @app.post("/v1/chat/completions")
    async def chat_completions_endpoint(request: Request):
        """OpenAI Chat Completions API endpoint."""
        request_data = await request.json()
        return await proxy.handle_chat_completions(request, request_data)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def catch_all(request: Request, path: str):
        """Catch-all for other endpoints - auto-detect and forward."""
        if request.method == "POST":
            try:
                request_data = await request.json()
                return await proxy.handle_generic(request, request_data)
            except Exception:
                pass

        # For non-POST or parse errors, return 404
        return Response(
            content='{"error": "Unknown endpoint"}',
            status_code=404,
            media_type="application/json",
        )

    return app
