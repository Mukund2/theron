"""Anthropic API handling for Theron proxy."""

import json
import uuid
from typing import Any, AsyncIterator, Optional

import httpx

from ..config import TheronConfig
from ..security import (
    ActionClassifier,
    ActionGate,
    GateDecision,
    InjectionDetector,
    SourceTagger,
    ThreatAnalysis,
)
from ..security.gating import GateAction
from ..security.tagger import SourceTag
from ..storage.models import EventCreate


class AnthropicHandler:
    """Handles Anthropic API requests through the proxy."""

    def __init__(
        self,
        config: TheronConfig,
        tagger: SourceTagger,
        detector: InjectionDetector,
        classifier: ActionClassifier,
        gate: ActionGate,
    ):
        self.config = config
        self.tagger = tagger
        self.detector = detector
        self.classifier = classifier
        self.gate = gate
        self.endpoint = config.proxy.endpoints.get(
            "anthropic", "https://api.anthropic.com"
        )

    def detect_api_format(self, request_data: dict[str, Any]) -> bool:
        """Check if this is an Anthropic API request."""
        # Anthropic uses 'messages' array and specific model naming
        if "messages" in request_data:
            model = request_data.get("model", "")
            if "claude" in model.lower():
                return True
            # Check for Anthropic-specific fields
            if "max_tokens" in request_data and "system" in request_data:
                return True
        return False

    async def process_request(
        self,
        request_data: dict[str, Any],
        headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> tuple[dict[str, Any], list[EventCreate]]:
        """Process an Anthropic API request.

        Args:
            request_data: The request body
            headers: Request headers
            client: HTTP client for upstream requests

        Returns:
            Tuple of (response_data, events_to_log)
        """
        request_id = str(uuid.uuid4())
        events: list[EventCreate] = []

        # Extract messages and analyze
        messages = request_data.get("messages", [])
        model = request_data.get("model", "unknown")

        # Tag all messages
        tagged_messages = self.tagger.tag_conversation(messages)

        # Analyze for injection in all content
        max_threat_score = 0
        injection_detected = False
        injection_patterns: list[str] = []

        for tagged in tagged_messages:
            if tagged.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT):
                analysis = self.detector.analyze(tagged.content, tagged.source_tag.value)
                if analysis.threat_score > max_threat_score:
                    max_threat_score = analysis.threat_score
                if analysis.injection_detected:
                    injection_detected = True
                    for match in analysis.pattern_matches:
                        injection_patterns.append(f"{match.category}:{match.matched_text[:30]}")

        # Get the dominant source tag (most untrusted in recent messages)
        dominant_source = self._get_dominant_source(tagged_messages)

        # Optionally inject security context into system prompt
        if injection_detected or max_threat_score > 50:
            request_data = self._inject_security_context(request_data, tagged_messages)

        # Make the upstream request
        response = await self._forward_request(request_data, headers, client)
        response_data = response.json()

        # Classify and gate tool calls in the response
        tool_classifications = self.classifier.classify_response(response_data, "anthropic")
        decisions: list[GateDecision] = []

        for tool_call, classification in tool_classifications:
            decision = self.gate.evaluate(
                tool_call, classification, dominant_source, max_threat_score
            )
            decisions.append(decision)

            # Log the event
            events.append(
                EventCreate(
                    request_id=request_id,
                    agent_id=headers.get("x-theron-agent-id"),
                    source_tag=dominant_source.value,
                    threat_score=max_threat_score,
                    injection_detected=injection_detected,
                    injection_patterns=json.dumps(injection_patterns) if injection_patterns else None,
                    tool_name=tool_call.name,
                    risk_tier=classification.risk_tier.value,
                    action=decision.action.value,
                    block_reason=decision.reason if decision.action == GateAction.BLOCK else None,
                    llm_provider="anthropic",
                    model=model,
                )
            )

        # Filter the response if needed
        if decisions:
            response_data = self.gate.filter_response_anthropic(response_data, decisions)
        else:
            # Log the request even if no tool calls
            events.append(
                EventCreate(
                    request_id=request_id,
                    agent_id=headers.get("x-theron-agent-id"),
                    source_tag=dominant_source.value,
                    threat_score=max_threat_score,
                    injection_detected=injection_detected,
                    injection_patterns=json.dumps(injection_patterns) if injection_patterns else None,
                    action="allowed",
                    llm_provider="anthropic",
                    model=model,
                )
            )

        return response_data, events

    async def process_request_streaming(
        self,
        request_data: dict[str, Any],
        headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> AsyncIterator[bytes]:
        """Process a streaming Anthropic API request.

        For streaming, we can't fully analyze the response before returning it,
        so we do pre-request analysis only and log post-hoc.
        """
        request_id = str(uuid.uuid4())

        # Extract and analyze messages
        messages = request_data.get("messages", [])
        tagged_messages = self.tagger.tag_conversation(messages)

        # Check for high-threat content
        max_threat_score = 0
        for tagged in tagged_messages:
            if tagged.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT):
                analysis = self.detector.analyze(tagged.content, tagged.source_tag.value)
                if analysis.threat_score > max_threat_score:
                    max_threat_score = analysis.threat_score

        # If very high threat, we could block the request entirely
        if max_threat_score >= 90:
            # Yield an error message
            error_event = {
                "type": "content_block_delta",
                "delta": {
                    "type": "text_delta",
                    "text": f"[Theron Security] Request blocked due to high threat score ({max_threat_score}). Potential prompt injection detected.",
                },
            }
            yield f"event: content_block_delta\ndata: {json.dumps(error_event)}\n\n".encode()
            return

        # Forward to upstream and stream response
        async with client.stream(
            "POST",
            f"{self.endpoint}/v1/messages",
            json=request_data,
            headers=self._prepare_headers(headers),
            timeout=self.config.proxy.timeout,
        ) as response:
            async for chunk in response.aiter_bytes():
                yield chunk

    async def _forward_request(
        self,
        request_data: dict[str, Any],
        headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> httpx.Response:
        """Forward a request to the Anthropic API."""
        return await client.post(
            f"{self.endpoint}/v1/messages",
            json=request_data,
            headers=self._prepare_headers(headers),
            timeout=self.config.proxy.timeout,
        )

    def _prepare_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Prepare headers for upstream request."""
        # Pass through authentication headers
        upstream_headers = {}
        for key in ["x-api-key", "anthropic-version", "content-type"]:
            if key in headers:
                upstream_headers[key] = headers[key]
            elif key.replace("-", "_") in headers:
                upstream_headers[key] = headers[key.replace("-", "_")]

        # Check for API key variations
        if "x-api-key" not in upstream_headers:
            for key, value in headers.items():
                if "api" in key.lower() and "key" in key.lower():
                    upstream_headers["x-api-key"] = value
                    break

        return upstream_headers

    def _get_dominant_source(self, tagged_messages: list) -> SourceTag:
        """Get the most untrusted source tag from recent messages."""
        # Priority: CONTENT_READ > TOOL_RESULT > USER_INDIRECT > USER_DIRECT
        priority = {
            SourceTag.CONTENT_READ: 4,
            SourceTag.TOOL_RESULT: 3,
            SourceTag.USER_INDIRECT: 2,
            SourceTag.USER_DIRECT: 1,
            SourceTag.SYSTEM: 0,
        }

        # Look at recent user messages (last 3)
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

    def _inject_security_context(
        self, request_data: dict[str, Any], tagged_messages: list
    ) -> dict[str, Any]:
        """Inject security context into the system prompt."""
        context = self.tagger.get_trust_context(tagged_messages)

        # Add to system prompt
        existing_system = request_data.get("system", "")
        if existing_system:
            request_data["system"] = f"{existing_system}\n\n{context}"
        else:
            request_data["system"] = context

        return request_data
