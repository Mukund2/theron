"""OpenAI API handling for Theron proxy."""

import json
import uuid
from typing import Any, AsyncIterator, Optional

import httpx

from ..config import TheronConfig
from ..dashboard.api import broadcast_sandbox_pending
from ..sandbox import get_sandbox_manager
from ..security import (
    ActionClassifier,
    ActionGate,
    GateDecision,
    InjectionDetector,
    SourceTagger,
)
from ..security.gating import GateAction
from ..security.tagger import SourceTag
from ..storage import get_database
from ..storage.models import EventCreate, SandboxResultCreate


class OpenAIHandler:
    """Handles OpenAI API requests through the proxy."""

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
        self.endpoint = config.proxy.endpoints.get("openai", "https://api.openai.com")

    def detect_api_format(self, request_data: dict[str, Any]) -> bool:
        """Check if this is an OpenAI API request."""
        if "messages" in request_data:
            model = request_data.get("model", "")
            # OpenAI model names
            if any(m in model.lower() for m in ["gpt", "o1", "o3", "chatgpt"]):
                return True
            # Check for OpenAI-specific fields
            if "functions" in request_data or "tools" in request_data:
                return True
            # Generic OpenAI-compatible (not Anthropic)
            if "max_tokens" in request_data and "system" not in request_data:
                return True
        return False

    async def process_request(
        self,
        request_data: dict[str, Any],
        headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> tuple[dict[str, Any], list[EventCreate]]:
        """Process an OpenAI API request.

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

        # Convert OpenAI messages to common format for tagging
        converted_messages = self._convert_messages_for_tagging(messages)
        tagged_messages = self.tagger.tag_conversation(converted_messages)

        # Analyze for injection
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

        # Get dominant source
        dominant_source = self._get_dominant_source(tagged_messages)

        # Optionally inject security context
        if injection_detected or max_threat_score > 50:
            request_data = self._inject_security_context(
                request_data, tagged_messages, messages
            )

        # Forward request
        response = await self._forward_request(request_data, headers, client)
        response_data = response.json()

        # Classify and gate tool calls
        tool_classifications = self.classifier.classify_response(response_data, "openai")
        decisions: list[GateDecision] = []

        for tool_call, classification in tool_classifications:
            decision = self.gate.evaluate(
                tool_call, classification, dominant_source, max_threat_score
            )
            decisions.append(decision)

            # Handle sandbox execution
            if decision.action == GateAction.SANDBOX and decision.sandbox_id:
                await self._execute_sandbox(
                    decision=decision,
                    request_id=request_id,
                    agent_id=headers.get("x-theron-agent-id"),
                    source_tag=dominant_source.value,
                    threat_score=max_threat_score,
                )

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
                    block_reason=decision.reason if decision.action in (GateAction.BLOCK, GateAction.SANDBOX) else None,
                    llm_provider="openai",
                    model=model,
                )
            )

        # Filter response if needed
        if decisions:
            response_data = self.gate.filter_response_openai(response_data, decisions)
        else:
            events.append(
                EventCreate(
                    request_id=request_id,
                    agent_id=headers.get("x-theron-agent-id"),
                    source_tag=dominant_source.value,
                    threat_score=max_threat_score,
                    injection_detected=injection_detected,
                    injection_patterns=json.dumps(injection_patterns) if injection_patterns else None,
                    action="allowed",
                    llm_provider="openai",
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
        """Process a streaming OpenAI API request."""
        request_id = str(uuid.uuid4())

        # Analyze messages
        messages = request_data.get("messages", [])
        converted = self._convert_messages_for_tagging(messages)
        tagged_messages = self.tagger.tag_conversation(converted)

        max_threat_score = 0
        for tagged in tagged_messages:
            if tagged.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT):
                analysis = self.detector.analyze(tagged.content, tagged.source_tag.value)
                if analysis.threat_score > max_threat_score:
                    max_threat_score = analysis.threat_score

        # Block if very high threat
        if max_threat_score >= 90:
            error_chunk = {
                "choices": [
                    {
                        "delta": {
                            "content": f"[Theron Security] Request blocked due to high threat score ({max_threat_score}). Potential prompt injection detected."
                        },
                        "finish_reason": "stop",
                    }
                ]
            }
            yield f"data: {json.dumps(error_chunk)}\n\n".encode()
            yield b"data: [DONE]\n\n"
            return

        # Forward to upstream
        async with client.stream(
            "POST",
            f"{self.endpoint}/v1/chat/completions",
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
        """Forward a request to the OpenAI API."""
        return await client.post(
            f"{self.endpoint}/v1/chat/completions",
            json=request_data,
            headers=self._prepare_headers(headers),
            timeout=self.config.proxy.timeout,
        )

    def _prepare_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Prepare headers for upstream request."""
        upstream_headers = {"content-type": "application/json"}

        # Pass through authorization
        if "authorization" in headers:
            upstream_headers["authorization"] = headers["authorization"]
        elif "Authorization" in headers:
            upstream_headers["authorization"] = headers["Authorization"]

        # OpenAI-specific headers
        for key in ["openai-organization", "openai-project"]:
            if key in headers:
                upstream_headers[key] = headers[key]

        return upstream_headers

    def _convert_messages_for_tagging(
        self, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert OpenAI messages to common format for tagging."""
        converted = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            # Handle array content (vision models)
            if isinstance(content, list):
                text_parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(part.get("text", ""))
                content = "\n".join(text_parts)

            # Map system role
            if role == "system":
                converted.append({"role": "system", "content": content})
            elif role == "tool":
                # Tool results
                converted.append({"role": "assistant", "content": content})
            else:
                converted.append({"role": role, "content": content})

        return converted

    def _get_dominant_source(self, tagged_messages: list) -> SourceTag:
        """Get the most untrusted source tag from recent messages."""
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

    def _inject_security_context(
        self,
        request_data: dict[str, Any],
        tagged_messages: list,
        original_messages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Inject security context into the system message."""
        context = self.tagger.get_trust_context(tagged_messages)

        messages = list(original_messages)

        # Find or create system message
        system_idx = None
        for i, msg in enumerate(messages):
            if msg.get("role") == "system":
                system_idx = i
                break

        if system_idx is not None:
            messages[system_idx]["content"] = (
                messages[system_idx].get("content", "") + "\n\n" + context
            )
        else:
            messages.insert(0, {"role": "system", "content": context})

        request_data["messages"] = messages
        return request_data

    async def _execute_sandbox(
        self,
        decision: GateDecision,
        request_id: str,
        agent_id: Optional[str],
        source_tag: str,
        threat_score: int,
    ) -> None:
        """Execute a tool call in the sandbox and store the result."""
        sandbox_mgr = get_sandbox_manager()

        # Build the command from the tool call
        command = self._build_command_from_tool(decision.tool_call)

        # Execute in sandbox
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

        # Store in database
        db = await get_database()
        await db.create_sandbox_result(
            SandboxResultCreate(
                sandbox_id=result.sandbox_id,
                tool_name=result.tool_name,
                tool_arguments=result.tool_arguments,
                command=result.command,
                status=result.status.value,
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

        # Broadcast to dashboard
        await broadcast_sandbox_pending(result.to_dict())

    def _build_command_from_tool(self, tool_call) -> str:
        """Build a shell command from a tool call for sandbox execution."""
        tool_name = tool_call.name
        args = tool_call.arguments or {}

        # Shell execution tools
        if tool_name in ("execute_shell", "run_command", "bash", "shell"):
            return args.get("command", args.get("cmd", str(args)))

        # File operations
        if tool_name in ("write_file", "create_file"):
            path = args.get("path", args.get("filename", "/tmp/output"))
            content = args.get("content", "")
            escaped_content = content.replace("'", "'\\''")
            return f"echo '{escaped_content}' > {path}"

        if tool_name in ("delete_file", "remove_file"):
            path = args.get("path", args.get("filename", ""))
            return f"rm -f {path}"

        if tool_name in ("read_file", "cat"):
            path = args.get("path", args.get("filename", ""))
            return f"cat {path}"

        # Network operations
        if tool_name in ("curl", "http_request", "fetch"):
            url = args.get("url", "")
            method = args.get("method", "GET").upper()
            return f"curl -X {method} '{url}'"

        if tool_name in ("send_email", "email"):
            to = args.get("to", args.get("recipient", ""))
            subject = args.get("subject", "")
            body = args.get("body", args.get("content", ""))
            return f"echo 'Would send email to: {to}, Subject: {subject}, Body: {body[:100]}...'"

        # Default: echo the tool call info
        return f"echo 'Tool: {tool_name}, Args: {json.dumps(args)[:200]}'"
