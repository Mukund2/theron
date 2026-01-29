"""Docker-based sandbox for isolated command execution."""

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .result import FileChange, SandboxResult, SandboxStatus

logger = logging.getLogger(__name__)

# Default sandbox configuration
DEFAULT_CONFIG = {
    "image": "python:3.11-slim",
    "memory_limit": "256m",
    "cpu_quota": 50000,  # 50% of one CPU
    "cpu_period": 100000,
    "timeout_seconds": 30,
    "network_disabled": True,
    "read_only": True,
    "tmpfs_size": "64m",
}


class DockerSandbox:
    """Executes commands in an isolated Docker container."""

    def __init__(
        self,
        image: str = DEFAULT_CONFIG["image"],
        memory_limit: str = DEFAULT_CONFIG["memory_limit"],
        cpu_quota: int = DEFAULT_CONFIG["cpu_quota"],
        cpu_period: int = DEFAULT_CONFIG["cpu_period"],
        timeout_seconds: int = DEFAULT_CONFIG["timeout_seconds"],
        network_disabled: bool = DEFAULT_CONFIG["network_disabled"],
    ):
        """Initialize the sandbox.

        Args:
            image: Docker image to use
            memory_limit: Memory limit (e.g., '256m')
            cpu_quota: CPU quota (microseconds per cpu_period)
            cpu_period: CPU period (microseconds)
            timeout_seconds: Maximum execution time
            network_disabled: Whether to disable networking
        """
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.cpu_period = cpu_period
        self.timeout_seconds = timeout_seconds
        self.network_disabled = network_disabled
        self._docker_available: Optional[bool] = None

    async def is_available(self) -> bool:
        """Check if Docker is available."""
        if self._docker_available is not None:
            return self._docker_available

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            self._docker_available = proc.returncode == 0
        except FileNotFoundError:
            self._docker_available = False
        except Exception as e:
            logger.warning(f"Docker availability check failed: {e}")
            self._docker_available = False

        return self._docker_available

    async def run(
        self,
        command: str,
        sandbox_id: str,
        tool_name: str,
        tool_arguments: dict[str, Any],
        working_dir: Optional[str] = None,
        env_vars: Optional[dict[str, str]] = None,
    ) -> SandboxResult:
        """Run a command in the sandbox.

        Args:
            command: The command to execute
            sandbox_id: Unique ID for this sandbox execution
            tool_name: Name of the tool being sandboxed
            tool_arguments: Arguments passed to the tool
            working_dir: Optional working directory inside container
            env_vars: Optional environment variables

        Returns:
            SandboxResult with execution details
        """
        result = SandboxResult(
            sandbox_id=sandbox_id,
            tool_name=tool_name,
            tool_arguments=tool_arguments,
            command=command,
            status=SandboxStatus.RUNNING,
        )

        if not await self.is_available():
            result.status = SandboxStatus.FAILED
            result.error_message = "Docker is not available"
            return result

        start_time = time.time()

        try:
            # Build docker run command
            docker_cmd = await self._build_docker_command(
                command, working_dir, env_vars
            )

            logger.info(f"Running sandbox {sandbox_id}: {command[:100]}...")

            # Execute the command
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.status = SandboxStatus.FAILED
                result.error_message = f"Execution timed out after {self.timeout_seconds}s"
                result.duration_ms = int((time.time() - start_time) * 1000)
                return result

            result.exit_code = proc.returncode
            result.stdout = stdout.decode("utf-8", errors="replace")[:50000]  # Limit output
            result.stderr = stderr.decode("utf-8", errors="replace")[:50000]
            result.status = SandboxStatus.COMPLETED
            result.completed_at = datetime.utcnow()

        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            result.status = SandboxStatus.FAILED
            result.error_message = str(e)

        result.duration_ms = int((time.time() - start_time) * 1000)
        return result

    async def _build_docker_command(
        self,
        command: str,
        working_dir: Optional[str],
        env_vars: Optional[dict[str, str]],
    ) -> list[str]:
        """Build the docker run command with security options."""
        docker_cmd = [
            "docker", "run",
            "--rm",  # Remove container after execution
            f"--memory={self.memory_limit}",
            f"--cpu-period={self.cpu_period}",
            f"--cpu-quota={self.cpu_quota}",
            "--pids-limit=64",  # Limit number of processes
            "--read-only",
            "--tmpfs", f"/tmp:size={DEFAULT_CONFIG['tmpfs_size']}",
            "--tmpfs", "/var/tmp:size=32m",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",  # Drop all capabilities
        ]

        if self.network_disabled:
            docker_cmd.append("--network=none")

        if working_dir:
            docker_cmd.extend(["-w", working_dir])

        # Add environment variables
        if env_vars:
            for key, value in env_vars.items():
                # Sanitize env var values
                if not self._is_safe_env_value(value):
                    continue
                docker_cmd.extend(["-e", f"{key}={value}"])

        docker_cmd.append(self.image)
        docker_cmd.extend(["sh", "-c", command])

        return docker_cmd

    def _is_safe_env_value(self, value: str) -> bool:
        """Check if an environment variable value is safe."""
        # Reject values with shell metacharacters
        dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">"]
        return not any(c in value for c in dangerous_chars)


class SandboxManager:
    """Manages sandbox executions and their results."""

    def __init__(self):
        """Initialize the sandbox manager."""
        self._sandbox = DockerSandbox()
        self._pending: dict[str, SandboxResult] = {}  # sandbox_id -> result
        self._lock = asyncio.Lock()

    async def is_available(self) -> bool:
        """Check if sandboxing is available."""
        return await self._sandbox.is_available()

    async def execute(
        self,
        sandbox_id: str,
        tool_name: str,
        tool_arguments: dict[str, Any],
        command: str,
        source_tag: Optional[str] = None,
        risk_tier: Optional[int] = None,
        threat_score: int = 0,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> SandboxResult:
        """Execute a command in the sandbox.

        Args:
            sandbox_id: Unique ID for this execution
            tool_name: Name of the tool
            tool_arguments: Tool arguments
            command: Command to execute
            source_tag: Trust level of the source
            risk_tier: Risk tier of the action
            threat_score: Threat score from injection detection
            agent_id: ID of the agent making the request
            request_id: ID of the original request

        Returns:
            SandboxResult with execution details
        """
        result = await self._sandbox.run(
            command=command,
            sandbox_id=sandbox_id,
            tool_name=tool_name,
            tool_arguments=tool_arguments,
        )

        # Add context
        result.source_tag = source_tag
        result.risk_tier = risk_tier
        result.threat_score = threat_score
        result.agent_id = agent_id
        result.request_id = request_id

        # Store in pending if completed successfully
        if result.status == SandboxStatus.COMPLETED:
            async with self._lock:
                self._pending[sandbox_id] = result

        return result

    async def get_pending(self) -> list[SandboxResult]:
        """Get all pending sandbox results awaiting approval."""
        async with self._lock:
            return [
                r for r in self._pending.values()
                if r.status == SandboxStatus.COMPLETED
            ]

    async def get_result(self, sandbox_id: str) -> Optional[SandboxResult]:
        """Get a specific sandbox result."""
        async with self._lock:
            return self._pending.get(sandbox_id)

    async def approve(self, sandbox_id: str) -> Optional[SandboxResult]:
        """Approve a sandbox result for real execution."""
        async with self._lock:
            result = self._pending.get(sandbox_id)
            if result and result.status == SandboxStatus.COMPLETED:
                result.status = SandboxStatus.APPROVED
                result.approved_at = datetime.utcnow()
                return result
        return None

    async def reject(self, sandbox_id: str) -> Optional[SandboxResult]:
        """Reject a sandbox result."""
        async with self._lock:
            result = self._pending.get(sandbox_id)
            if result and result.status == SandboxStatus.COMPLETED:
                result.status = SandboxStatus.REJECTED
                result.rejected_at = datetime.utcnow()
                return result
        return None

    async def cleanup_expired(self, max_age_seconds: int = 3600) -> int:
        """Clean up expired sandbox results.

        Args:
            max_age_seconds: Maximum age in seconds before expiring

        Returns:
            Number of expired results cleaned up
        """
        now = datetime.utcnow()
        expired_ids = []

        async with self._lock:
            for sandbox_id, result in self._pending.items():
                age = (now - result.created_at).total_seconds()
                if age > max_age_seconds and result.status == SandboxStatus.COMPLETED:
                    result.status = SandboxStatus.EXPIRED
                    expired_ids.append(sandbox_id)

            for sandbox_id in expired_ids:
                del self._pending[sandbox_id]

        return len(expired_ids)


# Global sandbox manager instance
_sandbox_manager: Optional[SandboxManager] = None


def get_sandbox_manager() -> SandboxManager:
    """Get the global sandbox manager instance."""
    global _sandbox_manager
    if _sandbox_manager is None:
        _sandbox_manager = SandboxManager()
    return _sandbox_manager
