"""Tests for the sandbox module."""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from theron.sandbox import (
    DockerSandbox,
    SandboxManager,
    SandboxResult,
    SandboxStatus,
    FileChange,
    get_sandbox_manager,
)


class TestSandboxResult:
    """Tests for SandboxResult model."""

    def test_create_result(self):
        """Test creating a sandbox result."""
        result = SandboxResult(
            sandbox_id="test-123",
            tool_name="execute_shell",
            tool_arguments={"command": "ls -la"},
            command="ls -la",
        )

        assert result.sandbox_id == "test-123"
        assert result.tool_name == "execute_shell"
        assert result.status == SandboxStatus.PENDING
        assert result.exit_code is None

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = SandboxResult(
            sandbox_id="test-123",
            tool_name="bash",
            tool_arguments={"cmd": "echo hello"},
            command="echo hello",
            status=SandboxStatus.COMPLETED,
            exit_code=0,
            stdout="hello\n",
            duration_ms=150,
        )

        data = result.to_dict()

        assert data["sandbox_id"] == "test-123"
        assert data["status"] == "completed"
        assert data["exit_code"] == 0
        assert data["stdout"] == "hello\n"
        assert "created_at" in data

    def test_result_from_dict(self):
        """Test creating result from dictionary."""
        data = {
            "sandbox_id": "test-456",
            "tool_name": "write_file",
            "tool_arguments": {"path": "/tmp/test.txt", "content": "hello"},
            "command": "echo 'hello' > /tmp/test.txt",
            "status": "completed",
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "file_changes": [
                {"path": "/tmp/test.txt", "action": "created", "size_bytes": 6}
            ],
            "duration_ms": 100,
            "created_at": "2024-01-15T10:30:00",
        }

        result = SandboxResult.from_dict(data)

        assert result.sandbox_id == "test-456"
        assert result.status == SandboxStatus.COMPLETED
        assert len(result.file_changes) == 1
        assert result.file_changes[0].path == "/tmp/test.txt"


class TestSandboxStatus:
    """Tests for SandboxStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        assert SandboxStatus.PENDING.value == "pending"
        assert SandboxStatus.RUNNING.value == "running"
        assert SandboxStatus.COMPLETED.value == "completed"
        assert SandboxStatus.APPROVED.value == "approved"
        assert SandboxStatus.REJECTED.value == "rejected"
        assert SandboxStatus.EXPIRED.value == "expired"
        assert SandboxStatus.FAILED.value == "failed"


class TestDockerSandbox:
    """Tests for DockerSandbox class."""

    @pytest.mark.asyncio
    async def test_docker_unavailable(self):
        """Test sandbox handles missing Docker gracefully."""
        sandbox = DockerSandbox()

        # Mock subprocess to simulate Docker not found
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = FileNotFoundError()

            available = await sandbox.is_available()
            assert available is False

    @pytest.mark.asyncio
    async def test_docker_available(self):
        """Test sandbox detects Docker availability."""
        sandbox = DockerSandbox()

        # Mock subprocess for successful Docker check
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            available = await sandbox.is_available()
            assert available is True

    @pytest.mark.asyncio
    async def test_run_without_docker(self):
        """Test run returns error when Docker unavailable."""
        sandbox = DockerSandbox()
        sandbox._docker_available = False

        result = await sandbox.run(
            command="echo hello",
            sandbox_id="test-123",
            tool_name="bash",
            tool_arguments={},
        )

        assert result.status == SandboxStatus.FAILED
        assert "Docker is not available" in result.error_message

    @pytest.mark.asyncio
    async def test_run_success(self):
        """Test successful sandbox execution."""
        sandbox = DockerSandbox()
        sandbox._docker_available = True

        # Mock the Docker execution
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"hello\n", b""))
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await sandbox.run(
                command="echo hello",
                sandbox_id="test-123",
                tool_name="bash",
                tool_arguments={"cmd": "echo hello"},
            )

        assert result.status == SandboxStatus.COMPLETED
        assert result.exit_code == 0
        assert result.stdout == "hello\n"

    @pytest.mark.asyncio
    async def test_run_timeout(self):
        """Test sandbox handles timeout."""
        sandbox = DockerSandbox(timeout_seconds=1)
        sandbox._docker_available = True

        # Mock a long-running process
        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        async def slow_communicate():
            await asyncio.sleep(10)
            return (b"", b"")

        mock_proc.communicate = slow_communicate

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await sandbox.run(
                command="sleep 100",
                sandbox_id="test-123",
                tool_name="bash",
                tool_arguments={},
            )

        assert result.status == SandboxStatus.FAILED
        assert "timed out" in result.error_message.lower()


class TestSandboxManager:
    """Tests for SandboxManager class."""

    @pytest.mark.asyncio
    async def test_execute_stores_result(self):
        """Test execute stores result in pending."""
        manager = SandboxManager()

        # Mock the sandbox run
        with patch.object(manager._sandbox, "run") as mock_run:
            mock_result = SandboxResult(
                sandbox_id="test-123",
                tool_name="bash",
                tool_arguments={},
                command="echo hello",
                status=SandboxStatus.COMPLETED,
                exit_code=0,
            )
            mock_run.return_value = mock_result

            with patch.object(manager._sandbox, "is_available", return_value=True):
                result = await manager.execute(
                    sandbox_id="test-123",
                    tool_name="bash",
                    tool_arguments={},
                    command="echo hello",
                )

        assert result.status == SandboxStatus.COMPLETED
        pending = await manager.get_pending()
        assert len(pending) == 1
        assert pending[0].sandbox_id == "test-123"

    @pytest.mark.asyncio
    async def test_approve(self):
        """Test approving a sandbox result."""
        manager = SandboxManager()

        # Add a pending result
        result = SandboxResult(
            sandbox_id="test-123",
            tool_name="bash",
            tool_arguments={},
            command="echo hello",
            status=SandboxStatus.COMPLETED,
        )
        manager._pending["test-123"] = result

        approved = await manager.approve("test-123")

        assert approved is not None
        assert approved.status == SandboxStatus.APPROVED
        assert approved.approved_at is not None

    @pytest.mark.asyncio
    async def test_reject(self):
        """Test rejecting a sandbox result."""
        manager = SandboxManager()

        # Add a pending result
        result = SandboxResult(
            sandbox_id="test-123",
            tool_name="bash",
            tool_arguments={},
            command="echo hello",
            status=SandboxStatus.COMPLETED,
        )
        manager._pending["test-123"] = result

        rejected = await manager.reject("test-123")

        assert rejected is not None
        assert rejected.status == SandboxStatus.REJECTED
        assert rejected.rejected_at is not None

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        """Test cleaning up expired results."""
        manager = SandboxManager()

        # Add an old result
        old_result = SandboxResult(
            sandbox_id="old-123",
            tool_name="bash",
            tool_arguments={},
            command="echo old",
            status=SandboxStatus.COMPLETED,
        )
        # Make it old
        old_result.created_at = datetime(2020, 1, 1)
        manager._pending["old-123"] = old_result

        # Add a recent result
        new_result = SandboxResult(
            sandbox_id="new-456",
            tool_name="bash",
            tool_arguments={},
            command="echo new",
            status=SandboxStatus.COMPLETED,
        )
        manager._pending["new-456"] = new_result

        cleaned = await manager.cleanup_expired(max_age_seconds=3600)

        assert cleaned == 1
        assert "old-123" not in manager._pending
        assert "new-456" in manager._pending

    @pytest.mark.asyncio
    async def test_get_result(self):
        """Test getting a specific result."""
        manager = SandboxManager()

        result = SandboxResult(
            sandbox_id="test-123",
            tool_name="bash",
            tool_arguments={},
            command="echo hello",
        )
        manager._pending["test-123"] = result

        found = await manager.get_result("test-123")
        assert found is not None
        assert found.sandbox_id == "test-123"

        not_found = await manager.get_result("nonexistent")
        assert not_found is None


class TestGlobalSandboxManager:
    """Tests for global sandbox manager."""

    def test_get_sandbox_manager(self):
        """Test getting the global sandbox manager."""
        manager1 = get_sandbox_manager()
        manager2 = get_sandbox_manager()

        assert manager1 is manager2
        assert isinstance(manager1, SandboxManager)
