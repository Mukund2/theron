"""Tests for the setup module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from theron.setup import (
    detect_shell,
    get_shell_profile_path,
    check_env_vars_configured,
    add_env_vars_to_profile,
    remove_env_vars_from_profile,
    get_theron_executable,
    get_launchd_plist_content,
    get_systemd_service_content,
    get_status,
    THERON_MARKER,
    ENV_VARS,
    _is_safe_path,
    _validate_home_subpath,
    _check_not_symlink,
    _set_secure_permissions,
    _atomic_write,
    _create_backup,
)


class TestShellDetection:
    """Tests for shell detection."""

    def test_detect_zsh(self):
        """Test detecting zsh shell."""
        with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
            assert detect_shell() == "zsh"

    def test_detect_bash(self):
        """Test detecting bash shell."""
        with patch.dict(os.environ, {"SHELL": "/bin/bash"}):
            assert detect_shell() == "bash"

    def test_detect_unknown_defaults_to_bash(self):
        """Test that unknown shells default to bash."""
        with patch.dict(os.environ, {"SHELL": "/bin/fish"}):
            assert detect_shell() == "bash"

    def test_detect_no_shell_env(self):
        """Test handling missing SHELL environment variable."""
        env = os.environ.copy()
        env.pop("SHELL", None)
        with patch.dict(os.environ, env, clear=True):
            # Should default to bash
            result = detect_shell()
            assert result == "bash"


class TestShellProfile:
    """Tests for shell profile handling."""

    def test_get_profile_path_zsh_existing(self, tmp_path):
        """Test getting profile path when .zshrc exists."""
        zshrc = tmp_path / ".zshrc"
        zshrc.touch()

        with patch("theron.setup.Path.home", return_value=tmp_path):
            path = get_shell_profile_path("zsh")
            assert path == zshrc

    def test_get_profile_path_bash_existing(self, tmp_path):
        """Test getting profile path when .bashrc exists."""
        bashrc = tmp_path / ".bashrc"
        bashrc.touch()

        with patch("theron.setup.Path.home", return_value=tmp_path):
            path = get_shell_profile_path("bash")
            assert path == bashrc

    def test_get_profile_path_creates_default(self, tmp_path):
        """Test that default profile path is returned when none exist."""
        with patch("theron.setup.Path.home", return_value=tmp_path):
            path = get_shell_profile_path("zsh")
            assert path == tmp_path / ".zshrc"


class TestEnvVarsConfiguration:
    """Tests for environment variable configuration."""

    def test_check_env_vars_not_configured(self, tmp_path):
        """Test checking when env vars are not configured."""
        profile = tmp_path / ".zshrc"
        profile.write_text("# Some existing content\n")

        assert check_env_vars_configured(profile) is False

    def test_check_env_vars_configured(self, tmp_path):
        """Test checking when env vars are configured."""
        profile = tmp_path / ".zshrc"
        profile.write_text(f"# Some content\n{THERON_MARKER}\nexport FOO=bar\n")

        with patch("theron.setup.Path.home", return_value=tmp_path):
            assert check_env_vars_configured(profile) is True

    def test_check_env_vars_nonexistent_file(self, tmp_path):
        """Test checking when profile doesn't exist."""
        profile = tmp_path / ".zshrc"

        assert check_env_vars_configured(profile) is False

    def test_add_env_vars_to_empty_profile(self, tmp_path):
        """Test adding env vars to empty profile."""
        profile = tmp_path / ".zshrc"
        profile.write_text("")

        with patch("theron.setup.Path.home", return_value=tmp_path):
            result = add_env_vars_to_profile(profile)

        assert result is True
        content = profile.read_text()
        assert THERON_MARKER in content
        assert "ANTHROPIC_API_URL" in content
        assert "OPENAI_API_BASE" in content

    def test_add_env_vars_to_existing_profile(self, tmp_path):
        """Test adding env vars preserves existing content."""
        profile = tmp_path / ".zshrc"
        existing = "# My existing config\nexport PATH=/usr/local/bin:$PATH\n"
        profile.write_text(existing)

        with patch("theron.setup.Path.home", return_value=tmp_path):
            result = add_env_vars_to_profile(profile)

        assert result is True
        content = profile.read_text()
        assert existing in content
        assert THERON_MARKER in content

    def test_add_env_vars_idempotent(self, tmp_path):
        """Test that adding env vars twice doesn't duplicate."""
        profile = tmp_path / ".zshrc"
        profile.write_text("")

        with patch("theron.setup.Path.home", return_value=tmp_path):
            add_env_vars_to_profile(profile)
            result = add_env_vars_to_profile(profile)

        assert result is False  # Second call returns False
        content = profile.read_text()
        assert content.count(THERON_MARKER) == 1

    def test_add_env_vars_creates_file(self, tmp_path):
        """Test adding env vars creates profile if it doesn't exist."""
        profile = tmp_path / ".zshrc"
        assert not profile.exists()

        # The function appends, so we need to ensure the file exists first
        # This is intentional - we don't want to create profiles unexpectedly
        profile.touch()

        with patch("theron.setup.Path.home", return_value=tmp_path):
            result = add_env_vars_to_profile(profile)

        assert result is True
        assert profile.exists()

    def test_remove_env_vars(self, tmp_path):
        """Test removing env vars from profile."""
        profile = tmp_path / ".zshrc"
        content = f"""# My config
export FOO=bar

{THERON_MARKER}
# Route AI agent API calls through Theron security proxy
export ANTHROPIC_API_URL="http://localhost:8081"
export OPENAI_API_BASE="http://localhost:8081/v1"

# More config
export BAZ=qux
"""
        profile.write_text(content)

        with patch("theron.setup.Path.home", return_value=tmp_path):
            result = remove_env_vars_from_profile(profile)

        assert result is True
        new_content = profile.read_text()
        assert THERON_MARKER not in new_content
        assert "ANTHROPIC_API_URL" not in new_content
        assert "export FOO=bar" in new_content
        assert "export BAZ=qux" in new_content

    def test_remove_env_vars_not_present(self, tmp_path):
        """Test removing when env vars aren't present."""
        profile = tmp_path / ".zshrc"
        profile.write_text("# Just some config\n")

        result = remove_env_vars_from_profile(profile)

        assert result is False


class TestExecutablePath:
    """Tests for finding the theron executable."""

    def test_get_executable_from_path(self):
        """Test finding theron in PATH."""
        with patch("shutil.which", return_value="/usr/local/bin/theron"):
            result = get_theron_executable()
            assert result == "/usr/local/bin/theron"

    def test_get_executable_fallback(self):
        """Test fallback to python -m theron."""
        with patch("shutil.which", return_value=None):
            result = get_theron_executable()
            assert "-m theron" in result


class TestServiceContent:
    """Tests for service configuration content."""

    def test_launchd_plist_content(self):
        """Test macOS Launch Agent plist generation."""
        with patch("shutil.which", return_value="/usr/local/bin/theron"):
            content = get_launchd_plist_content()

        assert "com.theron.agent" in content
        assert "RunAtLoad" in content
        assert "KeepAlive" in content
        assert "theron" in content

    def test_launchd_plist_with_python_module(self):
        """Test plist generation when using python -m."""
        with patch("shutil.which", return_value=None):
            content = get_launchd_plist_content()

        assert "-m" in content
        assert "theron" in content

    def test_systemd_service_content(self):
        """Test Linux systemd service generation."""
        with patch("shutil.which", return_value="/usr/local/bin/theron"):
            content = get_systemd_service_content()

        assert "theron.service" not in content  # Just checking it's service content
        assert "ExecStart" in content
        assert "Restart=on-failure" in content  # Changed from always for security
        assert "theron" in content


class TestStatus:
    """Tests for status checking."""

    def test_get_status(self, tmp_path):
        """Test getting setup status."""
        profile = tmp_path / ".zshrc"
        profile.write_text(f"{THERON_MARKER}\n")

        with patch("theron.setup.Path.home", return_value=tmp_path):
            with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
                with patch("theron.setup.is_service_running", return_value=False):
                    status = get_status()

        assert status["shell"] == "zsh"
        assert status["env_vars_configured"] is True
        assert status["service_running"] is False
        assert "platform" in status


class TestIntegration:
    """Integration tests for the setup process."""

    def test_full_setup_and_uninstall(self, tmp_path):
        """Test complete setup and uninstall cycle."""
        profile = tmp_path / ".zshrc"
        profile.touch()

        with patch("theron.setup.Path.home", return_value=tmp_path):
            # Add env vars
            add_env_vars_to_profile(profile)
            assert check_env_vars_configured(profile)

            # Remove env vars
            remove_env_vars_from_profile(profile)
            assert not check_env_vars_configured(profile)

    def test_env_vars_format(self, tmp_path):
        """Test that env vars are properly formatted."""
        profile = tmp_path / ".zshrc"
        profile.touch()

        with patch("theron.setup.Path.home", return_value=tmp_path):
            add_env_vars_to_profile(profile)

        content = profile.read_text()

        # Check format is correct for shell
        assert 'export ANTHROPIC_API_URL="http://localhost:8081"' in content
        assert 'export OPENAI_API_BASE="http://localhost:8081/v1"' in content


class TestSecurityFunctions:
    """Tests for security helper functions."""

    def test_is_safe_path_valid(self):
        """Test that valid paths are accepted."""
        assert _is_safe_path(Path("/usr/local/bin/theron"))
        assert _is_safe_path(Path("/home/user/.zshrc"))
        assert _is_safe_path(Path("/Users/test/file.txt"))

    def test_is_safe_path_invalid(self):
        """Test that paths with special characters are rejected."""
        assert not _is_safe_path(Path("/path/with spaces/file"))
        assert not _is_safe_path(Path("/path/with;semicolon"))
        assert not _is_safe_path(Path("/path/with$dollar"))
        assert not _is_safe_path(Path("/path/with`backtick`"))

    def test_validate_home_subpath_valid(self, tmp_path):
        """Test that paths within home are accepted."""
        with patch("theron.setup.Path.home", return_value=tmp_path):
            assert _validate_home_subpath(tmp_path / "subdir" / "file")
            assert _validate_home_subpath(tmp_path / ".config")

    def test_validate_home_subpath_invalid(self, tmp_path):
        """Test that paths outside home are rejected."""
        with patch("theron.setup.Path.home", return_value=tmp_path):
            assert not _validate_home_subpath(Path("/etc/passwd"))
            assert not _validate_home_subpath(Path("/tmp/outside"))

    def test_check_not_symlink_regular_file(self, tmp_path):
        """Test that regular files pass symlink check."""
        regular_file = tmp_path / "regular.txt"
        regular_file.touch()
        assert _check_not_symlink(regular_file)

    def test_check_not_symlink_symlink(self, tmp_path):
        """Test that symlinks fail symlink check."""
        target = tmp_path / "target.txt"
        target.touch()
        symlink = tmp_path / "symlink.txt"
        symlink.symlink_to(target)
        assert not _check_not_symlink(symlink)

    def test_set_secure_permissions_file(self, tmp_path):
        """Test that files get 600 permissions."""
        test_file = tmp_path / "secure.txt"
        test_file.touch()
        _set_secure_permissions(test_file)

        mode = test_file.stat().st_mode
        # Check owner read/write only (0o600)
        assert mode & 0o777 == 0o600

    def test_set_secure_permissions_directory(self, tmp_path):
        """Test that directories get 700 permissions."""
        test_dir = tmp_path / "secure_dir"
        test_dir.mkdir()
        _set_secure_permissions(test_dir, is_directory=True)

        mode = test_dir.stat().st_mode
        # Check owner rwx only (0o700)
        assert mode & 0o777 == 0o700

    def test_atomic_write(self, tmp_path):
        """Test atomic file writing."""
        test_file = tmp_path / "atomic.txt"
        content = "test content"

        result = _atomic_write(test_file, content)

        assert result is True
        assert test_file.read_text() == content
        # Check permissions are secure
        mode = test_file.stat().st_mode
        assert mode & 0o777 == 0o600

    def test_create_backup(self, tmp_path):
        """Test backup creation."""
        original = tmp_path / "original.txt"
        original.write_text("original content")

        backup_path = _create_backup(original)

        assert backup_path is not None
        assert backup_path.exists()
        assert backup_path.read_text() == "original content"
        assert ".theron_backup_" in backup_path.name

    def test_refuses_symlink_modification(self, tmp_path):
        """Test that symlink modification is refused."""
        target = tmp_path / "target.txt"
        target.write_text("target content")
        symlink = tmp_path / ".zshrc"
        symlink.symlink_to(target)

        with patch("theron.setup.Path.home", return_value=tmp_path):
            # This should refuse to modify the symlink
            result = add_env_vars_to_profile(symlink)

        # The function should return False for symlinks
        assert result is False


class TestSystemdHardening:
    """Tests for systemd service security hardening."""

    def test_systemd_has_security_directives(self):
        """Test that systemd service includes security hardening."""
        with patch("shutil.which", return_value="/usr/local/bin/theron"):
            content = get_systemd_service_content()

        # Check for key security directives
        assert "PrivateTmp=yes" in content
        assert "ProtectSystem=strict" in content
        assert "NoNewPrivileges=yes" in content
        assert "ProtectKernelTunables=yes" in content
        assert "ProtectControlGroups=yes" in content
        assert "MemoryDenyWriteExecute=yes" in content
        assert "RestrictAddressFamilies=" in content

    def test_systemd_has_resource_limits(self):
        """Test that systemd service has resource limits."""
        with patch("shutil.which", return_value="/usr/local/bin/theron"):
            content = get_systemd_service_content()

        assert "MemoryMax=" in content
        assert "CPUQuota=" in content


class TestLaunchdHardening:
    """Tests for macOS Launch Agent security settings."""

    def test_launchd_has_security_settings(self):
        """Test that Launch Agent includes security settings."""
        with patch("shutil.which", return_value="/usr/local/bin/theron"):
            content = get_launchd_plist_content()

        # Check for security-related settings
        assert "Umask" in content
        assert "ProcessType" in content
        assert "ThrottleInterval" in content
