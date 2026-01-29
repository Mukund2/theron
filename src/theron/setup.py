"""Setup module for Theron - configures shell and background service.

Security measures implemented:
- Restrictive file permissions (600 for configs, 700 for directories)
- Backup creation before modifying shell profiles
- Atomic file writes using temp files
- Path validation to prevent traversal attacks
- Symlink detection to prevent redirection attacks
- Input sanitization for paths
- Systemd service hardening (PrivateTmp, ProtectSystem, etc.)
"""

import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional


# Shell profile paths (only allow these specific files)
SHELL_PROFILES = {
    "zsh": [".zshrc", ".zshenv"],
    "bash": [".bashrc", ".bash_profile", ".profile"],
}

# Environment variables to add (hardcoded, not user-controllable)
ENV_VARS = {
    "ANTHROPIC_API_URL": "http://localhost:8081",
    "OPENAI_API_BASE": "http://localhost:8081/v1",
}

# Marker comment for our additions
THERON_MARKER = "# Added by Theron - Security Layer for AI Agents"

# Allowed characters in paths (security: prevent shell injection)
SAFE_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9/_.\-]+$')


def _is_safe_path(path: Path) -> bool:
    """Check if a path is safe (no special characters that could cause issues)."""
    path_str = str(path)
    # Allow typical path characters only
    return bool(SAFE_PATH_PATTERN.match(path_str))


def _validate_home_subpath(path: Path) -> bool:
    """Validate that a path is within the user's home directory."""
    try:
        home = Path.home().resolve()
        resolved = path.resolve()
        return str(resolved).startswith(str(home))
    except (OSError, ValueError):
        return False


def _check_not_symlink(path: Path) -> bool:
    """Check that a path is not a symlink (prevent symlink attacks)."""
    try:
        return not path.is_symlink()
    except OSError:
        return False


def _set_secure_permissions(path: Path, is_directory: bool = False) -> None:
    """Set secure file permissions (owner read/write only)."""
    try:
        if is_directory:
            # 700 for directories
            os.chmod(path, stat.S_IRWXU)
        else:
            # 600 for files
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Best effort


def _atomic_write(path: Path, content: str) -> bool:
    """Write content atomically using a temp file and rename."""
    try:
        # Create temp file in same directory for atomic rename
        fd, temp_path = tempfile.mkstemp(
            dir=path.parent,
            prefix='.theron_tmp_',
            suffix='.tmp'
        )
        try:
            os.write(fd, content.encode('utf-8'))
            os.fsync(fd)
        finally:
            os.close(fd)

        # Set permissions before rename
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)

        # Atomic rename
        os.rename(temp_path, path)
        return True
    except OSError:
        # Clean up temp file on failure
        try:
            os.unlink(temp_path)
        except (OSError, UnboundLocalError):
            pass
        return False


def _create_backup(path: Path) -> Optional[Path]:
    """Create a backup of a file before modifying it."""
    if not path.exists():
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = path.with_suffix(f".theron_backup_{timestamp}")

    try:
        shutil.copy2(path, backup_path)
        _set_secure_permissions(backup_path)
        return backup_path
    except OSError:
        return None


def detect_shell() -> str:
    """Detect the user's default shell."""
    shell = os.environ.get("SHELL", "/bin/bash")
    shell_name = Path(shell).name

    if shell_name in ("zsh", "bash"):
        return shell_name

    # Default to bash if unknown
    return "bash"


def get_shell_profile_path(shell: str) -> Optional[Path]:
    """Get the path to the shell profile file."""
    home = Path.home()

    profiles = SHELL_PROFILES.get(shell, SHELL_PROFILES["bash"])

    # Check which profile exists
    for profile in profiles:
        profile_path = home / profile

        # Security: validate path is safe
        if not _validate_home_subpath(profile_path):
            continue

        if profile_path.exists():
            return profile_path

    # If none exist, return the first one (will be created)
    return home / profiles[0]


def check_env_vars_configured(profile_path: Path) -> bool:
    """Check if Theron env vars are already configured."""
    if not profile_path.exists():
        return False

    # Security: check path is in home directory
    if not _validate_home_subpath(profile_path):
        return False

    try:
        content = profile_path.read_text()
        return THERON_MARKER in content
    except OSError:
        return False


def add_env_vars_to_profile(profile_path: Path) -> bool:
    """Add Theron environment variables to shell profile.

    Security measures:
    - Creates backup before modification
    - Validates path is within home directory
    - Uses atomic write operations
    - Sets restrictive file permissions
    """
    # Security: validate path
    if not _validate_home_subpath(profile_path):
        print(f"  Security: Refusing to modify path outside home directory")
        return False

    # Security: check for symlink attacks
    if profile_path.exists() and not _check_not_symlink(profile_path):
        print(f"  Security: Refusing to modify symlink")
        return False

    # Read existing content
    existing_content = ""
    if profile_path.exists():
        try:
            existing_content = profile_path.read_text()
        except OSError as e:
            print(f"  Error reading profile: {e}")
            return False

    # Check if already configured
    if THERON_MARKER in existing_content:
        return False  # Already configured

    # Create backup before modification
    if profile_path.exists():
        backup = _create_backup(profile_path)
        if backup:
            print(f"  Backup created: {backup}")

    # Build the addition (hardcoded values, not user input)
    lines = [
        "",
        THERON_MARKER,
        "# Route AI agent API calls through Theron security proxy",
    ]
    for var, value in ENV_VARS.items():
        lines.append(f'export {var}="{value}"')
    lines.append("")

    new_content = existing_content + "\n".join(lines)

    # Atomic write with secure permissions
    if _atomic_write(profile_path, new_content):
        return True
    else:
        # Fallback to regular write
        try:
            with open(profile_path, "w") as f:
                f.write(new_content)
            _set_secure_permissions(profile_path)
            return True
        except OSError as e:
            print(f"  Error writing profile: {e}")
            return False


def remove_env_vars_from_profile(profile_path: Path) -> bool:
    """Remove Theron environment variables from shell profile."""
    if not profile_path.exists():
        return False

    # Security: validate path
    if not _validate_home_subpath(profile_path):
        return False

    # Security: check for symlink attacks
    if not _check_not_symlink(profile_path):
        return False

    try:
        content = profile_path.read_text()
    except OSError:
        return False

    if THERON_MARKER not in content:
        return False  # Not configured

    # Create backup before modification
    _create_backup(profile_path)

    # Remove the Theron block
    lines = content.split("\n")
    new_lines = []
    skip_until_blank = False

    for line in lines:
        if THERON_MARKER in line:
            skip_until_blank = True
            continue
        if skip_until_blank:
            if line.startswith("export ANTHROPIC_API_URL") or \
               line.startswith("export OPENAI_API_BASE") or \
               line.startswith("# Route AI agent"):
                continue
            if line.strip() == "":
                skip_until_blank = False
                continue
        new_lines.append(line)

    # Atomic write
    new_content = "\n".join(new_lines)
    if not _atomic_write(profile_path, new_content):
        # Fallback
        try:
            with open(profile_path, "w") as f:
                f.write(new_content)
        except OSError:
            return False

    return True


def get_theron_executable() -> str:
    """Get the path to the theron executable.

    Security: validates the executable path.
    """
    # Try to find it in PATH
    theron_path = shutil.which("theron")
    if theron_path:
        # Validate the path looks reasonable
        if _is_safe_path(Path(theron_path)):
            return theron_path

    # Fall back to python -m theron (safer)
    python_path = sys.executable
    if _is_safe_path(Path(python_path)):
        return f"{python_path} -m theron"

    # Last resort
    return "/usr/bin/python3 -m theron"


def get_launchd_plist_path() -> Path:
    """Get the path for the macOS Launch Agent plist."""
    return Path.home() / "Library" / "LaunchAgents" / "com.theron.agent.plist"


def get_launchd_plist_content() -> str:
    """Generate macOS Launch Agent plist content with security settings."""
    theron_exec = get_theron_executable()
    log_dir = Path.home() / ".theron" / "logs"
    python_bin_dir = Path(sys.executable).parent

    # Handle both direct executable and python -m cases
    if " -m " in theron_exec:
        parts = theron_exec.split()
        program_args = f"""    <array>
        <string>{parts[0]}</string>
        <string>-m</string>
        <string>theron</string>
    </array>"""
    else:
        program_args = f"""    <array>
        <string>{theron_exec}</string>
    </array>"""

    # Note: macOS Launch Agents have limited sandboxing options
    # compared to systemd, but we set what we can
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.theron.agent</string>
    <key>ProgramArguments</key>
{program_args}
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/theron.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/theron.error.log</string>
    <key>WorkingDirectory</key>
    <string>{Path.home()}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:{python_bin_dir}</string>
    </dict>
    <key>Umask</key>
    <integer>63</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
"""


def get_systemd_service_path() -> Path:
    """Get the path for the Linux systemd user service."""
    return Path.home() / ".config" / "systemd" / "user" / "theron.service"


def get_systemd_service_content() -> str:
    """Generate Linux systemd user service content with security hardening.

    Security features enabled:
    - PrivateTmp: Isolate /tmp
    - ProtectSystem: Make system directories read-only
    - ProtectHome: Restrict home directory access (read-only)
    - NoNewPrivileges: Prevent privilege escalation
    - ProtectKernelTunables: Prevent kernel parameter modification
    - ProtectControlGroups: Prevent cgroup modification
    - RestrictRealtime: Prevent realtime scheduling
    - RestrictSUIDSGID: Prevent SUID/SGID
    """
    theron_exec = get_theron_executable()
    python_bin_dir = Path(sys.executable).parent
    theron_data_dir = Path.home() / ".theron"

    return f"""[Unit]
Description=Theron Security Proxy for AI Agents
After=network.target
Documentation=https://github.com/Mukund2/theron

[Service]
Type=simple
ExecStart={theron_exec}
Restart=on-failure
RestartSec=5
TimeoutStopSec=10

# Environment
Environment="PATH=/usr/local/bin:/usr/bin:/bin:{python_bin_dir}"

# Security Hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={theron_data_dir}
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
ProtectHostname=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native

# Resource limits
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=default.target
"""


def install_macos_service() -> bool:
    """Install Theron as a macOS Launch Agent."""
    plist_path = get_launchd_plist_path()

    # Security: validate paths
    if not _validate_home_subpath(plist_path):
        return False

    # Create directory with secure permissions
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    _set_secure_permissions(plist_path.parent, is_directory=True)

    # Create log directory with secure permissions
    log_dir = Path.home() / ".theron" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    _set_secure_permissions(log_dir, is_directory=True)

    # Write plist with secure permissions
    content = get_launchd_plist_content()
    if not _atomic_write(plist_path, content):
        try:
            plist_path.write_text(content)
            _set_secure_permissions(plist_path)
        except OSError:
            return False

    # Unload if already loaded (ignore errors)
    subprocess.run(
        ["launchctl", "unload", str(plist_path)],
        capture_output=True,
    )

    # Load the service
    result = subprocess.run(
        ["launchctl", "load", str(plist_path)],
        capture_output=True,
        text=True,
    )

    return result.returncode == 0


def uninstall_macos_service() -> bool:
    """Uninstall Theron macOS Launch Agent."""
    plist_path = get_launchd_plist_path()

    if not plist_path.exists():
        return False

    # Security: validate path
    if not _validate_home_subpath(plist_path):
        return False

    # Unload the service
    subprocess.run(
        ["launchctl", "unload", str(plist_path)],
        capture_output=True,
    )

    # Remove the plist
    try:
        plist_path.unlink()
    except OSError:
        return False

    return True


def install_linux_service() -> bool:
    """Install Theron as a Linux systemd user service."""
    service_path = get_systemd_service_path()

    # Security: validate path
    if not _validate_home_subpath(service_path):
        return False

    # Create directory with secure permissions
    service_path.parent.mkdir(parents=True, exist_ok=True)
    _set_secure_permissions(service_path.parent, is_directory=True)

    # Create data directory
    data_dir = Path.home() / ".theron"
    data_dir.mkdir(parents=True, exist_ok=True)
    _set_secure_permissions(data_dir, is_directory=True)

    # Write service file with secure permissions
    content = get_systemd_service_content()
    if not _atomic_write(service_path, content):
        try:
            service_path.write_text(content)
            _set_secure_permissions(service_path)
        except OSError:
            return False

    # Reload systemd
    subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True,
    )

    # Enable and start the service
    subprocess.run(
        ["systemctl", "--user", "enable", "theron.service"],
        capture_output=True,
    )

    result = subprocess.run(
        ["systemctl", "--user", "start", "theron.service"],
        capture_output=True,
        text=True,
    )

    return result.returncode == 0


def uninstall_linux_service() -> bool:
    """Uninstall Theron Linux systemd user service."""
    service_path = get_systemd_service_path()

    if not service_path.exists():
        return False

    # Security: validate path
    if not _validate_home_subpath(service_path):
        return False

    # Stop and disable
    subprocess.run(
        ["systemctl", "--user", "stop", "theron.service"],
        capture_output=True,
    )
    subprocess.run(
        ["systemctl", "--user", "disable", "theron.service"],
        capture_output=True,
    )

    # Remove service file
    try:
        service_path.unlink()
    except OSError:
        return False

    # Reload
    subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True,
    )

    return True


def install_background_service() -> tuple[bool, str]:
    """Install Theron as a background service for the current platform."""
    system = platform.system()

    if system == "Darwin":
        success = install_macos_service()
        service_type = "macOS Launch Agent"
    elif system == "Linux":
        success = install_linux_service()
        service_type = "systemd user service"
    else:
        return False, f"Unsupported platform: {system}"

    if success:
        return True, service_type
    else:
        return False, f"Failed to install {service_type}"


def uninstall_background_service() -> bool:
    """Uninstall Theron background service."""
    system = platform.system()

    if system == "Darwin":
        return uninstall_macos_service()
    elif system == "Linux":
        return uninstall_linux_service()
    else:
        return False


def is_service_running() -> bool:
    """Check if Theron background service is running."""
    system = platform.system()

    if system == "Darwin":
        result = subprocess.run(
            ["launchctl", "list", "com.theron.agent"],
            capture_output=True,
        )
        return result.returncode == 0
    elif system == "Linux":
        result = subprocess.run(
            ["systemctl", "--user", "is-active", "theron.service"],
            capture_output=True,
        )
        return result.returncode == 0
    else:
        return False


def run_setup(uninstall: bool = False) -> bool:
    """Run the full setup process."""
    if uninstall:
        return run_uninstall()

    print("Theron Setup")
    print("=" * 40)
    print()

    # Step 1: Detect shell
    shell = detect_shell()
    profile_path = get_shell_profile_path(shell)
    print(f"Detected shell: {shell}")
    print(f"Profile: {profile_path}")
    print()

    # Step 2: Add environment variables
    if check_env_vars_configured(profile_path):
        print("Environment variables: Already configured")
    else:
        if add_env_vars_to_profile(profile_path):
            print(f"Environment variables: Added to {profile_path}")
        else:
            print("Environment variables: Failed to add (check permissions)")
    print()

    # Step 3: Install background service
    print("Installing background service...")
    success, message = install_background_service()

    if success:
        print(f"Background service: Installed ({message})")
    else:
        print(f"Background service: {message}")
        print("  You can still run Theron manually with: theron")
    print()

    # Step 4: Instructions
    print("=" * 40)
    print("Setup complete!")
    print()
    print("To activate, either:")
    print("  1. Restart your terminal, OR")
    print(f"  2. Run: source {profile_path}")
    print()
    print("Theron will start automatically when you log in.")
    print("Your AI agents are now protected.")
    print()
    print("-" * 40)
    print("SECURITY DASHBOARD")
    print()
    print("  View events and blocked actions at:")
    print("  --> http://localhost:8080 <--")
    print()
    print("-" * 40)

    return True


def run_uninstall() -> bool:
    """Uninstall Theron setup."""
    print("Theron Uninstall")
    print("=" * 40)
    print()

    # Remove shell profile entries
    shell = detect_shell()
    profile_path = get_shell_profile_path(shell)

    if remove_env_vars_from_profile(profile_path):
        print(f"Removed environment variables from {profile_path}")
    else:
        print("Environment variables: Not found in profile")

    # Remove background service
    if uninstall_background_service():
        print("Removed background service")
    else:
        print("Background service: Not installed")

    print()
    print("Theron has been uninstalled.")
    print("Restart your terminal to complete the process.")
    print()

    return True


def get_status() -> dict:
    """Get the current setup status."""
    shell = detect_shell()
    profile_path = get_shell_profile_path(shell)

    return {
        "shell": shell,
        "profile_path": str(profile_path),
        "env_vars_configured": check_env_vars_configured(profile_path),
        "service_running": is_service_running(),
        "platform": platform.system(),
    }
