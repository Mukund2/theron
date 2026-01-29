"""Setup module for Theron - configures shell and background service."""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


# Shell profile paths
SHELL_PROFILES = {
    "zsh": [".zshrc", ".zshenv"],
    "bash": [".bashrc", ".bash_profile", ".profile"],
}

# Environment variables to add
ENV_VARS = {
    "ANTHROPIC_API_URL": "http://localhost:8081",
    "OPENAI_API_BASE": "http://localhost:8081/v1",
}

# Marker comment for our additions
THERON_MARKER = "# Added by Theron - Security Layer for AI Agents"


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
        if profile_path.exists():
            return profile_path

    # If none exist, create the first one
    return home / profiles[0]


def check_env_vars_configured(profile_path: Path) -> bool:
    """Check if Theron env vars are already configured."""
    if not profile_path.exists():
        return False

    content = profile_path.read_text()
    return THERON_MARKER in content


def add_env_vars_to_profile(profile_path: Path) -> bool:
    """Add Theron environment variables to shell profile."""
    # Read existing content
    existing_content = ""
    if profile_path.exists():
        existing_content = profile_path.read_text()

    # Check if already configured
    if THERON_MARKER in existing_content:
        return False  # Already configured

    # Build the addition
    lines = [
        "",
        THERON_MARKER,
        "# Route AI agent API calls through Theron security proxy",
    ]
    for var, value in ENV_VARS.items():
        lines.append(f'export {var}="{value}"')
    lines.append("")

    addition = "\n".join(lines)

    # Append to profile
    with open(profile_path, "a") as f:
        f.write(addition)

    return True


def remove_env_vars_from_profile(profile_path: Path) -> bool:
    """Remove Theron environment variables from shell profile."""
    if not profile_path.exists():
        return False

    content = profile_path.read_text()

    if THERON_MARKER not in content:
        return False  # Not configured

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

    # Write back
    with open(profile_path, "w") as f:
        f.write("\n".join(new_lines))

    return True


def get_theron_executable() -> str:
    """Get the path to the theron executable."""
    # Try to find it in PATH
    theron_path = shutil.which("theron")
    if theron_path:
        return theron_path

    # Fall back to python -m theron
    return f"{sys.executable} -m theron"


def get_launchd_plist_path() -> Path:
    """Get the path for the macOS Launch Agent plist."""
    return Path.home() / "Library" / "LaunchAgents" / "com.theron.agent.plist"


def get_launchd_plist_content() -> str:
    """Generate macOS Launch Agent plist content."""
    theron_exec = get_theron_executable()
    log_dir = Path.home() / ".theron" / "logs"

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
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/theron.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/theron.error.log</string>
    <key>WorkingDirectory</key>
    <string>{Path.home()}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:{Path(sys.executable).parent}</string>
    </dict>
</dict>
</plist>
"""


def get_systemd_service_path() -> Path:
    """Get the path for the Linux systemd user service."""
    return Path.home() / ".config" / "systemd" / "user" / "theron.service"


def get_systemd_service_content() -> str:
    """Generate Linux systemd user service content."""
    theron_exec = get_theron_executable()

    # Handle both direct executable and python -m cases
    if " -m " in theron_exec:
        exec_start = theron_exec
    else:
        exec_start = theron_exec

    return f"""[Unit]
Description=Theron Security Proxy for AI Agents
After=network.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=always
RestartSec=5
Environment="PATH=/usr/local/bin:/usr/bin:/bin:{Path(sys.executable).parent}"

[Install]
WantedBy=default.target
"""


def install_macos_service() -> bool:
    """Install Theron as a macOS Launch Agent."""
    plist_path = get_launchd_plist_path()

    # Create directory if needed
    plist_path.parent.mkdir(parents=True, exist_ok=True)

    # Create log directory
    log_dir = Path.home() / ".theron" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Write plist
    plist_path.write_text(get_launchd_plist_content())

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

    # Unload the service
    subprocess.run(
        ["launchctl", "unload", str(plist_path)],
        capture_output=True,
    )

    # Remove the plist
    plist_path.unlink()

    return True


def install_linux_service() -> bool:
    """Install Theron as a Linux systemd user service."""
    service_path = get_systemd_service_path()

    # Create directory if needed
    service_path.parent.mkdir(parents=True, exist_ok=True)

    # Write service file
    service_path.write_text(get_systemd_service_content())

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
    service_path.unlink()

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
        add_env_vars_to_profile(profile_path)
        print(f"Environment variables: Added to {profile_path}")
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
    print("Dashboard: http://localhost:8080")
    print()

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
