"""Run agents with Theron protection automatically configured."""

import os
import subprocess
import sys
import threading
import time
from typing import Optional

from .registry import AgentInfo, AgentRegistry, AgentRiskLevel


class AgentRunner:
    """Runs agents with Theron protection enabled."""

    def __init__(self):
        self.registry = AgentRegistry()
        self._theron_process: Optional[subprocess.Popen] = None

    def run(self, agent_name: str, args: list[str] = None) -> int:
        """Run an agent with Theron protection.

        Args:
            agent_name: Name of the agent to run
            args: Additional arguments to pass to the agent

        Returns:
            Exit code from the agent
        """
        args = args or []

        # Look up agent
        agent = self.registry.get(agent_name)
        if not agent:
            print(f"\n❌ Unknown agent: {agent_name}")
            print("\nUse 'theron agents' to list known agents")
            return 1

        # Show what we're doing
        print(f"\n🚀 Starting {agent.name} with Theron protection\n")

        # Check if Theron is already running
        if not self._check_theron_running():
            print("🛡️  Starting Theron proxy...")
            if not self._start_theron():
                print("❌ Failed to start Theron")
                return 1
            print("   Theron proxy running on http://localhost:8081")
            print("   Dashboard at http://localhost:8080")

        # Configure environment
        env = os.environ.copy()
        for var, value in agent.api_env_vars.items():
            env[var] = value
            print(f"   Setting {var}={value}")

        # Show risk warning for critical agents
        if agent.risk_level == AgentRiskLevel.CRITICAL:
            print(f"\n⚠️  WARNING: {agent.name} is a CRITICAL risk agent")
            print("   It can take autonomous actions without your approval")
            print("   Monitor the dashboard: http://localhost:8080")

        # Build command
        if not agent.run_command:
            print(f"\n❌ No run command configured for {agent.name}")
            return 1

        command = agent.run_command.split() + args

        print(f"\n▶️  Running: {' '.join(command)}")
        print("-" * 60)

        # Run the agent
        try:
            result = subprocess.run(
                command,
                env=env,
                cwd=os.getcwd(),
            )
            return result.returncode
        except FileNotFoundError:
            print(f"\n❌ Command not found: {command[0]}")
            print(f"   Is {agent.name} installed?")
            print(f"   Try: theron install {agent_name}")
            return 1
        except KeyboardInterrupt:
            print("\n\n⏹️  Agent stopped by user")
            return 130
        finally:
            self._cleanup()

    def _check_theron_running(self) -> bool:
        """Check if Theron proxy is already running."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("localhost", 8081))
            sock.close()
            return True
        except (ConnectionRefusedError, OSError):
            return False

    def _start_theron(self) -> bool:
        """Start Theron in the background."""
        try:
            # Start Theron as a background process
            self._theron_process = subprocess.Popen(
                [sys.executable, "-m", "theron"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for it to be ready
            for _ in range(30):  # 3 second timeout
                if self._check_theron_running():
                    return True
                time.sleep(0.1)

            return False
        except Exception as e:
            print(f"   Error starting Theron: {e}")
            return False

    def _cleanup(self):
        """Clean up resources."""
        # We don't stop Theron - user might want it running
        pass


def list_agents():
    """Print list of known agents."""
    registry = AgentRegistry()

    print("\n📋 Known AI Agents")
    print("=" * 60)

    for agent in registry.list_all():
        risk_emoji = {
            AgentRiskLevel.LOW: "🟢",
            AgentRiskLevel.MEDIUM: "🟡",
            AgentRiskLevel.HIGH: "🟠",
            AgentRiskLevel.CRITICAL: "🔴",
        }.get(agent.risk_level, "⚪")

        name_lower = agent.name.lower().replace(" ", "-")
        print(f"\n{risk_emoji} {agent.name}")
        print(f"   {agent.description}")
        print(f"   Install: theron install {name_lower}")
        print(f"   Run:     theron run {name_lower}")
        if agent.source != "builtin":
            print(f"   Source:  {agent.source}")

    print("\n" + "-" * 60)
    print("Risk levels: 🟢 Low  🟡 Medium  🟠 High  🔴 Critical")
    print()
    print("Add custom agents:")
    print("  theron new-agent <name>          # Create template")
    print("  Edit ~/.theron/agents/<name>.yaml")
    print()
