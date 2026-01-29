"""Guided agent installation with safety checks."""

import shutil
import subprocess
import sys
from typing import Optional

from .registry import AgentInfo, AgentRegistry, AgentRiskLevel


class AgentInstaller:
    """Guides users through safe agent installation."""

    def __init__(self):
        self.registry = AgentRegistry()

    def install(self, agent_name: str, method: Optional[str] = None) -> bool:
        """Install an agent with safety guidance.

        Args:
            agent_name: Name of the agent to install
            method: Installation method (pip, npm, docker, etc.)

        Returns:
            True if installation succeeded
        """
        # Look up agent
        agent = self.registry.get(agent_name)
        if not agent:
            print(f"\n❌ Unknown agent: {agent_name}")
            print("\nKnown agents:")
            for a in self.registry.list_all():
                print(f"  • {a.name} - {a.description[:50]}...")
            return False

        # Show agent info
        self._print_header(f"Installing {agent.name}")
        print(f"\n{agent.description}")
        print(f"Homepage: {agent.homepage}")
        print(f"Risk Level: {self._format_risk(agent.risk_level)}")

        # Show capabilities
        print("\n📋 This agent can:")
        for cap in agent.capabilities:
            print(f"   • {cap}")

        # Show warnings
        if agent.warnings:
            print("\n⚠️  WARNINGS:")
            for warning in agent.warnings:
                print(f"   {warning}")

        # Ask for confirmation
        print()
        if not self._confirm("Do you understand the risks and want to continue?"):
            print("\nInstallation cancelled.")
            return False

        # Choose installation method
        if not method:
            method = self._choose_install_method(agent)
            if not method:
                return False

        # Check prerequisites
        if not self._check_prerequisites(method):
            return False

        # Show what will happen
        print(f"\n📦 Installation method: {method}")
        install_cmd = agent.install_commands.get(method)
        print(f"   Command: {install_cmd}")

        # Configure Theron protection
        print("\n🛡️  Theron will be configured to protect you:")
        print("   • All API calls will route through Theron proxy")
        print("   • Dangerous actions will be blocked or sandboxed")
        print("   • Dashboard will show all agent activity")

        if agent.recommended_config:
            print("\n   Recommended security settings will be applied:")
            for key, value in agent.recommended_config.items():
                print(f"   • {key}: {value}")

        # Final confirmation
        print()
        if not self._confirm("Ready to install?"):
            print("\nInstallation cancelled.")
            return False

        # Run installation
        print(f"\n🚀 Installing {agent.name}...")
        success = self._run_install(install_cmd)

        if success:
            self._print_post_install(agent)
            return True
        else:
            print("\n❌ Installation failed. Check the error messages above.")
            return False

    def _print_header(self, text: str):
        """Print a formatted header."""
        width = 60
        print("\n" + "=" * width)
        print(f" {text}")
        print("=" * width)

    def _format_risk(self, risk: AgentRiskLevel) -> str:
        """Format risk level with color/emoji."""
        colors = {
            AgentRiskLevel.LOW: "🟢 LOW",
            AgentRiskLevel.MEDIUM: "🟡 MEDIUM",
            AgentRiskLevel.HIGH: "🟠 HIGH",
            AgentRiskLevel.CRITICAL: "🔴 CRITICAL",
        }
        return colors.get(risk, str(risk))

    def _confirm(self, message: str) -> bool:
        """Ask user for confirmation."""
        while True:
            response = input(f"{message} [y/N]: ").strip().lower()
            if response in ("y", "yes"):
                return True
            if response in ("n", "no", ""):
                return False
            print("Please answer 'y' or 'n'")

    def _choose_install_method(self, agent: AgentInfo) -> Optional[str]:
        """Let user choose installation method."""
        methods = agent.install_methods
        if len(methods) == 1:
            return methods[0]

        print("\n📦 Available installation methods:")
        for i, method in enumerate(methods, 1):
            cmd = agent.install_commands.get(method, "")
            print(f"   {i}. {method}: {cmd[:50]}...")

        while True:
            try:
                choice = input(f"\nChoose method [1-{len(methods)}]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(methods):
                    return methods[idx]
            except ValueError:
                pass
            print(f"Please enter a number between 1 and {len(methods)}")

    def _check_prerequisites(self, method: str) -> bool:
        """Check if required tools are installed."""
        tool_map = {
            "pip": "pip3",
            "npm": "npm",
            "docker": "docker",
            "git": "git",
        }

        tool = tool_map.get(method)
        if not tool:
            return True

        if not shutil.which(tool):
            print(f"\n❌ Required tool not found: {tool}")
            print(f"   Please install {tool} first.")

            # Provide installation hints
            hints = {
                "pip3": "Usually comes with Python. Try: brew install python3",
                "npm": "Install Node.js from https://nodejs.org",
                "docker": "Install Docker from https://docker.com",
                "git": "Install git from https://git-scm.com",
            }
            if tool in hints:
                print(f"   Hint: {hints[tool]}")

            return False

        return True

    def _run_install(self, command: str) -> bool:
        """Run the installation command."""
        try:
            # Run with shell for complex commands
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                text=True,
            )
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            print(f"\n❌ Command failed with exit code {e.returncode}")
            return False
        except Exception as e:
            print(f"\n❌ Error: {e}")
            return False

    def _print_post_install(self, agent: AgentInfo):
        """Print post-installation instructions."""
        self._print_header("Installation Complete! 🎉")

        print("\n📋 Next steps to run safely with Theron:\n")

        print("1. Start Theron (if not already running):")
        print("   theron\n")

        print("2. Set environment variables:")
        for var, value in agent.api_env_vars.items():
            print(f"   export {var}={value}")

        print(f"\n3. Run {agent.name}:")
        if agent.run_command:
            print(f"   {agent.run_command}")

        print("\n4. Monitor activity:")
        print("   Open http://localhost:8080 in your browser")

        print("\n" + "-" * 60)
        print("💡 TIP: Use 'theron run' to do steps 1-3 automatically:")
        print(f"   theron run {agent.name.lower().replace(' ', '-')}")
        print("-" * 60)

        # Extra safety tips for high-risk agents
        if agent.risk_level in (AgentRiskLevel.HIGH, AgentRiskLevel.CRITICAL):
            print("\n🛡️  SAFETY RECOMMENDATIONS:")
            print("   • Review the Theron dashboard regularly")
            print("   • Set up alerts for blocked actions")
            print("   • Consider running in a VM or container")
            if agent.risk_level == AgentRiskLevel.CRITICAL:
                print("   • Do NOT leave running unattended initially")
                print("   • Test thoroughly before trusting with important tasks")
