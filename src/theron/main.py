"""Main entry point for Theron."""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

import uvicorn

from .config import create_default_config, get_config, get_config_path
from .dashboard import create_dashboard_app
from .proxy import create_proxy_app


def setup_logging(level: str = "INFO") -> None:
    """Configure logging for Theron."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def print_banner() -> None:
    """Print the Theron startup banner."""
    banner = """
  _____ _
 |_   _| |__   ___ _ __ ___  _ __
   | | | '_ \\ / _ \\ '__/ _ \\| '_ \\
   | | | | | |  __/ | | (_) | | | |
   |_| |_| |_|\\___|_|  \\___/|_| |_|

  Security Layer for Agentic AI
  ─────────────────────────────────
"""
    print(banner)


def run_proxy(args: argparse.Namespace) -> None:
    """Run the proxy server."""
    config = get_config()

    port = args.port or config.proxy.listen_port
    host = args.host or "127.0.0.1"

    print(f"Starting Theron proxy on http://{host}:{port}")
    print(f"Configuration: {get_config_path()}")
    print()
    print("Usage:")
    print(f"  Set ANTHROPIC_API_URL=http://{host}:{port}")
    print(f"  Set OPENAI_API_BASE=http://{host}:{port}/v1")
    print()

    app = create_proxy_app(config)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=config.logging.level.lower(),
    )


def run_dashboard(args: argparse.Namespace) -> None:
    """Run the dashboard server."""
    config = get_config()

    port = args.port or config.dashboard.port
    host = args.host or "127.0.0.1"

    print(f"Starting Theron dashboard on http://{host}:{port}")

    app = create_dashboard_app(config)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=config.logging.level.lower(),
    )


def run_all(args: argparse.Namespace) -> None:
    """Run both proxy and dashboard servers."""
    import threading

    config = get_config()

    proxy_port = args.proxy_port or config.proxy.listen_port
    dashboard_port = args.dashboard_port or config.dashboard.port
    host = args.host or "127.0.0.1"

    print(f"Starting Theron proxy on http://{host}:{proxy_port}")
    print(f"Starting Theron dashboard on http://{host}:{dashboard_port}")
    print()
    print("Usage:")
    print(f"  Set ANTHROPIC_API_URL=http://{host}:{proxy_port}")
    print(f"  Set OPENAI_API_BASE=http://{host}:{proxy_port}/v1")
    print(f"  Dashboard: http://{host}:{dashboard_port}")
    print()

    def run_proxy_server():
        app = create_proxy_app(config)
        uvicorn.run(app, host=host, port=proxy_port, log_level="warning")

    def run_dashboard_server():
        app = create_dashboard_app(config)
        uvicorn.run(app, host=host, port=dashboard_port, log_level="warning")

    proxy_thread = threading.Thread(target=run_proxy_server, daemon=True)
    dashboard_thread = threading.Thread(target=run_dashboard_server, daemon=True)

    proxy_thread.start()
    dashboard_thread.start()

    def signal_handler(sig, frame):
        print("\nShutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep main thread alive
    proxy_thread.join()
    dashboard_thread.join()


def init_config(args: argparse.Namespace) -> None:
    """Initialize the configuration file."""
    config_path = create_default_config()
    print(f"Configuration file created at: {config_path}")


def run_setup(args: argparse.Namespace) -> None:
    """Set up Theron for automatic protection."""
    from .setup import run_setup as _run_setup, get_status

    if args.status:
        status = get_status()
        print("Theron Status")
        print("=" * 40)
        print(f"Shell: {status['shell']}")
        print(f"Profile: {status['profile_path']}")
        print(f"Environment variables: {'Configured' if status['env_vars_configured'] else 'Not configured'}")
        print(f"Background service: {'Running' if status['service_running'] else 'Not running'}")
        print(f"Platform: {status['platform']}")
        return

    success = _run_setup(uninstall=args.uninstall)
    sys.exit(0 if success else 1)


def install_agent(args: argparse.Namespace) -> None:
    """Install an AI agent with safety guidance."""
    from .agents import AgentInstaller

    installer = AgentInstaller()
    success = installer.install(args.agent, method=args.method)
    sys.exit(0 if success else 1)


def run_agent(args: argparse.Namespace) -> None:
    """Run an AI agent with Theron protection."""
    from .agents import AgentRunner

    runner = AgentRunner()
    exit_code = runner.run(args.agent, args=args.agent_args)
    sys.exit(exit_code)


def list_agents(args: argparse.Namespace) -> None:
    """List known AI agents."""
    from .agents.runner import list_agents as _list_agents
    _list_agents()


def create_agent_definition(args: argparse.Namespace) -> None:
    """Create a new agent definition template."""
    from pathlib import Path
    import yaml
    from .agents.registry import create_agent_template

    template = create_agent_template(args.name)

    if args.user:
        directory = Path.home() / ".theron" / "agents"
    else:
        directory = Path.cwd() / ".theron" / "agents"

    directory.mkdir(parents=True, exist_ok=True)

    filename = args.name.lower().replace(" ", "-") + ".yaml"
    file_path = directory / filename

    if file_path.exists() and not args.force:
        print(f"❌ File already exists: {file_path}")
        print("   Use --force to overwrite")
        sys.exit(1)

    with open(file_path, "w") as f:
        yaml.dump(template, f, default_flow_style=False, sort_keys=False)

    print(f"✓ Created agent template: {file_path}")
    print()
    print("Edit the file to customize:")
    print("  - description: What does this agent do?")
    print("  - risk_level: low, medium, high, or critical")
    print("  - capabilities: What can it do?")
    print("  - warnings: What should users know?")
    print("  - install_commands: How to install it")
    print("  - run_command: How to run it")
    print()
    print(f"Then use: theron install {args.name}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Theron - Security Layer for Agentic AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  theron setup              # One-time setup (adds to shell, starts service)
  theron setup --status     # Check if Theron is configured
  theron setup --uninstall  # Remove Theron setup

  theron                    # Run both proxy and dashboard (manual mode)
  theron proxy              # Run only the proxy server
  theron dashboard          # Run only the dashboard

For more information, visit: https://github.com/Mukund2/theron
        """,
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Proxy command
    proxy_parser = subparsers.add_parser("proxy", help="Run the proxy server")
    proxy_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    proxy_parser.add_argument("--port", type=int, help="Port to listen on")

    # Dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Run the dashboard")
    dashboard_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    dashboard_parser.add_argument("--port", type=int, help="Port to listen on")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize configuration")

    # Setup command
    setup_parser = subparsers.add_parser(
        "setup",
        help="Set up Theron for automatic protection",
    )
    setup_parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove Theron setup",
    )
    setup_parser.add_argument(
        "--status",
        action="store_true",
        help="Show current setup status",
    )

    # Agents command - list known agents
    agents_parser = subparsers.add_parser("agents", help="List known AI agents")

    # Install command - guided agent installation
    install_parser = subparsers.add_parser(
        "install",
        help="Install an AI agent with safety guidance",
    )
    install_parser.add_argument("agent", help="Name of the agent to install")
    install_parser.add_argument(
        "--method",
        help="Installation method (pip, npm, docker, etc.)",
    )

    # Run command - run agent with Theron protection
    run_parser = subparsers.add_parser(
        "run",
        help="Run an AI agent with Theron protection",
    )
    run_parser.add_argument("agent", help="Name of the agent to run")
    run_parser.add_argument(
        "agent_args",
        nargs="*",
        help="Additional arguments to pass to the agent",
    )

    # New-agent command - create a new agent definition
    new_agent_parser = subparsers.add_parser(
        "new-agent",
        help="Create a new agent definition template",
    )
    new_agent_parser.add_argument("name", help="Name of the new agent")
    new_agent_parser.add_argument(
        "--user",
        action="store_true",
        help="Create in user directory (~/.theron/agents/) instead of project",
    )
    new_agent_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing file",
    )

    # Default (run all) uses these args
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--proxy-port", type=int, help="Proxy server port")
    parser.add_argument("--dashboard-port", type=int, help="Dashboard port")

    args = parser.parse_args()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(log_level)

    print_banner()

    if args.command == "proxy":
        run_proxy(args)
    elif args.command == "dashboard":
        run_dashboard(args)
    elif args.command == "init":
        init_config(args)
    elif args.command == "setup":
        run_setup(args)
    elif args.command == "agents":
        list_agents(args)
    elif args.command == "install":
        install_agent(args)
    elif args.command == "run":
        run_agent(args)
    elif args.command == "new-agent":
        create_agent_definition(args)
    else:
        # Default: run both
        run_all(args)


if __name__ == "__main__":
    main()
