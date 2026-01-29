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


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Theron - Security Layer for Agentic AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  theron                    # Run both proxy and dashboard
  theron proxy              # Run only the proxy server
  theron dashboard          # Run only the dashboard
  theron init               # Create default configuration

For more information, visit: https://github.com/your-org/theron
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
    else:
        # Default: run both
        run_all(args)


if __name__ == "__main__":
    main()
