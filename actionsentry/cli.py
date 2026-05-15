"""
CLI interface for ActionSentry.

Provides the command-line argument parsing and dispatch.
"""

import argparse
import sys
import os

from . import __version__
from .models import Severity
from .scanner import Scanner
from .config import Config
from .formatters.terminal import format_terminal
from .formatters.json_fmt import format_json
from .formatters.sarif import format_sarif
from .formatters.markdown import format_markdown


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="actionsentry",
        description="ActionSentry - GitHub Actions Workflow Security Scanner",
        epilog="Example: actionsentry scan --severity HIGH --json",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan workflow files for security issues",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Output results in JSON format",
    )
    scan_parser.add_argument(
        "--sarif",
        dest="output_sarif",
        action="store_true",
        help="Output results in SARIF format",
    )
    scan_parser.add_argument(
        "--markdown", "-md",
        dest="output_markdown",
        action="store_true",
        help="Output results in Markdown format",
    )
    scan_parser.add_argument(
        "--severity", "-s",
        dest="severity",
        choices=["HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity to report",
    )
    scan_parser.add_argument(
        "--ignore", "-i",
        dest="ignore",
        type=str,
        default="",
        help="Comma-separated list of rule IDs to ignore",
    )
    scan_parser.add_argument(
        "--fix",
        dest="auto_fix",
        action="store_true",
        help="Auto-fix issues where possible",
    )
    scan_parser.add_argument(
        "--config", "-c",
        dest="config",
        type=str,
        default=None,
        help="Path to configuration file",
    )
    scan_parser.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        help="Disable colored output",
    )

    # list-rules command
    list_parser = subparsers.add_parser(
        "list-rules",
        help="List all available security rules",
    )
    list_parser.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Output in JSON format",
    )

    # version command
    subparsers.add_parser(
        "version",
        help="Show version information",
    )

    return parser


def cmd_scan(args) -> int:
    """Execute the scan command."""
    # Load config
    config = Config.load(config_path=args.config, base_path=args.path)

    # Parse severity filter
    severity_filter = None
    if args.severity:
        severity_filter = Severity(args.severity)

    # Parse ignore rules
    ignore_rules = set()
    if args.ignore:
        ignore_rules = {r.strip() for r in args.ignore.split(",") if r.strip()}

    # Create scanner and run
    scanner = Scanner(config=config)
    result = scanner.scan(
        path=args.path,
        severity_filter=severity_filter,
        ignore_rules=ignore_rules,
        auto_fix=args.auto_fix,
    )

    # Format output
    if args.output_sarif:
        output = format_sarif(result)
    elif args.output_json:
        output = format_json(result)
    elif args.output_markdown:
        output = format_markdown(result)
    else:
        output = format_terminal(result, use_color=not args.no_color)

    print(output)

    # Exit code: 0 if no HIGH findings, 1 if any HIGH findings
    high_count = result.findings_by_severity.get("HIGH", 0)
    if high_count > 0:
        return 1
    return 0


def cmd_list_rules(args) -> int:
    """Execute the list-rules command."""
    scanner = Scanner()
    rules = scanner.list_rules()

    if args.output_json:
        import json
        print(json.dumps([r.to_dict() for r in rules], indent=2))
    else:
        print("ActionSentry - Available Security Rules")
        print("=" * 60)
        for rule in rules:
            print(f"  {rule.rule_id} [{rule.severity.value}] - {rule.description}")
            print(f"    Category: {rule.category.value}")
            if rule.recommendation:
                print(f"    Fix: {rule.recommendation}")
            print()

    return 0


def cmd_version(args) -> int:
    """Execute the version command."""
    print(f"ActionSentry v{__version__}")
    return 0


def main(argv: list = None) -> int:
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "list-rules":
        return cmd_list_rules(args)
    elif args.command == "version":
        return cmd_version(args)
    else:
        parser.print_help()
        return 1
