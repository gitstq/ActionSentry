"""
Terminal output formatter with color-coded severity indicators.
"""

import sys
from typing import List

from ..models import ScanResult, Finding, Severity
from ..utils import (
    severity_emoji, severity_color, color_text, bold_text, dim_text,
    strip_ansi, supports_color,
)


class TerminalFormatter:
    """Formats scan results for terminal output."""

    def __init__(self, use_color: bool = True):
        self.use_color = use_color and supports_color()

    def format(self, result: ScanResult) -> str:
        """Format the complete scan result for terminal display."""
        lines = []

        # Header
        lines.append(self._header())
        lines.append("")

        # Summary
        lines.append(self._summary(result))
        lines.append("")

        # Findings grouped by file
        if result.findings:
            lines.append(self._findings_by_file(result))
        else:
            lines.append(self._no_findings())

        # Footer
        lines.append("")
        lines.append(self._footer(result))

        output = "\n".join(lines)
        if not self.use_color:
            output = strip_ansi(output)
        return output

    def _c(self, text: str, color_code: str) -> str:
        """Conditionally color text."""
        if self.use_color:
            return color_text(text, color_code)
        return text

    def _b(self, text: str) -> str:
        """Conditionally bold text."""
        if self.use_color:
            return bold_text(text)
        return text

    def _d(self, text: str) -> str:
        """Conditionally dim text."""
        if self.use_color:
            return dim_text(text)
        return text

    def _header(self) -> str:
        """Print the tool header."""
        return (
            f"{self._b('ActionSentry')} - "
            f"{self._d('GitHub Actions Workflow Security Scanner')}"
        )

    def _summary(self, result: ScanResult) -> str:
        """Print the scan summary."""
        by_sev = result.findings_by_severity
        parts = [
            f"Scanned {self._b(str(len(result.scanned_files)))} file(s)",
        ]

        if result.skipped_files:
            parts.append(
                f"Skipped {self._b(str(len(result.skipped_files)))} file(s)"
            )

        parts.append(f"Found {self._b(str(result.total_findings))} issue(s)")

        summary = " | ".join(parts)

        # Severity breakdown
        sev_parts = []
        for sev in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = by_sev.get(sev.value, 0)
            if count > 0:
                emoji = severity_emoji(sev.value)
                sev_parts.append(f"{emoji} {sev.value}: {count}")

        if sev_parts:
            summary += "\n  " + "  ".join(sev_parts)

        return summary

    def _findings_by_file(self, result: ScanResult) -> str:
        """Print findings grouped by file."""
        lines = []
        lines.append(self._b("Findings:"))
        lines.append("-" * 60)

        # Group findings by file
        by_file = {}
        for finding in result.findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        for file_path, findings in by_file.items():
            lines.append("")
            lines.append(self._b(f"  {file_path}"))
            lines.append("")

            for finding in findings:
                lines.append(self._format_finding(finding))

        return "\n".join(lines)

    def _format_finding(self, finding: Finding) -> str:
        """Format a single finding."""
        emoji = severity_emoji(finding.rule.severity.value)
        color = severity_color(finding.rule.severity.value)

        lines = []
        lines.append(
            f"    {emoji} {self._c(finding.rule.severity.value, color)} "
            f"{self._b(finding.rule.rule_id)}: {finding.rule.description}"
        )
        lines.append(
            f"       {self._d(f'File: {finding.file_path}:{finding.line}')}"
        )

        if finding.context:
            lines.append(f"       {self._d(f'Context: {finding.context}')}")

        if finding.code_snippet:
            lines.append(f"       {self._d(f'Code: {finding.code_snippet.strip()}')}")

        if finding.fix_suggestion:
            green = "\033[92m"
            lines.append(
                f"       {self._c('Fix:', green)} {finding.fix_suggestion}"
            )

        return "\n".join(lines)

    def _no_findings(self) -> str:
        """Print message when no findings."""
        green = "\033[92m"
        return f"  {self._c('No security issues found!', green)}"

    def _footer(self, result: ScanResult) -> str:
        """Print the footer."""
        time_str = f"{result.scan_time_ms}ms"
        error_str = ""
        if result.errors:
            error_str = f" | {len(result.errors)} error(s)"

        return self._d(f"Scan completed in {time_str}{error_str}")


def format_terminal(result: ScanResult, use_color: bool = True) -> str:
    """Convenience function to format results for terminal."""
    formatter = TerminalFormatter(use_color=use_color)
    return formatter.format(result)
