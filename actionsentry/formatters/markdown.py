"""
Markdown output formatter for summary reports.
"""

from typing import List

from ..models import ScanResult, Finding, Severity


class MarkdownFormatter:
    """Formats scan results as Markdown."""

    def format(self, result: ScanResult) -> str:
        """Format the complete scan result as Markdown."""
        lines = []

        # Header
        lines.append("# ActionSentry Scan Report")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Files scanned:** {len(result.scanned_files)}")
        lines.append(f"- **Total findings:** {result.total_findings}")
        if result.skipped_files:
            lines.append(f"- **Files skipped:** {len(result.skipped_files)}")
        if result.errors:
            lines.append(f"- **Errors:** {len(result.errors)}")
        lines.append(f"- **Scan time:** {result.scan_time_ms}ms")
        lines.append("")

        # Severity breakdown
        by_sev = result.findings_by_severity
        lines.append("### Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = by_sev.get(sev.value, 0)
            lines.append(f"| {sev.value} | {count} |")
        lines.append("")

        # Findings
        if result.findings:
            lines.append("## Findings")
            lines.append("")

            # Group by severity
            for sev in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                sev_findings = [
                    f for f in result.findings
                    if f.rule.severity == sev
                ]
                if not sev_findings:
                    continue

                lines.append(f"### {sev.value}")
                lines.append("")

                for finding in sev_findings:
                    lines.append(self._format_finding(finding))
                    lines.append("")

        else:
            lines.append("## Findings")
            lines.append("")
            lines.append("No security issues found.")
            lines.append("")

        # Errors
        if result.errors:
            lines.append("## Errors")
            lines.append("")
            for error in result.errors:
                lines.append(f"- {error}")
            lines.append("")

        return "\n".join(lines)

    def _format_finding(self, finding: Finding) -> str:
        """Format a single finding as Markdown."""
        lines = []
        lines.append(f"#### {finding.rule.rule_id}: {finding.rule.description}")
        lines.append("")
        lines.append(f"- **File:** `{finding.file_path}:{finding.line}`")
        lines.append(f"- **Severity:** {finding.rule.severity.value}")
        lines.append(f"- **Category:** {finding.rule.category.value}")

        if finding.context:
            lines.append(f"- **Context:** {finding.context}")

        if finding.code_snippet:
            lines.append(f"- **Code:**")
            lines.append(f"  ```")
            lines.append(f"  {finding.code_snippet.strip()}")
            lines.append(f"  ```")

        if finding.fix_suggestion:
            lines.append(f"- **Fix:** {finding.fix_suggestion}")

        return "\n".join(lines)


def format_markdown(result: ScanResult) -> str:
    """Convenience function to format results as Markdown."""
    formatter = MarkdownFormatter()
    return formatter.format(result)
