"""
Auto-fix engine for ActionSentry.

Attempts to automatically fix certain security issues that can be
safely remediated without breaking workflow functionality.
"""

import re
from typing import List, Optional, Tuple

from .models import Finding, Severity, Category


class FixResult:
    """Result of an auto-fix operation."""

    def __init__(self, finding: Finding, success: bool, original: str = "",
                 fixed: str = "", description: str = ""):
        self.finding = finding
        self.success = success
        self.original = original
        self.fixed = fixed
        self.description = description


class AutoFixer:
    """Engine for automatically fixing security issues."""

    # Rules that can be auto-fixed
    FIXABLE_RULES = {
        "CHK-001",   # persist-credentials: true -> false
        "PERM-001",  # write-all -> minimal permissions
    }

    def can_fix(self, finding: Finding) -> bool:
        """Check if a finding can be auto-fixed."""
        return finding.rule.rule_id in self.FIXABLE_RULES

    def fix_content(self, content: str, findings: List[Finding]) -> Tuple[str, List[FixResult]]:
        """Apply auto-fixes to file content.

        Returns (fixed_content, fix_results).
        """
        fixable = [f for f in findings if self.can_fix(f)]
        if not fixable:
            return content, []

        results = []
        new_content = content

        for finding in fixable:
            result = self._apply_fix(new_content, finding)
            results.append(result)
            if result.success:
                new_content = result.fixed

        return new_content, results

    def _apply_fix(self, content: str, finding: Finding) -> FixResult:
        """Apply a single fix to the content."""
        rule_id = finding.rule.rule_id
        line_num = finding.line

        if rule_id == "CHK-001":
            return self._fix_persist_credentials(content, line_num, finding)
        elif rule_id == "PERM-001":
            return self._fix_excessive_permissions(content, line_num, finding)

        return FixResult(finding, False, content, content, "No fix available")

    def _fix_persist_credentials(self, content: str, line_num: int,
                                  finding: Finding) -> FixResult:
        """Fix persist-credentials: true -> false."""
        lines = content.split("\n")
        if line_num < 1 or line_num > len(lines):
            return FixResult(finding, False, content, content,
                             "Could not find line to fix")

        line = lines[line_num - 1]
        if "persist-credentials" in line:
            new_line = re.sub(
                r"persist-credentials:\s*true",
                "persist-credentials: false",
                line,
            )
            lines[line_num - 1] = new_line
            fixed_content = "\n".join(lines)
            return FixResult(
                finding, True, content, fixed_content,
                "Changed persist-credentials: true to false",
            )

        return FixResult(finding, False, content, content,
                         "Could not find persist-credentials on the expected line")

    def _fix_excessive_permissions(self, content: str, line_num: int,
                                    finding: Finding) -> FixResult:
        """Fix permissions: write-all -> contents: read."""
        lines = content.split("\n")
        if line_num < 1 or line_num > len(lines):
            return FixResult(finding, False, content, content,
                             "Could not find line to fix")

        line = lines[line_num - 1]
        if "write-all" in line:
            new_line = line.replace("write-all", "contents: read")
            lines[line_num - 1] = new_line
            fixed_content = "\n".join(lines)
            return FixResult(
                finding, True, content, fixed_content,
                "Changed permissions: write-all to contents: read",
            )

        if "read-all" in line:
            new_line = line.replace("read-all", "contents: read")
            lines[line_num - 1] = new_line
            fixed_content = "\n".join(lines)
            return FixResult(
                finding, True, content, fixed_content,
                "Changed permissions: read-all to contents: read",
            )

        return FixResult(finding, False, content, content,
                         "Could not find permissions on the expected line")

    def get_fix_suggestion(self, finding: Finding) -> Optional[str]:
        """Get a human-readable fix suggestion for a finding."""
        if not self.can_fix(finding):
            return finding.fix_suggestion or finding.rule.recommendation

        rule_id = finding.rule.rule_id
        if rule_id == "CHK-001":
            return "Set 'persist-credentials: false' in actions/checkout"
        elif rule_id == "PERM-001":
            return "Replace 'permissions: write-all' with minimal permissions"

        return finding.fix_suggestion
