"""
SHL-001: Shellcheck Issues - Placeholder rule for shell command analysis.

This rule performs basic shell command analysis to detect common
anti-patterns in GitHub Actions run steps.
"""

import re
from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)


class ShellcheckPlaceholderRule(BaseRule):
    """SHL-001: Basic shell command analysis for common issues."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="SHL-001",
            severity=Severity.LOW,
            description=(
                "Shell Issues: Potential shell command issues detected "
                "(basic analysis)"
            ),
            category=Category.SHELL,
            recommendation=(
                "Run shellcheck on your shell scripts for detailed analysis. "
                "Use 'shell: bash' explicitly and consider adding 'set -euo pipefail'."
            ),
        )

    # Patterns that indicate shell issues
    SHELL_ISSUE_PATTERNS = [
        (re.compile(r"\beval\b"), "Use of 'eval' can lead to code injection"),
        (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"), "Piping curl to shell is risky"),
        (re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"), "Piping wget to shell is risky"),
        (re.compile(r"chmod\s+777"), "Overly permissive file permissions (777)"),
        (re.compile(r"\|(\s*)sudo\b"), "Using sudo in CI/CD pipelines"),
        (re.compile(r"rm\s+-rf\s+/"), "Dangerous: rm -rf / detected"),
        (re.compile(r"rm\s+-rf\s+\*"), "Dangerous: rm -rf * detected"),
        (re.compile(r"\bnc\b\s+-[el]"), "Netcat listener detected (potential backdoor)"),
        (re.compile(r">\s*/dev/tcp/"), "Bash network redirect detected"),
    ]

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.run:
                    continue

                for pattern, description in self.SHELL_ISSUE_PATTERNS:
                    if pattern.search(step.run):
                        line = step.line or self._find_line_containing(
                            workflow, step.run[:60]
                        )
                        snippet = self._get_line_content(workflow, line)
                        findings.append(self._make_finding(
                            workflow=workflow,
                            line=line,
                            code_snippet=snippet,
                            context=f"{description} in run step",
                        ))
                        break  # One finding per step

        return findings
