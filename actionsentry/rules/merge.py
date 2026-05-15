"""
AUT-001: Automatic Merge Detection.

Detects auto-merge related actions and configurations that
could bypass required reviews.
"""

import re
from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)

# Actions and patterns related to auto-merging
AUTO_MERGE_ACTIONS = [
    "pascalgn/automerge-action",
    "fastify/github-action-merge-dependabot",
    "reactivecircus/auto-merge",
    "diessl/auto-merge-dependabot",
    "github/auto-merge",
]

AUTO_MERGE_PATTERNS = [
    re.compile(r"auto.?merge", re.IGNORECASE),
    re.compile(r"merge.*dependabot", re.IGNORECASE),
    re.compile(r"enable.?auto.?merge", re.IGNORECASE),
]


class AutoMergeDetectionRule(BaseRule):
    """AUT-001: Detects auto-merge related actions."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="AUT-001",
            severity=Severity.MEDIUM,
            description=(
                "Automatic Merge Detection: Auto-merge action detected which "
                "may bypass required code reviews"
            ),
            category=Category.MERGE,
            recommendation=(
                "Ensure auto-merge actions only merge PRs that have passed all "
                "required checks and approvals. Consider using GitHub's built-in "
                "auto-merge feature with branch protection rules instead."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.uses:
                    continue

                action_name = step.uses.split("@")[0] if "@" in step.uses else step.uses

                # Check against known auto-merge actions
                for auto_action in AUTO_MERGE_ACTIONS:
                    if auto_action in action_name:
                        line = step.line or self._find_line_containing(
                            workflow, step.uses
                        )
                        snippet = self._get_line_content(workflow, line)
                        findings.append(self._make_finding(
                            workflow=workflow,
                            line=line,
                            code_snippet=snippet,
                            context=f"Auto-merge action detected: {step.uses}",
                        ))
                        break
                else:
                    # Check against patterns
                    for pattern in AUTO_MERGE_PATTERNS:
                        if pattern.search(action_name):
                            line = step.line or self._find_line_containing(
                                workflow, step.uses
                            )
                            snippet = self._get_line_content(workflow, line)
                            findings.append(self._make_finding(
                                workflow=workflow,
                                line=line,
                                code_snippet=snippet,
                                context=(
                                    f"Potential auto-merge action: {step.uses}"
                                ),
                            ))
                            break

        return findings
