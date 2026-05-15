"""
PIN-001: Unpinned Action References Detection.

Detects actions using @main, @master, or other branch references
instead of SHA commit hashes.
"""

from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)
from ..utils import parse_action_ref, is_branch_ref, is_action_ref_pinned


class UnpinnedActionRule(BaseRule):
    """PIN-001: Detects actions referenced by branch instead of SHA."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="PIN-001",
            severity=Severity.MEDIUM,
            description=(
                "Unpinned Action: Action referenced by branch/tag instead of "
                "commit SHA"
            ),
            category=Category.PINNING,
            recommendation=(
                "Pin actions to a specific commit SHA to prevent supply chain "
                "attacks. Example: uses: actions/checkout@abc123def456..."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.uses:
                    continue

                # Skip local actions
                if step.uses.startswith("./"):
                    continue

                ref_info = parse_action_ref(step.uses)
                if ref_info is None:
                    continue

                _, _, ref = ref_info

                # Check if it's a branch reference
                if is_branch_ref(ref):
                    line = step.line or self._find_line_containing(
                        workflow, step.uses
                    )
                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=(
                            f"Action '{step.uses}' uses branch reference "
                            f"'@{ref}' instead of commit SHA"
                        ),
                        fix_suggestion=(
                            f"Pin to a specific commit SHA: "
                            f"{step.uses.split('@')[0]}@<commit-sha>"
                        ),
                    ))
                elif not is_action_ref_pinned(ref):
                    # Not a branch but also not a SHA (could be a tag)
                    # Tags are somewhat better but still mutable
                    line = step.line or self._find_line_containing(
                        workflow, step.uses
                    )
                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=(
                            f"Action '{step.uses}' uses tag reference "
                            f"'@{ref}' instead of commit SHA"
                        ),
                        fix_suggestion=(
                            f"Pin to a specific commit SHA: "
                            f"{step.uses.split('@')[0]}@<commit-sha>"
                        ),
                    ))

        return findings
