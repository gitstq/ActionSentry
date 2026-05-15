"""
CHK-001: Checkout with Persisted Credentials Detection.

Detects actions/checkout with persist-credentials: true, which can
leave the GITHUB_TOKEN accessible on disk after the job completes.
"""

from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)


class CheckoutPersistedCredentialsRule(BaseRule):
    """CHK-001: Detects actions/checkout with persist-credentials: true."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="CHK-001",
            severity=Severity.MEDIUM,
            description=(
                "Persisted Credentials: actions/checkout with "
                "persist-credentials: true can leave tokens on disk"
            ),
            category=Category.CHECKOUT,
            recommendation=(
                "Set 'persist-credentials: false' in actions/checkout unless "
                "you specifically need the token for subsequent steps. "
                "This prevents the GITHUB_TOKEN from being accessible on disk."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.uses:
                    continue
                if "actions/checkout" not in step.uses:
                    continue

                # Check persist-credentials in with
                persist = step.with_.get("persist-credentials")
                if persist is True or persist == "true":
                    line = step.line or self._find_line_containing(
                        workflow, step.uses
                    )
                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=(
                            f"actions/checkout has persist-credentials: true "
                            f"in job '{job.job_id}'"
                        ),
                        fix_suggestion=(
                            "Set 'persist-credentials: false' unless "
                            "you need git push access in later steps."
                        ),
                    ))

        return findings
