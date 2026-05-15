"""
PERM-001: Excessive Permissions Detection.

Detects permissions: write-all or permissions: read-all at the
workflow or job level, which grant more access than needed.
"""

from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow,
)


class ExcessivePermissionsRule(BaseRule):

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="PERM-001",
            severity=Severity.MEDIUM,
            description="Excessive Permissions: Workflow or job uses broad permission scope",
            category=Category.PERMISSIONS,
            recommendation=(
                "Use minimal permissions. Specify only the permissions "
                "your workflow needs, e.g., permissions: { contents: read }."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []

        # Check workflow-level permissions
        if workflow.permissions:
            raw = workflow.permissions.get("_raw", "")
            if raw in ("write-all", "read-all"):
                line = self._find_line_containing(workflow, "permissions:")
                snippet = self._get_line_content(workflow, line)
                findings.append(self._make_finding(
                    workflow=workflow,
                    line=line,
                    code_snippet=snippet,
                    context=f"Workflow-level permissions: {raw}",
                ))

        # Check job-level permissions
        for job in workflow.jobs:
            if job.permissions:
                raw = job.permissions.get("_raw", "")
                if raw in ("write-all", "read-all"):
                    line = self._find_line_containing(workflow, "permissions:")
                    # Try to find a more specific line near the job
                    job_line = self._find_line_containing(
                        workflow, job.job_id
                    )
                    if job_line > 0:
                        # Search for permissions after the job line
                        for i in range(job_line - 1, min(job_line + 20, len(workflow.lines))):
                            if "permissions:" in workflow.lines[i]:
                                line = i + 1
                                break
                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=f"Job '{job.job_id}' permissions: {raw}",
                    ))

        return findings
