"""
EXE-001: Dangerous Script Execution Detection.

Detects actions/github-script with excessive permissions or
dangerous script content.
"""

from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)
from ..utils import contains_expression, extract_expressions, is_untrusted_input


class DangerousScriptExecutionRule(BaseRule):
    """EXE-001: Detects actions/github-script with potentially dangerous usage."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="EXE-001",
            severity=Severity.MEDIUM,
            description=(
                "Dangerous Script Execution: actions/github-script with "
                "potentially dangerous script content"
            ),
            category=Category.EXECUTION,
            recommendation=(
                "Review the script content carefully. Avoid using untrusted "
                "input in github-script. Ensure the script has minimal "
                "permissions."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.uses:
                    continue
                if "actions/github-script" not in step.uses:
                    continue

                # Check for untrusted input in the script
                script = step.with_.get("script", "")
                if isinstance(script, str) and contains_expression(script):
                    expressions = extract_expressions(script)
                    for expr in expressions:
                        if is_untrusted_input(expr):
                            line = step.line or self._find_line_containing(
                                workflow, step.uses
                            )
                            snippet = self._get_line_content(workflow, line)
                            findings.append(self._make_finding(
                                workflow=workflow,
                                line=line,
                                code_snippet=snippet,
                                context=(
                                    f"actions/github-script uses untrusted input: "
                                    f"${{{expr}}}"
                                ),
                            ))
                            break

                # Check for dangerous API calls in the script
                dangerous_apis = [
                    "repos.createDeployment",
                    "repos.createRelease",
                    "actions.createWorkflowDispatch",
                    "repos.mergeUpstream",
                    "orgs.update",
                    "users.updateAuthenticated",
                    "repos.createOrUpdateFileContents",
                ]
                if isinstance(script, str):
                    for api in dangerous_apis:
                        if api in script:
                            line = step.line or self._find_line_containing(
                                workflow, step.uses
                            )
                            snippet = self._get_line_content(workflow, line)
                            findings.append(self._make_finding(
                                workflow=workflow,
                                line=line,
                                code_snippet=snippet,
                                context=(
                                    f"actions/github-script calls dangerous API: "
                                    f"{api}"
                                ),
                            ))
                            break

        return findings
