"""
SEC-003: Self-Hosted Runner Risk Detection.

Detects usage of self-hosted runners which can pose supply chain
and persistent threat risks.
"""

from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow,
)


class SelfHostedRunnerRule(BaseRule):
    """SEC-003: Detects self-hosted runner usage."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="SEC-003",
            severity=Severity.MEDIUM,
            description=(
                "Self-Hosted Runner: Using self-hosted runners can expose "
                "the runner environment to persistent threats"
            ),
            category=Category.RUNNERS,
            recommendation=(
                "Use GitHub-hosted runners when possible. If self-hosted runners "
                "are required, ensure they are ephemeral, isolated, and regularly "
                "updated. Avoid using self-hosted runners for pull_request events "
                "from public repositories."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            if not job.runs_on:
                continue
            for label in job.runs_on:
                if label == "self-hosted" or "self-hosted" in label:
                    # Check if this is triggered by PR events from public repos
                    is_pr_triggered = any(
                        t in workflow.triggers
                        for t in ("pull_request", "pull_request_target")
                    )
                    context = f"Job '{job.job_id}' runs on self-hosted runner"
                    if is_pr_triggered:
                        context += " (HIGH RISK: triggered by pull request event)"

                    line = self._find_line_containing(workflow, "runs-on")
                    # Try to find the specific job's runs-on
                    job_line = self._find_line_containing(workflow, job.job_id)
                    if job_line > 0:
                        for i in range(job_line - 1, min(job_line + 10, len(workflow.lines))):
                            if "runs-on" in workflow.lines[i]:
                                line = i + 1
                                break

                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=context,
                    ))
                    break  # One finding per job

        return findings
