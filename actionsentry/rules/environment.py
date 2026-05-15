"""
ENV-001: Environment Variable Injection Detection.

Detects untrusted input being assigned to environment variables
which could lead to injection attacks.
"""

from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)
from ..utils import contains_expression, extract_expressions, is_untrusted_input


class EnvironmentVariableInjectionRule(BaseRule):
    """ENV-001: Detects untrusted input in environment variables."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="ENV-001",
            severity=Severity.HIGH,
            description=(
                "Environment Variable Injection: Untrusted input assigned to "
                "environment variable"
            ),
            category=Category.ENVIRONMENT,
            recommendation=(
                "Validate and sanitize untrusted input before assigning to "
                "environment variables. Use GitHub Actions expressions with "
                "filter functions or external validation."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []

        # Check top-level env
        self._check_env_dict(workflow.env, "workflow", workflow, findings)

        # Check job and step level env
        for job in workflow.jobs:
            self._check_env_dict(
                job.env, f"job '{job.job_id}'", workflow, findings
            )
            for step in job.steps:
                scope = f"step '{step.name or step.uses or 'unnamed'}'"
                self._check_env_dict(step.env, scope, workflow, findings)

        return findings

    def _check_env_dict(self, env: dict, scope: str, workflow,
                        findings: list):
        """Check an environment dict for untrusted input."""
        if not env or not isinstance(env, dict):
            return
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            if not contains_expression(value):
                continue
            expressions = extract_expressions(value)
            for expr in expressions:
                if is_untrusted_input(expr):
                    line = self._find_line_containing(workflow, key)
                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=(
                            f"Untrusted input in {scope} env var '{key}': "
                            f"${{{expr}}}"
                        ),
                    ))
                    break  # One finding per env var
