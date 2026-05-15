"""
CMD-001: Command Injection Detection.

Detects ${{ github.event.inputs.* }} or other untrusted expressions
directly used in shell commands (run: steps with sh/bash/pwsh).
"""

import re
from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)
from ..utils import contains_expression, extract_expressions, is_untrusted_input


class CommandInjectionRule(BaseRule):

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="CMD-001",
            severity=Severity.HIGH,
            description="Command Injection: Untrusted input used directly in shell command",
            category=Category.COMMAND_INJECTION,
            recommendation=(
                "Avoid using untrusted input directly in shell commands. "
                "Use environment variables with proper sanitization, or "
                "pass input through actions that handle it safely."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.run:
                    continue
                if not contains_expression(step.run):
                    continue

                expressions = extract_expressions(step.run)
                for expr in expressions:
                    if is_untrusted_input(expr):
                        line = step.line or self._find_line_containing(
                            workflow, step.run[:60]
                        )
                        snippet = self._get_line_content(workflow, line)
                        findings.append(self._make_finding(
                            workflow=workflow,
                            line=line,
                            code_snippet=snippet,
                            context=f"Expression: ${{{expr}}} in run step",
                        ))
                        break  # One finding per step is enough
        return findings
