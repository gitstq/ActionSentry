"""
SEC-001: Inherited Secrets Detection.
SEC-002: Hardcoded Secrets Detection.
"""

import re
from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowJob, WorkflowStep,
)
from ..utils import contains_expression


class InheritedSecretsRule(BaseRule):
    """SEC-001: Detects secrets: inherit which can leak secrets to forks."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="SEC-001",
            severity=Severity.HIGH,
            description=(
                "Inherited Secrets: 'secrets: inherit' can leak secrets "
                "to forked repositories"
            ),
            category=Category.SECRETS,
            recommendation=(
                "Avoid using 'secrets: inherit' in reusable workflows called "
                "from pull_request events. Explicitly pass only the secrets "
                "that are needed."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.uses:
                    continue
                secrets_val = step.with_.get("secrets", "")
                if secrets_val == "inherit":
                    line = step.line or self._find_line_containing(
                        workflow, "secrets: inherit"
                    )
                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=f"Step '{step.name or step.uses}' uses secrets: inherit",
                    ))
        return findings


# Patterns that look like hardcoded secrets/tokens
SECRET_PATTERNS = [
    re.compile(r"(?i)(token|api_key|apikey|secret|password|passwd|auth)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{8,}['\"]?"),
    re.compile(r"(?i)ghp_[a-zA-Z0-9]{36}"),       # GitHub PAT
    re.compile(r"(?i)gho_[a-zA-Z0-9]{36}"),       # GitHub OAuth
    re.compile(r"(?i)ghu_[a-zA-Z0-9]{36}"),       # GitHub User-to-server
    re.compile(r"(?i)ghs_[a-zA-Z0-9]{36}"),       # GitHub Server-to-server
    re.compile(r"(?i)github_pat_[a-zA-Z0-9_]{22,}"),  # GitHub fine-grained PAT
    re.compile(r"(?i)(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}"),  # AWS access key
    re.compile(r"(?i)npm_[a-zA-Z0-9]{36}"),       # NPM token
    re.compile(r"(?i)glpat-[a-zA-Z0-9\-]{20,}"),  # GitLab PAT
    re.compile(r"(?i)xox[bsp]-[a-zA-Z0-9\-]{10,}"),  # Slack token
    # Generic long base64-like strings that look like secrets
    re.compile(r"(?i)['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]"),
]


class HardcodedSecretsRule(BaseRule):
    """SEC-002: Detects potential hardcoded secrets/tokens in env vars."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="SEC-002",
            severity=Severity.HIGH,
            description="Hardcoded Secrets: Potential secret or token found in workflow",
            category=Category.SECRETS,
            recommendation=(
                "Use GitHub Secrets to store sensitive values. "
                "Access them via ${{ secrets.SECRET_NAME }} instead of "
                "hardcoding them in the workflow file."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []

        # Check env vars at all levels
        envs_to_check = []
        # Top-level env
        if workflow.env:
            envs_to_check.append(("workflow", workflow.env))
        # Job-level env
        for job in workflow.jobs:
            if job.env:
                envs_to_check.append((f"job '{job.job_id}'", job.env))
            # Step-level env
            for step in job.steps:
                if step.env:
                    envs_to_check.append(
                        (f"step '{step.name or step.uses or step.run[:30]}'", step.env)
                    )

        for scope, env_dict in envs_to_check:
            for key, value in env_dict.items():
                if not isinstance(value, str):
                    continue
                # Skip if it's an expression (those reference secrets properly)
                if contains_expression(value):
                    continue
                for pattern in SECRET_PATTERNS:
                    if pattern.search(value):
                        line = self._find_line_containing(workflow, key)
                        snippet = self._get_line_content(workflow, line)
                        # Mask the actual secret value in the snippet
                        masked = snippet[:max(0, len(snippet) - 20)] + "***"
                        findings.append(self._make_finding(
                            workflow=workflow,
                            line=line,
                            code_snippet=masked,
                            context=f"Potential secret in {scope} env var '{key}'",
                        ))
                        break  # One finding per env var

        return findings
