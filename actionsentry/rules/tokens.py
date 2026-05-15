"""
SEC-004: Dangerous GitHub Token Access Detection.

Detects GITHUB_TOKEN being passed to external (non-official) actions,
which could lead to token theft.
"""

import re
from typing import List, Set

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow, WorkflowStep,
)

# GitHub's official action namespaces
OFFICIAL_NAMESPACES = {
    "actions",
    "github",
}

# Official actions that commonly need the token
OFFICIAL_ACTIONS_NEEDING_TOKEN = {
    "actions/checkout",
    "actions/create-release",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/cache",
    "actions/label",
    "actions/github-script",
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-go",
    "actions/setup-java",
    "actions/setup-dotnet",
    "actions/configure-pages",
    "actions/deploy-pages",
    "actions/upload-pages-artifact",
    "actions/stale",
    "actions/first-interaction",
    "actions/request-dispatch",
    "actions/manage-merged-pr",
}


class DangerousTokenAccessRule(BaseRule):
    """SEC-004: Detects GITHUB_TOKEN passed to external actions."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="SEC-004",
            severity=Severity.HIGH,
            description=(
                "Dangerous Token Access: GITHUB_TOKEN passed to external action"
            ),
            category=Category.TOKENS,
            recommendation=(
                "Only pass GITHUB_TOKEN to official GitHub Actions. "
                "For third-party actions, create a fine-grained PAT with "
                "minimal permissions and use that instead."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        for job in workflow.jobs:
            for step in job.steps:
                if not step.uses:
                    continue

                # Check if this is an official action
                action_name = step.uses.split("@")[0] if "@" in step.uses else step.uses
                if action_name in OFFICIAL_ACTIONS_NEEDING_TOKEN:
                    continue
                # Check namespace
                parts = action_name.split("/")
                if len(parts) >= 1 and parts[0] in OFFICIAL_NAMESPACES:
                    continue

                # Check if GITHUB_TOKEN is passed via env or with
                token_passed = False
                token_location = ""

                # Check env
                for key, value in step.env.items():
                    val_str = str(value)
                    if "GITHUB_TOKEN" in val_str or "github.token" in val_str.lower():
                        token_passed = True
                        token_location = f"env.{key}"
                        break

                # Check with
                if not token_passed:
                    for key, value in step.with_.items():
                        val_str = str(value)
                        if "GITHUB_TOKEN" in val_str or "github.token" in val_str.lower():
                            token_passed = True
                            token_location = f"with.{key}"
                            break

                # Check run step for token references
                if not token_passed and step.run:
                    if "GITHUB_TOKEN" in step.run or "${{ secrets.GITHUB_TOKEN" in step.run:
                        # This is less severe for run steps but still worth noting
                        # Only flag if the step uses external actions context
                        pass

                if token_passed:
                    line = step.line or self._find_line_containing(
                        workflow, step.uses
                    )
                    snippet = self._get_line_content(workflow, line)
                    findings.append(self._make_finding(
                        workflow=workflow,
                        line=line,
                        code_snippet=snippet,
                        context=(
                            f"GITHUB_TOKEN passed via {token_location} to "
                            f"external action '{step.uses}'"
                        ),
                    ))

        return findings
