"""
TRG-001: Risky Triggers Detection.
WRK-001: Unpinned Workflow Triggers Detection.
"""

from typing import List

from .base import BaseRule
from ..models import (
    Finding, Rule, Severity, Category, Workflow,
)


class RiskyTriggersRule(BaseRule):
    """TRG-001: Detects pull_request_target trigger which can execute untrusted code."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="TRG-001",
            severity=Severity.HIGH,
            description=(
                "Risky Trigger: 'pull_request_target' can execute untrusted code "
                "from forked repositories"
            ),
            category=Category.TRIGGERS,
            recommendation=(
                "If you must use pull_request_target, ensure you do not check out "
                "untrusted code with actions/checkout. Use a separate job to check "
                "out the PR code and never run untrusted code in the context of "
                "the GITHUB_TOKEN. Consider using pull_request instead."
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []
        if "pull_request_target" in workflow.triggers:
            line = self._find_line_containing(workflow, "pull_request_target")
            snippet = self._get_line_content(workflow, line)
            findings.append(self._make_finding(
                workflow=workflow,
                line=line,
                code_snippet=snippet,
                context="Workflow triggered by pull_request_target event",
            ))
        return findings


class UnpinnedWorkflowTriggersRule(BaseRule):
    """WRK-001: Detects workflows triggered on all branches without restrictions."""

    @property
    def rule(self) -> Rule:
        return Rule(
            rule_id="WRK-001",
            severity=Severity.LOW,
            description=(
                "Unpinned Workflow Triggers: Workflow triggers are not restricted "
                "to specific branches or paths"
            ),
            category=Category.WORKFLOW,
            recommendation=(
                "Restrict workflow triggers to specific branches, tags, or paths "
                "to prevent unnecessary runs and reduce the attack surface. "
                "Example: push: { branches: [main, develop] }"
            ),
        )

    def analyze(self, workflow: Workflow) -> List[Finding]:
        findings = []

        risky_triggers = {
            "push": "Push trigger without branch restrictions",
            "workflow_dispatch": "Manual trigger enabled",
            "repository_dispatch": "External event trigger enabled",
            "schedule": "Scheduled trigger (verify cron expressions)",
        }

        for trigger_name, trigger_config in workflow.triggers.items():
            if trigger_name not in risky_triggers:
                continue

            # If the trigger has branch/path restrictions, it's fine
            if isinstance(trigger_config, dict):
                has_restrictions = any(
                    k in trigger_config
                    for k in ("branches", "tags", "paths", "branches-ignore",
                              "tags-ignore", "paths-ignore")
                )
                if has_restrictions:
                    continue

            line = self._find_line_containing(workflow, trigger_name)
            snippet = self._get_line_content(workflow, line)
            findings.append(self._make_finding(
                workflow=workflow,
                line=line,
                code_snippet=snippet,
                context=risky_triggers[trigger_name],
            ))

        return findings
