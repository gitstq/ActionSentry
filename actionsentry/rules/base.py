"""
Base rule class for ActionSentry security rules.
"""

from abc import ABC, abstractmethod
from typing import List

from ..models import Finding, Rule as RuleModel, Workflow, WorkflowJob, WorkflowStep


class BaseRule(ABC):
    """Abstract base class for all security rules."""

    @property
    @abstractmethod
    def rule(self) -> RuleModel:
        """Return the Rule model for this rule."""
        pass

    @abstractmethod
    def analyze(self, workflow: Workflow) -> List[Finding]:
        """Analyze a workflow and return any findings."""
        pass

    def _make_finding(
        self,
        workflow: Workflow,
        line: int,
        code_snippet: str = "",
        context: str = "",
        fix_suggestion: str = "",
    ) -> Finding:
        """Helper to create a Finding for this rule."""
        return Finding(
            rule=self.rule,
            file_path=workflow.file_path,
            line=line,
            code_snippet=code_snippet,
            context=context,
            fix_suggestion=fix_suggestion or self.rule.recommendation,
        )

    def _get_line_content(self, workflow: Workflow, line_num: int) -> str:
        """Get content of a specific line (1-indexed) from the workflow."""
        if 1 <= line_num <= len(workflow.lines):
            return workflow.lines[line_num - 1]
        return ""

    def _find_line_containing(self, workflow: Workflow, text: str) -> int:
        """Find the line number containing the given text."""
        for i, line in enumerate(workflow.lines):
            if text in line:
                return i + 1
        return 0
