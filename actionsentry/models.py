"""
Data models for ActionSentry findings, rules, workflows, etc.
"""

from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Severity levels for findings."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Return numeric rank for sorting (higher = more severe)."""
        order = {Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
        return order[self]

    def __lt__(self, other):
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented


class Category(Enum):
    """Categories for security rules."""
    COMMAND_INJECTION = "command-injection"
    PERMISSIONS = "permissions"
    SECRETS = "secrets"
    TRIGGERS = "triggers"
    PINNING = "pinning"
    RUNNERS = "runners"
    EXECUTION = "execution"
    ENVIRONMENT = "environment"
    TOKENS = "tokens"
    MERGE = "merge"
    CHECKOUT = "checkout"
    SHELL = "shell"
    WORKFLOW = "workflow"


class Rule:
    """Represents a security rule."""

    def __init__(
        self,
        rule_id: str,
        severity: Severity,
        description: str,
        category: Category,
        recommendation: str = "",
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description
        self.category = category
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "severity": self.severity.value,
            "description": self.description,
            "category": self.category.value,
            "recommendation": self.recommendation,
        }

    def __repr__(self):
        return f"Rule({self.rule_id}, {self.severity.value}, {self.description})"


class Finding:
    """Represents a single finding from a security scan."""

    def __init__(
        self,
        rule: Rule,
        file_path: str,
        line: int,
        column: int = 1,
        code_snippet: str = "",
        context: str = "",
        fix_suggestion: str = "",
    ):
        self.rule = rule
        self.file_path = file_path
        self.line = line
        self.column = column
        self.code_snippet = code_snippet
        self.context = context
        self.fix_suggestion = fix_suggestion

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity.value,
            "description": self.rule.description,
            "category": self.rule.category.value,
            "file": self.file_path,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "context": self.context,
            "fix_suggestion": self.fix_suggestion,
        }

    def __repr__(self):
        return (
            f"Finding({self.rule.rule_id} @ {self.file_path}:{self.line})"
        )


class WorkflowStep:
    """Represents a single step in a workflow job."""

    def __init__(self, name: str = "", uses: str = "", run: str = "",
                 env: Optional[Dict] = None, with_: Optional[Dict] = None,
                 shell: str = "", line: int = 0, working_directory: str = "",
                 continue_on_error: bool = False, timeout_minutes: int = 0):
        self.name = name
        self.uses = uses
        self.run = run
        self.env = env or {}
        self.with_ = with_ or {}
        self.shell = shell
        self.line = line
        self.working_directory = working_directory
        self.continue_on_error = continue_on_error
        self.timeout_minutes = timeout_minutes


class WorkflowJob:
    """Represents a single job in a workflow."""

    def __init__(self, name: str = "", job_id: str = "",
                 runs_on: Optional[List[str]] = None,
                 steps: Optional[List[WorkflowStep]] = None,
                 permissions: Optional[Dict] = None,
                 env: Optional[Dict] = None,
                 services: Optional[Dict] = None,
                 needs: Optional[List[str]] = None,
                 if_condition: str = "",
                 line: int = 0):
        self.name = name
        self.job_id = job_id
        self.runs_on = runs_on or []
        self.steps = steps or []
        self.permissions = permissions
        self.env = env or {}
        self.services = services or {}
        self.needs = needs or []
        self.if_condition = if_condition
        self.line = line


class Workflow:
    """Represents a parsed GitHub Actions workflow file."""

    def __init__(self, file_path: str = "", raw_content: str = ""):
        self.file_path = file_path
        self.raw_content = raw_content
        self.name: str = ""
        self.triggers: Dict[str, Any] = {}
        self.permissions: Optional[Dict] = None
        self.env: Dict = {}
        self.jobs: List[WorkflowJob] = []
        self.concurrency: Optional[Dict] = None
        self.on: Optional[Dict] = None  # raw 'on' key data
        self.raw: Dict = {}
        self.lines: List[str] = []
        self.parse_errors: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "name": self.name,
            "triggers": self.triggers,
            "permissions": self.permissions,
            "env": self.env,
            "jobs": [
                {
                    "id": j.job_id,
                    "name": j.name,
                    "runs_on": j.runs_on,
                    "permissions": j.permissions,
                    "steps": [
                        {
                            "name": s.name,
                            "uses": s.uses,
                            "run": s.run,
                            "shell": s.shell,
                            "env": s.env,
                            "with": s.with_,
                            "line": s.line,
                        }
                        for s in j.steps
                    ],
                }
                for j in self.jobs
            ],
        }


class ScanResult:
    """Result of a scan operation."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.scanned_files: List[str] = []
        self.skipped_files: List[str] = []
        self.errors: List[str] = []
        self.scan_time_ms: int = 0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def findings_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.rule.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "errors": self.errors,
            "scan_time_ms": self.scan_time_ms,
            "findings": [f.to_dict() for f in self.findings],
        }
