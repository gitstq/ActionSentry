"""
Main scanner orchestrator for ActionSentry.

Coordinates parsing workflows, applying rules, and collecting findings.
"""

import os
import time
from typing import List, Optional, Set

from .models import (
    ScanResult, Finding, Severity, Workflow,
)
from .config import Config
from .workflow_parser import parse_workflow_file, get_all_workflow_files
from .rules import create_registry, RuleRegistry
from .fixer import AutoFixer


class Scanner:
    """Main scanner that orchestrates workflow analysis."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.registry = create_registry()
        self.fixer = AutoFixer()

    def scan(self, path: str = ".",
             severity_filter: Optional[Severity] = None,
             ignore_rules: Optional[Set[str]] = None,
             auto_fix: bool = False) -> ScanResult:
        """Scan workflows in the given path.

        Args:
            path: Base directory to scan for workflows.
            severity_filter: Only report findings at or above this severity.
            ignore_rules: Set of rule IDs to ignore.
            auto_fix: Whether to apply auto-fixes.

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult()
        start_time = time.time()

        # Merge ignore rules from config and CLI
        effective_ignore = set(self.config.ignore_rules)
        if ignore_rules:
            effective_ignore.update(ignore_rules)

        # Get active rules
        active_rules = self.registry.exclude_rules(list(effective_ignore))

        # Find workflow files
        workflow_files = get_all_workflow_files(path)

        if not workflow_files:
            result.errors.append(
                f"No workflow files found in {os.path.join(path, '.github', 'workflows')}"
            )
            result.scan_time_ms = int((time.time() - start_time) * 1000)
            return result

        # Parse and analyze each workflow
        for file_path in workflow_files:
            # Check exclusion
            if self.config.should_exclude_path(file_path):
                result.skipped_files.append(file_path)
                continue

            # Parse workflow
            workflow, error = parse_workflow_file(file_path)
            if error:
                result.errors.append(f"{file_path}: {error}")
                result.scanned_files.append(file_path)
                continue

            result.scanned_files.append(file_path)

            # Apply each rule
            for rule_instance in active_rules:
                try:
                    findings = rule_instance.analyze(workflow)
                    result.findings.extend(findings)
                except Exception as e:
                    result.errors.append(
                        f"Error applying rule {rule_instance.rule.rule_id} "
                        f"to {file_path}: {e}"
                    )

        # Apply severity filtering
        effective_severity = severity_filter or self.config.min_severity
        if effective_severity:
            result.findings = [
                f for f in result.findings
                if f.rule.severity >= effective_severity
            ]

        # Sort findings by severity (descending) then by file and line
        result.findings.sort(
            key=lambda f: (-f.rule.severity.rank, f.file_path, f.line)
        )

        # Apply auto-fixes if requested
        if auto_fix:
            self._apply_fixes(result)

        result.scan_time_ms = int((time.time() - start_time) * 1000)
        return result

    def _apply_fixes(self, result: ScanResult):
        """Apply auto-fixes to findings and update file contents."""
        # Group fixable findings by file
        by_file = {}
        for finding in result.findings:
            if self.fixer.can_fix(finding):
                by_file.setdefault(finding.file_path, []).append(finding)

        for file_path, findings in by_file.items():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                fixed_content, fix_results = self.fixer.fix_content(
                    content, findings
                )

                if fixed_content != content:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(fixed_content)

                    # Update fix suggestions in findings
                    for fr in fix_results:
                        if fr.success:
                            for finding in findings:
                                if finding == fr.finding:
                                    finding.fix_suggestion = (
                                        f"[AUTO-FIXED] {fr.description}"
                                    )
            except IOError as e:
                result.errors.append(f"Failed to fix {file_path}: {e}")

    def list_rules(self) -> List:
        """List all available rules."""
        return self.registry.get_rule_models()
