"""
Configuration loader for ActionSentry.

Supports .actionsentry.yml configuration file in the project root.
"""

import os
from typing import Dict, List, Optional, Set

from .parser import parse_yaml_file
from .models import Severity


class Config:
    """ActionSentry configuration."""

    def __init__(self):
        self.ignore_rules: Set[str] = set()
        self.exclude_paths: List[str] = []
        self.severity_overrides: Dict[str, Severity] = {}
        self.baseline_file: str = ""
        self.output_format: str = "terminal"
        self.min_severity: Optional[Severity] = None
        self.show_info: bool = True

    @classmethod
    def load(cls, config_path: Optional[str] = None,
             base_path: str = ".") -> "Config":
        """Load configuration from file or defaults.

        Args:
            config_path: Explicit path to config file. If None, auto-detects.
            base_path: Base directory to search for config file.
        """
        config = cls()

        if config_path is None:
            config_path = cls._find_config(base_path)

        if config_path and os.path.isfile(config_path):
            config._load_from_file(config_path)

        return config

    @classmethod
    def _find_config(cls, base_path: str) -> Optional[str]:
        """Find the configuration file in the given base path."""
        candidates = [
            os.path.join(base_path, ".actionsentry.yml"),
            os.path.join(base_path, ".actionsentry.yaml"),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return None

    def _load_from_file(self, config_path: str):
        """Load configuration from a YAML file."""
        data, _, error = parse_yaml_file(config_path)
        if error or not isinstance(data, dict):
            return

        # Parse ignore rules
        ignore = data.get("ignore", data.get("ignore_rules", []))
        if isinstance(ignore, list):
            self.ignore_rules = set(str(r) for r in ignore)
        elif isinstance(ignore, str):
            self.ignore_rules = {r.strip() for r in ignore.split(",")}

        # Parse exclude paths
        exclude = data.get("exclude", data.get("exclude_paths", []))
        if isinstance(exclude, list):
            self.exclude_paths = [str(p) for p in exclude]

        # Parse severity overrides
        overrides = data.get("severity", data.get("severity_overrides", {}))
        if isinstance(overrides, dict):
            for rule_id, sev in overrides.items():
                try:
                    self.severity_overrides[rule_id] = Severity(sev.upper())
                except ValueError:
                    pass

        # Parse baseline file
        baseline = data.get("baseline", "")
        if isinstance(baseline, str):
            self.baseline_file = baseline

        # Parse output format
        fmt = data.get("format", data.get("output_format", ""))
        if isinstance(fmt, str):
            self.output_format = fmt

        # Parse minimum severity
        min_sev = data.get("min_severity", "")
        if isinstance(min_sev, str):
            try:
                self.min_severity = Severity(min_sev.upper())
            except ValueError:
                pass

        # Parse show_info
        show_info = data.get("show_info", True)
        if isinstance(show_info, bool):
            self.show_info = show_info

    def should_ignore_rule(self, rule_id: str) -> bool:
        """Check if a rule should be ignored."""
        return rule_id in self.ignore_rules

    def should_exclude_path(self, file_path: str) -> bool:
        """Check if a file path should be excluded."""
        for pattern in self.exclude_paths:
            if pattern in file_path:
                return True
        return False

    def get_severity(self, rule_id: str, default: Severity) -> Severity:
        """Get the effective severity for a rule."""
        return self.severity_overrides.get(rule_id, default)
