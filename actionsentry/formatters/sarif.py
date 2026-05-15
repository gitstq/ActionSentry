"""
SARIF v2.1.0 output formatter for GitHub Code Scanning integration.

SARIF (Static Analysis Results Interchange Format) is the standard
format for code scanning alerts on GitHub.
"""

import json
from typing import Any, Dict, List

from ..models import ScanResult, Finding, Severity


# SARIF severity level mapping
_SEVERITY_TO_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# SARIF severity rank (higher = more severe)
_SEVERITY_RANK = {
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class SARIFFormatter:
    """Formats scan results as SARIF v2.1.0."""

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def format(self, result: ScanResult) -> str:
        """Format the complete scan result as SARIF."""
        sarif = self._build_sarif(result)
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _build_sarif(self, result: ScanResult) -> Dict[str, Any]:
        """Build the SARIF document structure."""
        # Collect unique rules from findings
        rules = {}
        for finding in result.findings:
            rule_id = finding.rule.rule_id
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.rule.description,
                    "shortDescription": {
                        "text": finding.rule.description,
                    },
                    "fullDescription": {
                        "text": finding.rule.description,
                    },
                    "helpUri": f"https://github.com/actionsentry/actionsentry/rules/{rule_id}",
                    "properties": {
                        "category": finding.rule.category.value,
                        "security-severity": self._severity_to_cvss(finding.rule.severity),
                    },
                    "defaultConfiguration": {
                        "level": _SEVERITY_TO_LEVEL[finding.rule.severity],
                    },
                }

        # Group findings by file
        results_by_file: Dict[str, List[Finding]] = {}
        for finding in result.findings:
            results_by_file.setdefault(finding.file_path, []).append(finding)

        # Build artifacts and results
        artifacts = []
        all_results = []

        for file_path, findings in results_by_file.items():
            artifacts.append({
                "location": {
                    "uri": file_path,
                },
            })

            for finding in findings:
                result = self._build_result(finding)
                all_results.append(result)

        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ActionSentry",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/actionsentry/actionsentry",
                            "rules": list(rules.values()),
                        },
                    },
                    "artifacts": artifacts,
                    "results": all_results,
                }
            ],
        }

        return sarif

    def _build_result(self, finding: Finding) -> Dict[str, Any]:
        """Build a SARIF result for a single finding."""
        result: Dict[str, Any] = {
            "ruleId": finding.rule.rule_id,
            "level": _SEVERITY_TO_LEVEL[finding.rule.severity],
            "message": {
                "text": finding.rule.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": finding.column,
                        },
                    },
                }
            ],
            "properties": {
                "context": finding.context,
            },
        }

        if finding.fix_suggestion:
            result["fixes"] = [
                {
                    "description": {
                        "text": finding.fix_suggestion,
                    },
                }
            ]

        if finding.code_snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.code_snippet.strip(),
            }

        return result

    def _severity_to_cvss(self, severity: Severity) -> str:
        """Convert severity to a CVSS-like score string."""
        mapping = {
            Severity.HIGH: "9.0",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0",
            Severity.INFO: "0.0",
        }
        return mapping.get(severity, "0.0")


def format_sarif(result: ScanResult) -> str:
    """Convenience function to format results as SARIF."""
    formatter = SARIFFormatter()
    return formatter.format(result)
