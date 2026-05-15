"""
JSON output formatter for CI/CD integration.
"""

import json
from typing import Any, Dict

from ..models import ScanResult


class JSONFormatter:
    """Formats scan results as JSON."""

    def format(self, result: ScanResult) -> str:
        """Format the complete scan result as JSON."""
        data = self._build_output(result)
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _build_output(self, result: ScanResult) -> Dict[str, Any]:
        """Build the JSON output structure."""
        return {
            "tool": {
                "name": "actionsentry",
                "version": "1.0.0",
            },
            "summary": {
                "total_findings": result.total_findings,
                "findings_by_severity": result.findings_by_severity,
                "scanned_files": len(result.scanned_files),
                "skipped_files": len(result.skipped_files),
                "errors": len(result.errors),
                "scan_time_ms": result.scan_time_ms,
            },
            "findings": [f.to_dict() for f in result.findings],
            "errors": result.errors,
        }


def format_json(result: ScanResult) -> str:
    """Convenience function to format results as JSON."""
    formatter = JSONFormatter()
    return formatter.format(result)
