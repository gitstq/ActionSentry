"""
Utility functions for ActionSentry.
"""

import os
import re
import glob
from typing import List, Optional, Tuple


def find_workflow_files(path: str) -> List[str]:
    """Find all workflow YAML files in the given path."""
    workflows_dir = os.path.join(path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return []
    files = []
    for pattern in ("*.yml", "*.yaml"):
        files.extend(glob.glob(os.path.join(workflows_dir, pattern)))
    return sorted(files)


def read_file(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Read a file and return (content, error). Returns (None, error) on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read(), None
    except IOError as e:
        return None, str(e)


def get_line_at(content: str, line_num: int) -> str:
    """Get a specific line from content (1-indexed)."""
    lines = content.split("\n")
    if 1 <= line_num <= len(lines):
        return lines[line_num - 1]
    return ""


def get_code_snippet(content: str, line_num: int, context: int = 1) -> str:
    """Get a code snippet around a specific line."""
    lines = content.split("\n")
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    return "\n".join(lines[start:end])


def severity_emoji(severity: str) -> str:
    """Return an emoji for a severity level."""
    mapping = {
        "HIGH": "\U0001f534",
        "MEDIUM": "\U0001f7e1",
        "LOW": "\U0001f535",
        "INFO": "\u26aa",
    }
    return mapping.get(severity, "\u2753")


def severity_color(severity: str) -> str:
    """Return ANSI color code for a severity level."""
    mapping = {
        "HIGH": "\033[91m",    # Red
        "MEDIUM": "\033[93m",  # Yellow
        "LOW": "\033[94m",     # Blue
        "INFO": "\033[90m",    # Gray
    }
    return mapping.get(severity, "\033[0m")


def color_text(text: str, color_code: str) -> str:
    """Wrap text in ANSI color codes."""
    reset = "\033[0m"
    return f"{color_code}{text}{reset}"


def bold_text(text: str) -> str:
    """Wrap text in ANSI bold codes."""
    return f"\033[1m{text}\033[0m"


def dim_text(text: str) -> str:
    """Wrap text in ANSI dim codes."""
    return f"\033[2m{text}\033[0m"


def supports_color() -> bool:
    """Check if the terminal supports color output."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") in ("dumb", ""):
        return False
    if not hasattr(os, "isatty"):
        return True
    return os.isatty(1) if hasattr(os, "isatty") else True


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def is_action_ref_pinned(ref: str) -> bool:
    """Check if an action reference is pinned to a SHA commit hash."""
    if not ref:
        return False
    # SHA pinning: 40 hex chars
    if re.match(r"^[0-9a-f]{40}$", ref):
        return True
    # Tag pinning like v1.2.3 is considered "pinned" but not ideal
    if re.match(r"^v?\d+\.\d+", ref):
        return True
    return False


def is_branch_ref(ref: str) -> bool:
    """Check if an action reference points to a branch."""
    if not ref:
        return False
    return ref in ("main", "master", "develop", "dev", "next", "beta", "canary")


def parse_action_ref(uses: str) -> Optional[Tuple[str, str, str]]:
    """Parse an action 'uses' reference into (owner, repo, ref).
    Returns None if the reference is local (./) or invalid.
    """
    if not uses:
        return None
    # Local action reference
    if uses.startswith("./") or uses.startswith("./"):
        return None
    # Handle owner/repo@ref or owner/repo/subpath@ref
    match = re.match(r"^([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)(?:/[^@]+)?@(.+)$", uses)
    if match:
        return match.group(1), match.group(2), match.group(3)
    return None


def contains_expression(text: str) -> bool:
    """Check if text contains a GitHub Actions expression ${{ ... }}."""
    if not text:
        return False
    return "${{" in text and "}}" in text


def extract_expressions(text: str) -> List[str]:
    """Extract all GitHub Actions expressions from text."""
    if not text:
        return []
    pattern = r"\$\{\{(.*?)\}\}"
    return re.findall(pattern, text, re.DOTALL)


def is_untrusted_input(expr: str) -> bool:
    """Check if an expression references potentially untrusted input."""
    if not expr:
        return False
    expr = expr.strip()
    untrusted_patterns = [
        "github.event.inputs.",
        "github.event.issue.",
        "github.event.pull_request.",
        "github.event.comment.",
        "github.event.review.",
        "github.event.head_commit.",
        "github.head_ref",
        "github.event_path",
        "github.event.workflow_run.head_branch",
    ]
    for pattern in untrusted_patterns:
        if pattern in expr:
            return True
    return False


def format_file_path(file_path: str, base_path: str = "") -> str:
    """Format a file path relative to a base path if possible."""
    if base_path and file_path.startswith(base_path):
        return os.path.relpath(file_path, base_path)
    return file_path
