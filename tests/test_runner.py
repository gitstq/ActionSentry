"""
Test runner for ActionSentry.

Runs all unit tests for the parser, rules, scanner, and formatters.
Uses only Python stdlib (unittest).
"""

import os
import sys
import unittest
import json
import tempfile
import shutil

# Add parent directory to path so we can import actionsentry
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from actionsentry.parser import parse_yaml, SimpleYAMLParser
from actionsentry.workflow_parser import parse_workflow_file, get_all_workflow_files
from actionsentry.models import Severity, Category, Workflow, Finding, Rule, ScanResult
from actionsentry.scanner import Scanner
from actionsentry.config import Config
from actionsentry.fixer import AutoFixer
from actionsentry.formatters.terminal import format_terminal
from actionsentry.formatters.json_fmt import format_json
from actionsentry.formatters.sarif import format_sarif
from actionsentry.formatters.markdown import format_markdown
from actionsentry.utils import (
    is_action_ref_pinned, is_branch_ref, parse_action_ref,
    contains_expression, extract_expressions, is_untrusted_input,
    strip_ansi, severity_emoji,
)


# ============================================================
# YAML Parser Tests
# ============================================================

class TestYAMLParser(unittest.TestCase):
    """Tests for the simple YAML parser."""

    def test_simple_mapping(self):
        content = "name: hello\nversion: 1.0\n"
        data, tracker = parse_yaml(content)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["name"], "hello")
        self.assertEqual(data["version"], 1.0)

    def test_nested_mapping(self):
        content = "on:\n  push:\n    branches:\n      - main\n"
        data, _ = parse_yaml(content)
        self.assertIn("on", data)
        self.assertIn("push", data["on"])

    def test_sequence(self):
        content = "items:\n  - apple\n  - banana\n  - cherry\n"
        data, _ = parse_yaml(content)
        self.assertEqual(data["items"], ["apple", "banana", "cherry"])

    def test_boolean_values(self):
        content = "enabled: true\ndisabled: false\n"
        data, _ = parse_yaml(content)
        self.assertTrue(data["enabled"])
        self.assertFalse(data["disabled"])

    def test_null_values(self):
        content = "value: null\nother: ~\n"
        data, _ = parse_yaml(content)
        self.assertIsNone(data["value"])
        self.assertIsNone(data["other"])

    def test_number_values(self):
        content = "count: 42\nrate: 3.14\n"
        data, _ = parse_yaml(content)
        self.assertEqual(data["count"], 42)
        self.assertAlmostEqual(data["rate"], 3.14)

    def test_quoted_strings(self):
        content = 'name: "hello world"\npath: \'single/quoted\'\n'
        data, _ = parse_yaml(content)
        self.assertEqual(data["name"], "hello world")
        self.assertEqual(data["path"], "single/quoted")

    def test_comments(self):
        content = "# This is a comment\nname: test\n  # inline comment\n"
        data, _ = parse_yaml(content)
        self.assertEqual(data["name"], "test")

    def test_flow_sequence(self):
        content = "items: [a, b, c]\n"
        data, _ = parse_yaml(content)
        self.assertEqual(data["items"], ["a", "b", "c"])

    def test_flow_mapping(self):
        content = "config: {key: value, num: 42}\n"
        data, _ = parse_yaml(content)
        self.assertEqual(data["config"]["key"], "value")

    def test_multiline_string_literal(self):
        content = "script: |\n  echo hello\n  echo world\n"
        data, _ = parse_yaml(content)
        self.assertIn("echo hello", data["script"])
        self.assertIn("echo world", data["script"])

    def test_anchors_and_aliases(self):
        content = "defaults: &defaults\n  timeout: 30\nprod:\n  <<: *defaults\n  env: production\n"
        data, _ = parse_yaml(content)
        self.assertIn("defaults", data)
        self.assertIn("prod", data)

    def test_on_keyword_as_boolean(self):
        """Test that 'on: push' is handled correctly (on is a Python keyword)."""
        content = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        data, _ = parse_yaml(content)
        # 'on' might be parsed as True (boolean) since YAML treats 'on' as true
        self.assertTrue(data is not None)

    def test_empty_content(self):
        content = ""
        data, _ = parse_yaml(content)
        self.assertIsNone(data)

    def test_complex_workflow(self):
        content = """name: CI
on:
  push:
    branches: [main]
  pull_request:
permissions: read-all
env:
  NODE_ENV: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm test
"""
        data, _ = parse_yaml(content)
        self.assertEqual(data["name"], "CI")
        self.assertIn("push", data["on"])


# ============================================================
# Utility Tests
# ============================================================

class TestUtils(unittest.TestCase):
    """Tests for utility functions."""

    def test_is_action_ref_pinned_sha(self):
        self.assertTrue(is_action_ref_pinned("abc123def456789012345678901234567890abcd"))

    def test_is_action_ref_pinned_tag(self):
        self.assertTrue(is_action_ref_pinned("v1.2.3"))
        self.assertTrue(is_action_ref_pinned("v3.0"))

    def test_is_branch_ref(self):
        self.assertTrue(is_branch_ref("main"))
        self.assertTrue(is_branch_ref("master"))
        self.assertFalse(is_branch_ref("v1.2.3"))
        self.assertFalse(is_branch_ref("abc123"))

    def test_parse_action_ref(self):
        result = parse_action_ref("actions/checkout@v3")
        self.assertEqual(result, ("actions", "checkout", "v3"))

        result = parse_action_ref("actions/cache@v3.0.0")
        self.assertEqual(result, ("actions", "cache", "v3.0.0"))

        result = parse_action_ref("./local/action")
        self.assertIsNone(result)

    def test_contains_expression(self):
        self.assertTrue(contains_expression("echo ${{ github.event.inputs.x }}"))
        self.assertFalse(contains_expression("echo hello"))
        self.assertFalse(contains_expression(""))

    def test_extract_expressions(self):
        exprs = extract_expressions("echo ${{ github.event.inputs.x }} and ${{ github.sha }}")
        self.assertEqual(len(exprs), 2)
        self.assertIn("github.event.inputs.x", [e.strip() for e in exprs])

    def test_is_untrusted_input(self):
        self.assertTrue(is_untrusted_input("github.event.inputs.user_input"))
        self.assertTrue(is_untrusted_input("github.event.pull_request.head.ref"))
        self.assertFalse(is_untrusted_input("github.sha"))
        self.assertFalse(is_untrusted_input("github.repository"))

    def test_strip_ansi(self):
        text = "\033[91mHello\033[0m"
        self.assertEqual(strip_ansi(text), "Hello")

    def test_severity_emoji(self):
        self.assertEqual(severity_emoji("HIGH"), "\U0001f534")
        self.assertEqual(severity_emoji("MEDIUM"), "\U0001f7e1")


# ============================================================
# Workflow Parser Tests
# ============================================================

class TestWorkflowParser(unittest.TestCase):
    """Tests for the workflow parser."""

    TESTS_DIR = os.path.join(os.path.dirname(__file__), ".github", "workflows")

    def test_parse_simple_workflow(self):
        path = os.path.join(self.TESTS_DIR, "wrk001.yml")
        workflow, error = parse_workflow_file(path)
        self.assertIsNone(error)
        self.assertIsNotNone(workflow)
        self.assertEqual(workflow.name, "Unpinned Triggers Test")
        self.assertIn("push", workflow.triggers)

    def test_parse_comprehensive_workflow(self):
        path = os.path.join(self.TESTS_DIR, "comprehensive.yml")
        workflow, error = parse_workflow_file(path)
        self.assertIsNone(error)
        self.assertIsNotNone(workflow)
        self.assertEqual(workflow.name, "CI Pipeline")
        self.assertGreater(len(workflow.jobs), 0)

    def test_parse_nonexistent_file(self):
        workflow, error = parse_workflow_file("/nonexistent/file.yml")
        self.assertIsNotNone(error)
        self.assertIsNone(workflow)

    def test_get_all_workflow_files(self):
        # get_all_workflow_files expects the parent directory of .github/
        files = get_all_workflow_files(os.path.dirname(__file__))
        self.assertGreater(len(files), 0)


# ============================================================
# Rule Tests
# ============================================================

class TestRules(unittest.TestCase):
    """Tests for individual security rules."""

    TESTS_DIR = os.path.join(os.path.dirname(__file__), ".github", "workflows")

    def _parse_and_scan(self, filename):
        """Helper to parse a workflow and run all rules."""
        path = os.path.join(self.TESTS_DIR, filename)
        workflow, error = parse_workflow_file(path)
        self.assertIsNone(error, f"Failed to parse {filename}: {error}")
        scanner = Scanner()
        # scanner.scan expects the parent of .github/ directory
        result = scanner.scan(path=os.path.join(os.path.dirname(__file__)))
        return result

    def test_cmd001_command_injection(self):
        result = self._parse_and_scan("cmd001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("CMD-001", rule_ids)

    def test_perm001_excessive_permissions(self):
        result = self._parse_and_scan("perm001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("PERM-001", rule_ids)

    def test_sec001_inherited_secrets(self):
        result = self._parse_and_scan("sec001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("SEC-001", rule_ids)

    def test_sec002_hardcoded_secrets(self):
        result = self._parse_and_scan("sec002.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("SEC-002", rule_ids)

    def test_trg001_risky_triggers(self):
        result = self._parse_and_scan("trg001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("TRG-001", rule_ids)

    def test_pin001_unpinned_actions(self):
        result = self._parse_and_scan("pin001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("PIN-001", rule_ids)

    def test_sec003_self_hosted_runner(self):
        result = self._parse_and_scan("sec003.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("SEC-003", rule_ids)

    def test_exe001_dangerous_script(self):
        result = self._parse_and_scan("exe001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("EXE-001", rule_ids)

    def test_env001_env_injection(self):
        result = self._parse_and_scan("env001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("ENV-001", rule_ids)

    def test_shl001_shell_issues(self):
        result = self._parse_and_scan("shl001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("SHL-001", rule_ids)

    def test_sec004_token_access(self):
        result = self._parse_and_scan("sec004.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("SEC-004", rule_ids)

    def test_aut001_auto_merge(self):
        result = self._parse_and_scan("aut001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("AUT-001", rule_ids)

    def test_chk001_checkout_credentials(self):
        result = self._parse_and_scan("chk001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("CHK-001", rule_ids)

    def test_wrk001_unpinned_triggers(self):
        result = self._parse_and_scan("wrk001.yml")
        rule_ids = [f.rule.rule_id for f in result.findings]
        self.assertIn("WRK-001", rule_ids)

    def test_comprehensive_workflow(self):
        """The comprehensive workflow should trigger multiple rules."""
        result = self._parse_and_scan("comprehensive.yml")
        rule_ids = set(f.rule.rule_id for f in result.findings)
        # Should detect at least 5 different rule violations
        self.assertGreaterEqual(len(rule_ids), 5,
                                f"Expected >= 5 rules, got: {rule_ids}")


# ============================================================
# Scanner Tests
# ============================================================

class TestScanner(unittest.TestCase):
    """Tests for the scanner."""

    TESTS_DIR = os.path.join(os.path.dirname(__file__), ".github", "workflows")

    def test_scan_directory(self):
        scanner = Scanner()
        result = scanner.scan(path=os.path.dirname(__file__))
        self.assertGreater(len(result.scanned_files), 0)
        self.assertGreater(result.total_findings, 0)

    def test_scan_with_severity_filter(self):
        scanner = Scanner()
        result = scanner.scan(
            path=self.TESTS_DIR,
            severity_filter=Severity.HIGH,
        )
        for finding in result.findings:
            self.assertGreaterEqual(finding.rule.severity, Severity.HIGH)

    def test_scan_with_ignore_rules(self):
        scanner = Scanner()
        result = scanner.scan(
            path=self.TESTS_DIR,
            ignore_rules={"CMD-001", "PIN-001"},
        )
        rule_ids = {f.rule.rule_id for f in result.findings}
        self.assertNotIn("CMD-001", rule_ids)
        self.assertNotIn("PIN-001", rule_ids)

    def test_scan_nonexistent_path(self):
        scanner = Scanner()
        result = scanner.scan(path="/nonexistent/path")
        self.assertGreater(len(result.errors), 0)

    def test_list_rules(self):
        scanner = Scanner()
        rules = scanner.list_rules()
        self.assertGreaterEqual(len(rules), 14)


# ============================================================
# Formatter Tests
# ============================================================

class TestFormatters(unittest.TestCase):
    """Tests for output formatters."""

    def _make_result(self):
        """Create a sample ScanResult for testing."""
        result = ScanResult()
        result.scanned_files = ["test.yml"]
        result.scan_time_ms = 100

        rule = Rule(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            description="Test finding",
            category=Category.COMMAND_INJECTION,
        )
        finding = Finding(
            rule=rule,
            file_path="test.yml",
            line=10,
            code_snippet="run: echo ${{ github.event.inputs.x }}",
            context="Test context",
        )
        result.findings.append(finding)
        return result

    def test_terminal_formatter(self):
        result = self._make_result()
        output = format_terminal(result, use_color=False)
        self.assertIn("TEST-001", output)
        self.assertIn("HIGH", output)
        self.assertIn("test.yml", output)

    def test_json_formatter(self):
        result = self._make_result()
        output = format_json(result)
        data = json.loads(output)
        self.assertEqual(data["summary"]["total_findings"], 1)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["rule_id"], "TEST-001")

    def test_sarif_formatter(self):
        result = self._make_result()
        output = format_sarif(result)
        data = json.loads(output)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "ActionSentry")
        self.assertEqual(len(data["runs"][0]["results"]), 1)

    def test_markdown_formatter(self):
        result = self._make_result()
        output = format_markdown(result)
        self.assertIn("# ActionSentry", output)
        self.assertIn("TEST-001", output)
        self.assertIn("HIGH", output)


# ============================================================
# Fixer Tests
# ============================================================

class TestFixer(unittest.TestCase):
    """Tests for the auto-fix engine."""

    def test_fix_persist_credentials(self):
        content = "      - uses: actions/checkout@v3\n        with:\n          persist-credentials: true\n"
        fixer = AutoFixer()

        rule = Rule(
            rule_id="CHK-001",
            severity=Severity.MEDIUM,
            description="Test",
            category=Category.CHECKOUT,
        )
        finding = Finding(rule=rule, file_path="test.yml", line=3)

        fixed_content, results = fixer.fix_content(content, [finding])
        self.assertTrue(results[0].success)
        self.assertIn("persist-credentials: false", fixed_content)
        self.assertNotIn("persist-credentials: true", fixed_content)

    def test_fix_excessive_permissions(self):
        content = "permissions: write-all\n"
        fixer = AutoFixer()

        rule = Rule(
            rule_id="PERM-001",
            severity=Severity.MEDIUM,
            description="Test",
            category=Category.PERMISSIONS,
        )
        finding = Finding(rule=rule, file_path="test.yml", line=1)

        fixed_content, results = fixer.fix_content(content, [finding])
        self.assertTrue(results[0].success)
        self.assertIn("contents: read", fixed_content)

    def test_can_fix(self):
        fixer = AutoFixer()
        rule = Rule(
            rule_id="CHK-001",
            severity=Severity.MEDIUM,
            description="Test",
            category=Category.CHECKOUT,
        )
        finding = Finding(rule=rule, file_path="test.yml", line=1)
        self.assertTrue(fixer.can_fix(finding))

    def test_cannot_fix(self):
        fixer = AutoFixer()
        rule = Rule(
            rule_id="CMD-001",
            severity=Severity.HIGH,
            description="Test",
            category=Category.COMMAND_INJECTION,
        )
        finding = Finding(rule=rule, file_path="test.yml", line=1)
        self.assertFalse(fixer.can_fix(finding))


# ============================================================
# Config Tests
# ============================================================

class TestConfig(unittest.TestCase):
    """Tests for the configuration loader."""

    def test_default_config(self):
        config = Config.load(base_path="/nonexistent")
        self.assertEqual(config.ignore_rules, set())
        self.assertEqual(config.exclude_paths, [])

    def test_config_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("ignore:\n  - CMD-001\n  - PIN-001\n")
            f.write("min_severity: HIGH\n")
            f.write("exclude:\n  - experimental/\n")
            config_path = f.name

        try:
            config = Config.load(config_path=config_path)
            self.assertIn("CMD-001", config.ignore_rules)
            self.assertIn("PIN-001", config.ignore_rules)
            self.assertEqual(config.min_severity, Severity.HIGH)
            self.assertIn("experimental/", config.exclude_paths)
        finally:
            os.unlink(config_path)


# ============================================================
# Main Test Runner
# ============================================================

def run_tests():
    """Run all tests and return the exit code."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestYAMLParser))
    suite.addTests(loader.loadTestsFromTestCase(TestUtils))
    suite.addTests(loader.loadTestsFromTestCase(TestWorkflowParser))
    suite.addTests(loader.loadTestsFromTestCase(TestRules))
    suite.addTests(loader.loadTestsFromTestCase(TestScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestFormatters))
    suite.addTests(loader.loadTestsFromTestCase(TestFixer))
    suite.addTests(loader.loadTestsFromTestCase(TestConfig))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 60)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
