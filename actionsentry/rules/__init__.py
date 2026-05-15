"""
Rule registry - manages all security rules.
"""

from typing import Dict, List, Optional, Type

from .base import BaseRule
from ..models import Rule as RuleModel, Severity


class RuleRegistry:
    """Registry for managing security rules."""

    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}

    def register(self, rule_instance: BaseRule):
        """Register a rule instance."""
        self._rules[rule_instance.rule.rule_id] = rule_instance

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[BaseRule]:
        """Get all registered rules."""
        return list(self._rules.values())

    def get_rules_by_severity(self, severity: Severity) -> List[BaseRule]:
        """Get all rules with a specific severity."""
        return [r for r in self._rules.values() if r.rule.severity == severity]

    def get_rule_models(self) -> List[RuleModel]:
        """Get all rule models (without instances)."""
        return [r.rule for r in self._rules.values()]

    def filter_rules(self, rule_ids: List[str]) -> List[BaseRule]:
        """Get specific rules by their IDs."""
        return [r for rid in rule_ids for r in [self._rules.get(rid)] if r is not None]

    def exclude_rules(self, exclude_ids: List[str]) -> List[BaseRule]:
        """Get all rules except the ones with the given IDs."""
        exclude_set = set(exclude_ids)
        return [r for rid, r in self._rules.items() if rid not in exclude_set]


def create_registry() -> RuleRegistry:
    """Create and populate the rule registry with all built-in rules."""
    registry = RuleRegistry()

    # Import all rule modules to trigger registration
    from .command_injection import CommandInjectionRule
    from .permissions import ExcessivePermissionsRule
    from .secrets import InheritedSecretsRule, HardcodedSecretsRule
    from .triggers import RiskyTriggersRule, UnpinnedWorkflowTriggersRule
    from .pinning import UnpinnedActionRule
    from .runners import SelfHostedRunnerRule
    from .execution import DangerousScriptExecutionRule
    from .environment import EnvironmentVariableInjectionRule
    from .shell import ShellcheckPlaceholderRule
    from .tokens import DangerousTokenAccessRule
    from .merge import AutoMergeDetectionRule
    from .checkout import CheckoutPersistedCredentialsRule

    # Register all rules
    rules = [
        CommandInjectionRule(),
        ExcessivePermissionsRule(),
        InheritedSecretsRule(),
        HardcodedSecretsRule(),
        RiskyTriggersRule(),
        UnpinnedActionRule(),
        SelfHostedRunnerRule(),
        DangerousScriptExecutionRule(),
        EnvironmentVariableInjectionRule(),
        ShellcheckPlaceholderRule(),
        UnpinnedWorkflowTriggersRule(),
        DangerousTokenAccessRule(),
        AutoMergeDetectionRule(),
        CheckoutPersistedCredentialsRule(),
    ]

    for rule in rules:
        registry.register(rule)

    return registry
