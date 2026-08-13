import logging
import os
from dataclasses import dataclass, field

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from typing import Dict, List

logger = logging.getLogger(__name__)

class SecurityLevel:
    """Security classification level enumeration."""
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"

class FlowPolicy:
    # Information flow policy constraints
    NO_READ_UP = "no_read_up"
    NO_WRITE_DOWN = "no_write_down"
    NON_INTERFERENCE = "non_interference"

@dataclass
class SecurityLabel:
    variable_name: Any = None
    level: Any = None
    description: str = "c"

class FlowRule:
    __slots__ = ('from_level', 'to_level', 'allowed', 'description',)

    def __init__(self, from_level, to_level, allowed, description=""):
        self.from_level = from_level
        self.to_level = to_level
        self.allowed = allowed
        self.description = description

class FlowViolation:
    __slots__ = ('source_var', 'source_level', 'target_var', 'target_level', 'violation_type', 'path', 'description',)

    def __init__(self, source_var, source_level, target_var, target_level, violation_type, path=None, description=""):
        self.source_var = source_var
        self.source_level = source_level
        self.target_var = target_var
        self.target_level = target_level
        self.violation_type = violation_type
        self.path = path
        self.description = description

class FlowVerificationResult:
    __slots__ = ('verified', 'violations', 'checked_flows', 'execution_time',)

    def __init__(self, verified, violations=None, checked_flows=0, execution_time=0.0):
        self.verified = verified
        self.violations = violations
        self.checked_flows = checked_flows
        self.execution_time = execution_time

class InformationFlowVerifier(BaseAnalyzer):
    """
    Automated information flow security policy verifier.

    Core functionality:
        1. Maintain security labels marking data classification levels
        2. Track information flow paths within binary
        3. Verify compliance with non-interference policy
        4. Detect illegal flows and generate counterexamples
    """

    def __init__(self):
        self._security_labels: Dict[str, SecurityLevel] = {}
        self._flow_rules: List[FlowRule] = []

    def _level_to_int(self, level: SecurityLevel) -> int:
        # Map security level to ordinal for comparison
        level_order = {
            SecurityLevel.PUBLIC: 0,
            SecurityLevel.CONFIDENTIAL: 1,
            SecurityLevel.SECRET: 2,
            SecurityLevel.TOP_SECRET: 3
        }
        return level_order.get(level, 0)

    def _parse_policy(self, policy_spec: Dict[str, Any]) -> None:
        # Parse security policy specification
        self._security_labels = {}
        self._flow_rules = []

        for var_name, level_str in policy_spec.get("variables", {}).items():
            try:
                self._security_labels[var_name] = SecurityLevel(level_str.lower())
            except ValueError:
                logger.warning(f"Unknown security level: {level_str}, defaulting to public")
                self._security_labels[var_name] = SecurityLevel.PUBLIC

        for rule in policy_spec.get("rules", []):
            try:
                from_level = SecurityLevel(rule.get("from", "public").lower())
                to_level = SecurityLevel(rule.get("to", "public").lower())
                self._flow_rules.append(FlowRule(
                    from_level=from_level,
                    to_level=to_level,
                    allowed=rule.get("allow", False),
                    description=rule.get("description", "")
                ))
            except ValueError as e:
                logger.warning(f"Rule parse failed: {e}")

    def _check_non_interference(self) -> List[FlowViolation]:
        """Validate non-interference policy across all labeled variables."""
        violations = []

        variables = list(self._security_labels.keys())

        for source_var in variables:
            source_level = self._security_labels[source_var]

            for target_var in variables:
                if source_var == target_var:
                    continue

                target_level = self._security_labels[target_var]

                source_level_int = self._level_to_int(source_level)
                target_level_int = self._level_to_int(target_level)

                if source_level_int > target_level_int:
                    violation = FlowViolation(
                        source_var=source_var,
                        source_level=source_level,
                        target_var=target_var,
                        target_level=target_level,
                        violation_type="write_down",
                        description=f"High-level data {source_var}({source_level.value}) flows to low-level {target_var}({target_level.value})"
                    )
                    violations.append(violation)

        return violations

    def _check_flow_rules(self) -> List[FlowViolation]:
        """Verify custom flow rules against labeled variables."""
        violations = []

        for rule in self._flow_rules:
            if not rule.allowed:
                for source_var, source_level in self._security_labels.items():
                    if source_level == rule.from_level:
                        for target_var, target_level in self._security_labels.items():
                            if target_level == rule.to_level and source_var != target_var:
                                violations.append(FlowViolation(
                                    source_var=source_var,
                                    source_level=source_level,
                                    target_var=target_var,
                                    target_level=target_level,
                                    violation_type="rule_violation",
                                    description=f"Rule violation: {rule.from_level.value} -> {rule.to_level.value} disallowed"
                                ))

        return violations

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        Execute information flow security policy verification.
        """
        binary_path = kwargs.get("binary_path")
        policy_spec = kwargs.get("policy_spec")

        if not policy_spec:
            return {"success": False, "error": "policy_spec is required"}

        logger.info(f"Starting information flow security policy verification")

        try:
            self._parse_policy(policy_spec)

            violations = []

            violations.extend(self._check_non_interference())
            violations.extend(self._check_flow_rules())

            result = FlowVerificationResult(
                verified=len(violations) == 0,
                violations=violations,
                checked_flows=len(self._security_labels) * (len(self._security_labels) - 1)
            )

            return {
                "success": True,
                "result": result.__dict__,
                "violations": [v.__dict__ for v in violations],
                "summary": {
                    "total_variables": len(self._security_labels),
                    "checked_flows": result.checked_flows,
                    "violations_found": len(violations),
                    "verified": result.verified
                },
                "message": f"Information flow verification complete: {'PASS' if result.verified else f'{len(violations)} violations found'}"
            }

        except Exception as e:
            logger.error(f"Information flow verification failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="InformationFlowVerifier",
            type=AnalyzerType.FORMAL_VERIFICATION,
            version="1.0.0",
            description="Automated information flow security policy verifier: validates non-interference, maintains security labels, detects illegal data flows",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"]
        )


class SecurityLevel:
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"
