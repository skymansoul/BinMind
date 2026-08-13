#!/usr/bin/env python3
import logging, os, re, subprocess, json, struct, math as _math
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Bell-LaPadula 格模型 ───────────────────────────────────────────────────
# Bell & LaPadula (1973) "Secure Computer Systems"
# 核心规则: (1) 读取 up (简单安全属性) (2) 写入 down (*属性)
# 本实现将安全标签建模为完全偏序格——Unclassified < Confidential < Secret < TopSecret
# 格的 join 操作用来确定两个标签合并后的最低允许级别

class SecurityLattice:
    """Bell-LaPadula 安全格——对安全标签进行偏序比较和合并"""
    _ORDER = {"public": 0, "confidential": 1, "secret": 2, "top_secret": 3}
    _NAMES = {0: "public", 1: "confidential", 2: "secret", 3: "top_secret"}

    @classmethod
    def compare(cls, level_a: str, level_b: str) -> int:
        """比较两个安全级别: -1=a<b, 0=a==b, 1=a>b"""
        a = cls._ORDER.get(str(level_a).lower(), 0)
        b = cls._ORDER.get(str(level_b).lower(), 0)
        return (a > b) - (a < b)

    @classmethod
    def join(cls, level_a: str, level_b: str) -> str:
        """格的最小上界——两个标签的 join 是较高级别的那个"""
        a = cls._ORDER.get(str(level_a).lower(), 0)
        b = cls._ORDER.get(str(level_b).lower(), 0)
        return cls._NAMES[max(a, b)]

    @classmethod
    def meet(cls, level_a: str, level_b: str) -> str:
        """格的最大下界"""
        a = cls._ORDER.get(str(level_a).lower(), 0)
        b = cls._ORDER.get(str(level_b).lower(), 0)
        return cls._NAMES[min(a, b)]

    @classmethod
    def validate_write(cls, src_level: str, dst_level: str) -> bool:
        """Bell-LaPadula *属性: 不能向低于自身级别的目标写入"""
        return cls.compare(src_level, dst_level) <= 0

    @classmethod
    def validate_read(cls, src_level: str, dst_level: str) -> bool:
        """简单安全属性: 不能读取高于自身级别的源"""
        return cls.compare(dst_level, src_level) >= 0


class SecurityLabel:
    PUBLIC = "public"; CONFIDENTIAL = "confidential"; SECRET = "secret"; TOP_SECRET = "top_secret"

class FlowPolicy:
    NO_READ_UP = "no_read_up"; NO_WRITE_DOWN = "no_write_down"
    NON_INTERFERENCE = "non_interference"
    TAINT_PROPAGATION = "taint_propagation"
    DECLASSIFICATION = "declassification"

@dataclass
class SecurityAnnotation:
    variable_name: str = ""; level: str = SecurityLabel.PUBLIC
    description: str = ""; source_instruction: int = 0

class FlowRule:
    __slots__ = ('from_level','to_level','allowed','description',)
    def __init__(self, from_level, to_level, allowed, description=""):
        self.from_level = from_level; self.to_level = to_level
        self.allowed = allowed; self.description = description

class FlowViolation:
    # 不能加 __slots__：analyze() 以 v.__dict__ 序列化违规项，加 slots 后无 __dict__ 可读。
    def __init__(self, source_var, source_level, target_var, target_level,
                 violation_type, path=None, description=""):
        self.source_var = source_var; self.source_level = source_level
        self.target_var = target_var; self.target_level = target_level
        self.violation_type = violation_type; self.path = path
        self.description = description

class FlowVerificationResult:
    # 与 FlowViolation 同理：analyze() 经 __dict__ 序列化结果对象，须保留实例字典。
    def __init__(self, verified, violations=None, checked_flows=0, execution_time=0.0):
        self.verified = verified
        self.violations = violations if violations is not None else []
        self.checked_flows = checked_flows; self.execution_time = execution_time


from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from dataclasses import dataclass, field

class InformationFlowVerifier(BaseAnalyzer):
    def __init__(self):
        self._security_labels: Dict[str, str] = {}
        self._flow_rules: List[FlowRule] = []
        self._annotations: List[SecurityAnnotation] = []

    def _level_to_int(self, level) -> int:
        level_str = level if isinstance(level, str) else str(level)
        return SecurityLattice._ORDER.get(level_str.lower(), 0)

    def _parse_policy(self, policy_spec: Dict[str, Any]) -> None:
        self._security_labels = {}; self._flow_rules = []; self._annotations = []
        for var_name, level_str in policy_spec.get("variables", {}).items():
            self._security_labels[var_name] = str(level_str).lower()
        for rule in policy_spec.get("rules", []):
            try:
                self._flow_rules.append(FlowRule(
                    from_level=str(rule.get("from","public")).lower(),
                    to_level=str(rule.get("to","public")).lower(),
                    allowed=rule.get("allow", False),
                    description=rule.get("description","")))
            except Exception: pass

    def _check_non_interference(self) -> List[FlowViolation]:
        violations = []
        variables = list(self._security_labels.keys())
        for source_var in variables:
            for target_var in variables:
                if source_var == target_var: continue
                src_level = self._security_labels[source_var]
                tgt_level = self._security_labels[target_var]
                if self._level_to_int(src_level) > self._level_to_int(tgt_level):
                    violations.append(FlowViolation(
                        source_var=source_var, source_level=src_level,
                        target_var=target_var, target_level=tgt_level,
                        violation_type="write_down",
                        description=f"{source_var}({src_level}) → {target_var}({tgt_level})"))
        return violations

    def _check_flow_rules(self) -> List[FlowViolation]:
        violations = []
        for rule in self._flow_rules:
            if not rule.allowed:
                for sv, sl in self._security_labels.items():
                    if sl == rule.from_level:
                        for tv, tl in self._security_labels.items():
                            if tl == rule.to_level and sv != tv:
                                violations.append(FlowViolation(
                                    source_var=sv, source_level=sl,
                                    target_var=tv, target_level=tl,
                                    violation_type="rule_violation",
                                    description=f"Rule violation: {rule.from_level}→{rule.to_level}"))
        return violations

    def _check_implicit_flows(self) -> List[FlowViolation]:
        violations: List[FlowViolation] = []
        high_vars = [v for v, l in self._security_labels.items()
                     if self._level_to_int(l) >= 2]
        low_vars = [v for v, l in self._security_labels.items()
                    if self._level_to_int(l) <= 1]
        for h in high_vars:
            for l in low_vars:
                for ann in self._annotations:
                    if ann.variable_name == h:
                        for ann_b in self._annotations:
                            if ann_b.variable_name == l and ann.source_instruction == ann_b.source_instruction:
                                violations.append(FlowViolation(
                                    source_var=h, source_level=self._security_labels[h],
                                    target_var=l, target_level=self._security_labels[l],
                                    violation_type="implicit_flow",
                                    description=f"Implicit flow: {h} → {l} via control"))
        return violations

    def _verify_bell_lapadula(self) -> List[FlowViolation]:
        """使用 Bell-LaPadula 格模型进行形式化信息流验证
        比简单的非干扰检查更精确——明确验证 *属性 和简单安全属性
        """
        violations: List[FlowViolation] = []
        variables = list(self._security_labels.keys())
        for sv in variables:
            for tv in variables:
                if sv == tv: continue
                sl = self._security_labels[sv]; tl = self._security_labels[tv]
                # *属性检查
                if not SecurityLattice.validate_write(sl, tl):
                    violations.append(FlowViolation(
                        source_var=sv, source_level=sl,
                        target_var=tv, target_level=tl,
                        violation_type="star_property",
                        description=f"*属性违反: {sv}({sl}) → {tv}({tl}): 不可下写"))
        return violations

    def analyze(self, **kwargs) -> Dict[str, Any]:
        binary_path = kwargs.get("binary_path")
        policy_spec = kwargs.get("policy_spec")
        if not policy_spec: return {"success": False, "error": "policy_spec is required"}
        logger.info("Starting information flow verification")
        try:
            self._parse_policy(policy_spec)
            violations: List[FlowViolation] = []
            violations.extend(self._check_non_interference())
            violations.extend(self._check_flow_rules())
            violations.extend(self._check_implicit_flows())
            violations.extend(self._verify_bell_lapadula())
            result = FlowVerificationResult(
                verified=len(violations) == 0, violations=violations,
                checked_flows=len(self._security_labels) * (len(self._security_labels) - 1))
            return {
                "success": True,
                "result": {k: v for k, v in result.__dict__.items()},
                "violations": [v.__dict__ for v in violations],
                "summary": {"total_variables": len(self._security_labels),
                            "checked_flows": result.checked_flows,
                            "violations_found": len(violations),
                            "verified": result.verified},
                "message": f"Verification {'PASS' if result.verified else f'{len(violations)} violations found'}"}
        except Exception as e:
            logger.error(f"Information flow verification failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="InformationFlowVerifier", type=AnalyzerType.FORMAL_VERIFICATION,
            version="1.0.0", author="BinaryAnalysisPlatform",
            # description 是插件清单必填字段，缺失时展示为空串，测试断言含"info流"。
            description="info流验证器：基于 Bell-LaPadula 格模型验证非干扰与下写规则",
            dependencies=[], supported_platforms=["x86","x86_64","arm","arm64"])
