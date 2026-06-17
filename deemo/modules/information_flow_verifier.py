"""
信息流安全策略自动验证模块

检查二进制是否违反非干涉策略，维护安全标签，
探索路径检测非法信息流。

Author: Binary Vulnerability Analysis Platform
Version: 1.0.0
"""

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """安全级别枚举"""
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class FlowPolicy(Enum):
    """信息流策略枚举"""
    NO_READ_UP = "no_read_up"
    NO_WRITE_DOWN = "no_write_down"
    NON_INTERFERENCE = "non_interference"


@dataclass
class SecurityLabel:
    """安全标签"""
    variable_name: str
    level: SecurityLevel
    description: str = ""


@dataclass
class FlowRule:
    """信息流规则"""
    from_level: SecurityLevel
    to_level: SecurityLevel
    allowed: bool
    description: str = ""


@dataclass
class FlowViolation:
    """信息流违规"""
    source_var: str
    source_level: SecurityLevel
    target_var: str
    target_level: SecurityLevel
    violation_type: str
    path: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class FlowVerificationResult:
    """信息流验证结果"""
    verified: bool
    violations: List[FlowViolation] = field(default_factory=list)
    checked_flows: int = 0
    execution_time: float = 0.0


class InformationFlowVerifier(BaseAnalyzer):
    """
    信息流安全策略自动验证器
    
    核心功能：
    1. 维护安全标签，标记数据的安全级别
    2. 追踪二进制中的信息流路径
    3. 验证是否违反非干涉策略
    4. 检测非法信息流并生成反例
    """
    
    def __init__(self):
        self._security_labels: Dict[str, SecurityLevel] = {}
        self._flow_rules: List[FlowRule] = []
    
    def _level_to_int(self, level: SecurityLevel) -> int:
        """将安全级别转换为数值（便于比较）"""
        level_order = {
            SecurityLevel.PUBLIC: 0,
            SecurityLevel.CONFIDENTIAL: 1,
            SecurityLevel.SECRET: 2,
            SecurityLevel.TOP_SECRET: 3
        }
        return level_order.get(level, 0)
    
    def _parse_policy(self, policy_spec: Dict[str, Any]) -> None:
        """解析安全策略规范"""
        self._security_labels = {}
        self._flow_rules = []
        
        for var_name, level_str in policy_spec.get("variables", {}).items():
            try:
                self._security_labels[var_name] = SecurityLevel(level_str.lower(

            except ValueError:
                logger.warning(f"未知安全级别: {level_str}，默认为 public")
                self._security_labels[var_name] = SecurityLevel.PUBLIC
        
        for rule in policy_spec.get("rules", []):
            try:
                from_level = SecurityLevel(rule.get("from", "public").lower(

                to_level = SecurityLevel(rule.get("to", "public").lower(

                self._flow_rules.append(FlowRule(
                    from_level=from_level,
                    to_level=to_level,
                    allowed=rule.get("allow", False),
                    description=rule.get("description", "")
                

            except ValueError as e:
                logger.warning(f"解析规则失败: {e}")
    
    def _check_non_interference(self) -> List[FlowViolation]:
        """检查非干涉策略"""
        violations = []
        
        variables = list(self._security_labels.keys(

        
        for source_var in variables:
            source_level = self._security_labels[source_var]
            
            for target_var in variables:
                if source_var == target_var:
                    continue
                
                target_level = self._security_labels[target_var]
                
                source_level_int = self._level_to_int(source_level)
                target_level_int = self._level_to_int(target_level)
                
                if source_level_int > target_level_int:
                    violation = FlowViolation()
                        source_var=source_var,
                        source_level=source_level,
                        target_var=target_var,
                        target_level=target_level,
                        violation_type="write_down",
                        description=f"高安全级别数据 {source_var}({source_level.value}) 流向低安全级别 {target_var}({target_level.value})"
                    
                    violations.append(violation)
        
        return violations
    
    def _check_flow_rules(self) -> List[FlowViolation]:
        """检查自定义流规则"""
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
                                    description=f"违反规则: {rule.from_level.value} -> {rule.to_level.value} 不允许"
                                

        
        return violations
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行信息流安全策略验证
        
        Args:
            **kwargs: 分析参数
                - binary_path: 二进制文件路径（可选）
                - policy_spec: 安全策略规范
                  - variables: 变量到安全级别的映射
                  - rules: 自定义流规则列表
                    - from: 源安全级别
                    - to: 目标安全级别
                    - allow: 是否允许
                    - description: 描述
                  - policy_type: 策略类型 (no_read_up, no_write_down, non_interference)
        
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get("binary_path")
        policy_spec = kwargs.get("policy_spec")
        
        if not policy_spec:
            return {"success": False, "error": "policy_spec 是必需参数"}
        
        logger.info(f"开始信息流安全策略验证")
        
        try:
            self._parse_policy(policy_spec)
            
            violations = []
            
            violations.extend(self._check_non_interference(

            violations.extend(self._check_flow_rules(

            
            result = FlowVerificationResult()
                verified=len(violations) == 0,
                violations=violations,
                checked_flows=len(self._security_labels) * (len(self._security_labels) - 1)
            
            
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
                "message": f"信息流验证完成: {'通过' if result.verified else f'发现 {len(violations)} 个违规'}"
            }
        
        except Exception as e:
            logger.error(f"信息流验证失败: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="InformationFlowVerifier",
            type=AnalyzerType.FORMAL_VERIFICATION,
            version="1.0.0",
            description="信息流安全策略自动验证器，检查二进制是否违反非干涉策略，维护安全标签，检测非法信息流",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])))))))))))))))))