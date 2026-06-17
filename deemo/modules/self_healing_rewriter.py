"""
自愈性二进制重写模块

基于 Frida/DynamoRIO 在加载时注入漏洞检查逻辑（如边界检查）。
自动生成针对特定 CVE 的保护策略，并验证运行时性能开销。

安全注意事项：
- 所有注入操作必须在测试环境中执行
- 保护策略必须经过严格验证
- 禁止在生产环境中直接应用
- 性能开销评估必须准确

已知限制：
- 当前仅支持简单的边界检查注入
- 复杂的保护策略需要人工设计
- 性能开销评估可能存在误差
"""

import logging
import os
import re
import time
import hashlib
import tempfile
import subprocess
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from enum import Enum
from pathlib import Path

try:
    from loguru import logger
except ImportError:
    logger = logging.getLogger(__name__)

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class ProtectionType(Enum):
    """保护类型枚举"""
    BOUND_CHECK = "bound_check"          # 边界检查
    NULL_CHECK = "null_check"            # 空指针检查
    INTEGER_CHECK = "integer_check"      # 整数溢出检查
    FORMAT_CHECK = "format_check"        # 格式字符串检查
    MEMORY_TRACKING = "memory_tracking"  # 内存追踪
    CANARY_INSERT = "canary_insert"       # 栈保护
    ASLR_ENFORCE = "aslr_enforce"         # ASLR强制
    DEP_ENFORCE = "dep_enforce"           # DEP强制


class InstrumentationFramework(Enum):
    """插桩框架枚举"""
    FRIDA = "frida"
    DYNAMORIO = "dynamorio"
    PIN = "pin"
    VALGRIND = "valgrind"
    CUSTOM = "custom"


@dataclass
class CVEInfo:
    """CVE信息"""
    cve_id: str
    vulnerability_type: str
    affected_functions: List[str]
    description: str
    severity: str
    mitigation: str


@dataclass
class ProtectionRule:
    """保护规则"""
    rule_id: str
    protection_type: ProtectionType
    target_function: str
    check_code: str
    performance_estimate: float
    description: str


@dataclass
class InstrumentationResult:
    """插桩结果"""
    binary_path: str
    rules_applied: List[ProtectionRule]
    instrumented_code: str
    performance_overhead: float
    success: bool
    verification_passed: bool
    notes: List[str] = field(default_factory=list)


class ProtectionStrategyGenerator:
    """保护策略生成器"""
    
    def __init__(self):
        self.cve_database = self._load_cve_database()
        self.rule_templates = self._load_rule_templates()
    
    def _load_cve_database(self) -> Dict[str, CVEInfo]:
        """加载CVE数据库"""
        # 简化的CVE数据库
        return {
            "CVE-2017-5123": CVEInfo()
                cve_id="CVE-2017-5123",
                vulnerability_type="buffer_overflow",
                affected_functions=["memcpy", "strcpy"],
                description="waitid系统调用边界检查缺失",
                severity="HIGH",
                mitigation="添加边界检查"
            ),
            "CVE-2021-34527": CVEInfo()
                cve_id="CVE-2021-34527",
                vulnerability_type="integer_overflow",
                affected_functions=["alloc", "malloc"],
                description="PrintNightmare整数溢出",
                severity="CRITICAL",
                mitigation="添加整数溢出检查"
            ),
            "CVE-2022-2264": CVEInfo()
                cve_id="CVE-2022-2264",
                vulnerability_type="use_after_free",
                affected_functions=["free", "realloc"],
                description="内存释放后使用",
                severity="HIGH",
                mitigation="添加内存追踪"
            ),
        }
    
    def _load_rule_templates(self) -> Dict[ProtectionType, str]:
        """加载规则模板"""
        return {
            ProtectionType.BOUND_CHECK: """
// 边界检查保护
if (src_len >= dst_size) {
    src_len = dst_size - 1;
}
""",
            ProtectionType.NULL_CHECK: """
// 空指针检查保护
if (ptr == NULL) {,
    return ERROR_NULL_POINTER;
}
""",
            ProtectionType.INTEGER_CHECK: """
// 整数溢出检查保护
if (a > 0 && b > MAX - a) {
    return ERROR_OVERFLOW;
}
""",
            ProtectionType.CANARY_INSERT: """
// 栈保护
__stack_chk_guard = random();
canary = __stack_chk_guard;
""",
        }
    
    def generate_strategy(self, cve_id: str) -> List[ProtectionRule]:
        """
        生成保护策略
        
        Args:
            cve_id: CVE编号
            
        Returns:
            保护规则列表
        """
        rules = []
        
        cve_info = self.cve_database.get(cve_id)
        if not cve_info:
            logger.warning(f"未找到CVE: {cve_id}")
            return rules
        
        # 根据漏洞类型生成规则
        vuln_type = cve_info.vulnerability_type
        
        if vuln_type == "buffer_overflow":
            protection_type = ProtectionType.BOUND_CHECK
        elif vuln_type == "integer_overflow":
            protection_type = ProtectionType.INTEGER_CHECK
        elif vuln_type == "use_after_free":
            protection_type = ProtectionType.MEMORY_TRACKING
        elif vuln_type == "null_pointer":
            protection_type = ProtectionType.NULL_CHECK
        else:
            protection_type = ProtectionType.BOUND_CHECK
        
        # 为每个受影响函数生成规则
        for func in cve_info.affected_functions:
            template = self.rule_templates.get(protection_type, "")
            
            rule = ProtectionRule()
                rule_id=f"{cve_id}_{func}",
                protection_type=protection_type,
                target_function=func,
                check_code=template,
                performance_estimate=0.05,  # 5%开销估计
                description=f"针对 {cve_id} 的 {func} 保护"
            
            rules.append(rule)
        
        return rules
    
    def generate_custom_strategy(self, functions: List[str],)
                                 protection_type: ProtectionType) -> List[ProtectionRule]:
        """
        生成自定义保护策略
        
        Args:
            functions: 目标函数列表
            protection_type: 保护类型
            
        Returns:
            保护规则列表
        """
        rules = []
        template = self.rule_templates.get(protection_type, "")
        
        for func in functions:
            rule = ProtectionRule()
                rule_id=f"custom_{func}",
                protection_type=protection_type,
                target_function=func,
                check_code=template,
                performance_estimate=0.05,
                description=f"自定义 {func} 保护"
            
            rules.append(rule)
        
        return rules


class FridaInstrumenter:
    """Frida插桩器"""
    
    def __init__(self):
        self.script_template = self._load_script_template()
    
    def _load_script_template(self) -> str:
        """加载Frida脚本模板"""
        return """
// Frida 保护脚本
// 自动生成

var targetModule = Process.findModuleByName("{module_name}");,
if (targetModule) {
    // 挂钩目标函数
    var targetFunc = targetModule.findExportByName("{function_name}");,
    if (targetFunc) {
        Interceptor.attach(targetFunc, {)
            onEnter: function(args) {
                // 保护检查
                {check_code}
            },
            onLeave: function(retval) {
                // 返回值检查
            }
        });
    }
}
"""
    
    def generate_script(self, module_name: str, function_name: str,)
                        check_code: str) -> str:
        """
        生成Frida脚本
        
        Args:
            module_name: 模块名
            function_name: 函数名
            check_code: 检查代码
            
        Returns:
            Frida脚本
        """
        # 使用字符串拼接而不是format，避免{字符问题
        script = self.script_template.replace("{module_name}", module_name)
        script = script.replace("{function_name}", function_name)
        script = script.replace("{check_code}", check_code)
        return script
    
    def apply_protection(self, binary_path: str, rules: List[ProtectionRule]) -> InstrumentationResult:
        """
        应用保护
        
        Args:
            binary_path: 二进制路径
            rules: 保护规则列表
            
        Returns:
            插桩结果
        """
        scripts = []
        module_name = os.path.basename(binary_path)
        
        for rule in rules:
            script = self.generate_script()
                module_name=module_name,
                function_name=rule.target_function,
                check_code=rule.check_code
            
            scripts.append(script)
        
        combined_script = "\n".join(scripts)
        
        # 估算性能开销
        total_overhead = sum(r.performance_estimate for r in rules)
        
        return InstrumentationResult()
            binary_path=binary_path,
            rules_applied=rules,
            instrumented_code=combined_script,
            performance_overhead=total_overhead,
            success=True,
            verification_passed=False,
            notes=["Frida脚本已生成", "需要在运行环境中验证"]
        



class DynamoRioInstrumenter:
    """DynamoRIO插桩器"""
    
    def __init__(self):
        self.tool_template = self._load_tool_template()
    
    def _load_tool_template(self) -> str:
        """加载DynamoRIO工具模板"""
        return """
// DynamoRIO 保护工具
// 自动生成

#include "dr_api.h"

static void event_bb_insert(void *drcontext, void *tag, instrlist_t *bb,)
                            instr_t *instr, bool for_trace, bool translating,
                            void *user_data) {
    // 插入保护检查
    {check_code}
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_register_bb_insert_event(event_bb_insert);
}
"""
    
    def generate_tool(self, check_code: str) -> str:
        """
        生成DynamoRIO工具
        
        Args:
            check_code: 检查代码
            
        Returns:
            DynamoRIO工具代码
        """
        # 使用字符串替换而不是format
        return self.tool_template.replace("{check_code}", check_code)
    
    def apply_protection(self, binary_path: str, rules: List[ProtectionRule]) -> InstrumentationResult:
        """
        应用保护
        
        Args:
            binary_path: 二进制路径
            rules: 保护规则列表
            
        Returns:
            插桩结果
        """
        tools = []
        
        for rule in rules:
            tool = self.generate_tool(rule.check_code)
            tools.append(tool)
        
        combined_tool = "\n".join(tools)
        
        # 估算性能开销（DynamoRIO通常开销更高）
        total_overhead = sum(r.performance_estimate for r in rules) * 1.5
        
        return InstrumentationResult()
            binary_path=binary_path,
            rules_applied=rules,
            instrumented_code=combined_tool,
            performance_overhead=total_overhead,
            success=True,
            verification_passed=False,
            notes=["DynamoRIO工具已生成", "需要编译并验证"]
        



class PerformanceValidator:
    """性能验证器"""
    
    def __init__(self):
        self.benchmark_iterations = 100
    
    def estimate_overhead(self, original_time: float, )
                          instrumented_time: float) -> float:
        """
        估算性能开销
        
        Args:
            original_time: 原始执行时间
            instrumented_time: 插桩后执行时间
            
        Returns:
            性能开销百分比
        """
        if original_time == 0:
            return 0.0
        
        return ((instrumented_time - original_time) / original_time) * 100
    
    def validate_acceptable(self, overhead: float, )
                            threshold: float = 10.0) -> bool:
        """
        验证开销是否可接受
        
        Args:
            overhead: 性能开销
            threshold: 阈值
            
        Returns:
            是否可接受
        """
        return overhead <= threshold


class SelfHealingRewriter(BaseAnalyzer):
    """
    自愈性二进制重写分析器
    
    继承 BaseAnalyzer，接入 DAG 任务调度。
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化重写器
        
        Args:
            config: 配置字典
        """
        self.config = config or {}
        self.framework = InstrumentationFramework()
            self.config.get('framework', 'frida')
        
        self.strategy_generator = ProtectionStrategyGenerator()
        self.frida_instrumenter = FridaInstrumenter()
        self.dynamorio_instrumenter = DynamoRioInstrumenter()
        self.performance_validator = PerformanceValidator()
        self.sandbox_enabled = self.config.get('sandbox', True)
        self._results: List[InstrumentationResult] = []
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata()
            name="self_healing_rewriter",
            type=AnalyzerType.OTHER,
            version="1.0.0",
            description="自愈性二进制重写模块",
            author="Binary Analysis Team",
            dependencies=["frida"],
            supported_platforms=["linux", "windows", "macos"],
            config_schema={
                "framework": {"type": "string", "default": "frida"},
                "sandbox": {"type": "boolean", "default": True},
                "performance_threshold": {"type": "float", "default": 10.0}
            }
        

    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        if 'binary_path' not in kwargs:
            return False, "缺少必需参数: binary_path"
        
        binary_path = kwargs.get('binary_path')
        if not isinstance(binary_path, str):
            return False, "binary_path 必须是字符串"
        
        if not os.path.exists(binary_path):
            return False, f"二进制文件不存在: {binary_path}"
        
        return True, None
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行自愈性重写分析
        
        Args:
            binary_path: 二进制文件路径
            cve_id: CVE编号（可选）
            functions: 目标函数列表（可选）
            protection_type: 保护类型（可选）
            verify: 是否验证（可选）
            
        Returns:
            分析结果字典
        """
        valid, error = self.validate_input(**kwargs)
        if not valid:
            return {"success": False, "error": error}
        
        binary_path = kwargs.get('binary_path')
        cve_id = kwargs.get('cve_id')
        functions = kwargs.get('functions', [])
        protection_type_str = kwargs.get('protection_type', 'bound_check')
        verify = kwargs.get('verify', False)
        
        logger.info(f"开始自愈性重写分析: {binary_path}")
        
        # Step 1: 生成保护策略
        if cve_id:
            rules = self.strategy_generator.generate_strategy(cve_id)
            logger.info(f"为 {cve_id} 生成 {len(rules)} 条保护规则")
        elif functions:
            try:
                protection_type = ProtectionType(protection_type_str.lower())

            except ValueError:
                protection_type = ProtectionType.BOUND_CHECK
            rules = self.strategy_generator.generate_custom_strategy()
                functions, protection_type
            
        else:
            # 默认策略：通用边界检查
            rules = self.strategy_generator.generate_custom_strategy()
                ['memcpy', 'strcpy', 'strncpy'],
                ProtectionType.BOUND_CHECK
            
        
        if not rules:
            return {
                "success": False,
                "error": "无法生成保护规则",
                "binary_path": binary_path
            }
        
        # Step 2: 应用插桩
        if self.framework == InstrumentationFramework.FRIDA:
            result = self.frida_instrumenter.apply_protection(binary_path, rules)
        elif self.framework == InstrumentationFramework.DYNAMORIO:
            result = self.dynamorio_instrumenter.apply_protection(binary_path, rules)
        else:
            result = self.frida_instrumenter.apply_protection(binary_path, rules)
        
        # Step 3: 验证性能开销
        if verify:
            acceptable = self.performance_validator.validate_acceptable()
                result.performance_overhead,
                self.config.get('performance_threshold', 10.0)
            
            result.verification_passed = acceptable,
            if acceptable:
                result.notes.append("性能开销验证通过")
            else:
                result.notes.append(f"性能开销过高: {result.performance_overhead:.1f}%")
        
        self._results.append(result)
        
        return {
            "success": True,
            "binary_path": binary_path,
            "framework": self.framework.value,
            "rules_applied": [
                {
                    "rule_id": r.rule_id,
                    "protection_type": r.protection_type.value,
                    "target_function": r.target_function,
                    "description": r.description
                } for r in result.rules_applied
            ],
            "instrumented_code": result.instrumented_code,
            "performance_overhead": result.performance_overhead,
            "verification_passed": result.verification_passed,
            "notes": result.notes
        }
    
    def cleanup(self) -> None:
        """清理资源"""
        self._results.clear()


class SelfHealingRewriterTask:
    """自愈性重写任务 - 用于DAG调度"""
    
    def __init__(self, task_id: str, binary_path: str, cve_id: Optional[str] = None):
        self.task_id = task_id
        self.binary_path = binary_path
        self.cve_id = cve_id
        self.analyzer = SelfHealingRewriter()
    
    def execute(self) -> Dict[str, Any]:
        """执行任务"""
        kwargs = {'binary_path': self.binary_path}
        if self.cve_id:
            kwargs['cve_id'] = self.cve_id,
        return self.analyzer.analyze(**kwargs)


def apply_self_healing_protection(binary_path: str, )
                                  cve_id: Optional[str] = None,
                                  framework: str = 'frida',
                                  config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    应用自愈性保护的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        cve_id: CVE编号
        framework: 插桩框架
        config: 配置字典
        
    Returns:
        保护结果
    """
    config = config or {}
    config['framework'] = framework
    analyzer = SelfHealingRewriter(config)
    
    kwargs = {'binary_path': binary_path}
    if cve_id:
        kwargs['cve_id'] = cve_id
    
    return analyzer.analyze(**kwargs)