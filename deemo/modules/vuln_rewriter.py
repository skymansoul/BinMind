"""
漏洞函数自动重写模块

输入：易受攻击函数的反编译代码和安全示例。
将代码提升至 IR，生成功能摘要，通过约束求解器搜索等价且无漏洞的新代码，
降低为机器码并插入二进制。
基于 Rosette 思路或自实现的程序合成管线。

安全注意事项：
- 所有生成的代码必须经过安全验证
- 重写操作必须在沙箱环境中执行
- 禁止直接修改生产环境二进制
- 输入验证必须严格

已知限制：
- 当前仅支持简单的缓冲区溢出修复
- 复杂的漏洞类型需要人工干预
- 性能开销评估可能不精确
"""

import logging
import os
import re
import time
import hashlib
import tempfile
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from enum import Enum
from pathlib import Path

try:
    import z3
except ImportError:
    z3 = None

try:
    from loguru import logger
except ImportError:
    logger = logging.getLogger(__name__)

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    NULL_POINTER = "null_pointer"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    OTHER = "other"


class RewriteStrategy(Enum):
    """重写策略枚举"""
    CONSTRAINT_SOLVING = "constraint_solving"  # 约束求解
    PATTERN_MATCHING = "pattern_matching"       # 模式匹配
    TEMPLATE_BASED = "template_based"           # 模板替换
    SYNTHESIS = "synthesis"                     # 程序合成


@dataclass
class FunctionSummary:
    """函数摘要"""
    name: str
    inputs: List[str]
    outputs: List[str]
    side_effects: List[str]
    constraints: List[str]
    semantics: str


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    vuln_type: VulnerabilityType
    location: Tuple[int, int]  # (start_line, end_line)
    description: str
    severity: str
    fix_suggestion: str


@dataclass
class RewriteResult:
    """重写结果"""
    original_code: str
    rewritten_code: str
    strategy: RewriteStrategy
    success: bool
    verified: bool
    performance_impact: float
    notes: List[str] = field(default_factory=list)


class IRNode:
    """IR节点基类"""
    
    def __init__(self, node_type: str, value: Any = None):
        self.node_type = node_type
        self.value = value
        self.children: List['IRNode'] = []
    
    def add_child(self, child: 'IRNode'):
        self.children.append(child)
    
    def to_string(self) -> str:
        if not self.children:
            return f"{self.node_type}({self.value})"
        children_str = ", ".join(c.to_string() for c in self.children)
        return f"{self.node_type}({children_str})"


class IRBuilder:
    """IR构建器"""
    
    def __init__(self):
        self.variables: Set[str] = set()
        self.functions: Dict[str, FunctionSummary] = {}
    
    def build_from_code(self, code: str) -> IRNode:
        """
        从代码构建IR
        
        Args:
            code: 源代码字符串
            
        Returns:
            IR根节点
        """
        root = IRNode("Program")
        
        # 简化的IR构建：解析基本结构
        lines = code.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 解析函数定义
            if re.match(r'^\w+\s+\w+\s*\(', line):
                func_node = self._parse_function(line)
                root.add_child(func_node)
            
            # 解析变量声明
            elif re.match(r'^\w+\s+\w+\s*=', line):
                var_node = self._parse_variable(line)
                root.add_child(var_node)
            
            # 解析语句
            else:
                stmt_node = IRNode("Statement", line)
                root.add_child(stmt_node)
        
        return root
    
    def _parse_function(self, line: str) -> IRNode:
        """解析函数定义"""
        match = re.match(r'(\w+)\s+(\w+)\s*\(([^)]*)\)', line
        if match:
            return_type, name, params = match.groups()
            func_node = IRNode("Function", name)
            func_node.add_child(IRNode("ReturnType", return_type

            
            for param in params.split(','):
                param = param.strip()
                if param:
                    func_node.add_child(IRNode("Parameter", param

            
            return func_node
        return IRNode("UnknownFunction", line)
    
    def _parse_variable(self, line: str) -> IRNode:
        """解析变量声明"""
        match = re.match(r'(\w+)\s+(\w+)\s*=\s*(.+)', line)
        if match:
            type_, name, value = match.groups()
            var_node = IRNode("Variable", name)
            var_node.add_child(IRNode("Type", type_

            var_node.add_child(IRNode("Value", value

            self.variables.add(name)
            return var_node
        return IRNode("UnknownVariable", line)
    
    def generate_summary(self, func_name: str, ir: IRNode) -> FunctionSummary:
        """
        生成函数摘要
        
        Args:
            func_name: 函数名
            ir: IR节点
            
        Returns:
            函数摘要
        """
        inputs = []
        outputs = []
        side_effects = []
        constraints = []
        
        # 从IR提取信息
        for child in ir.children:
            if child.node_type == "Parameter":
                inputs.append(child.value)
            elif child.node_type == "ReturnType":
                outputs.append(child.value)
        
        return FunctionSummary(
            name=func_name,
            inputs=inputs,
            outputs=outputs,
            side_effects=side_effects,
            constraints=constraints,
            semantics=ir.to_string())
        



class ConstraintSolver:
    """约束求解器"""
    
    def __init__(self):
        self.constraints: List[Any] = []
    
    def add_constraint(self, constraint: str):
        """添加约束条件"""
        self.constraints.append(constraint)
    
    def solve(self) -> Optional[Dict[str, Any]]:
        """
        求解约束
        
        Returns:
            解字典，或None
        """
        if z3 is None:
            logger.warning("z3 未安装，无法执行约束求解")
            return None
        
        try:
            solver = z3.Solver()
            
            # 简化的约束求解示例
            # 实际实现需要根据具体漏洞类型构建约束
            
            if solver.check() == z3.sat:
                model = solver.model()
                result = {}
                for decl in model.decls():
                    result[str(decl.name())] = str(model[decl])
                return result
            
            return None
        except Exception as e:
            logger.error(f"约束求解失败: {e}")
            return None


class CodeSynthesizer:
    """代码合成器"""
    
    def __init__(self):
        self.templates: Dict[VulnerabilityType, List[str]] = self._load_templates()
    
    def _load_templates(self) -> Dict[VulnerabilityType, List[str]]:
        """加载修复模板"""
        return {
            VulnerabilityType.BUFFER_OVERFLOW: [
                "// 安全版本：添加边界检查\nvoid safe_copy(char *dst, const char *src, size_t dst_size) {\n    size_t src_len = strlen(src);\n    if (src_len >= dst_size) {\n        src_len = dst_size - 1;\n    }\n    memcpy(dst, src, src_len);\n    dst[src_len] = '\\0';\n}",
                "// 安全版本：使用strncpy\nvoid safe_strcpy(char *dst, const char *src, size_t size) {\n    strncpy(dst, src, size - 1);\n    dst[size - 1] = '\\0';\n}",
            ],
            VulnerabilityType.INTEGER_OVERFLOW: [
                "// 安全版本：添加溢出检查\nint safe_add(int a, int b) {\n    if (a > 0 && b > INT_MAX - a) return -1;\n    if (a < 0 && b < INT_MIN - a) return -1;\n    return a + b;\n}",
            ],
            VulnerabilityType.NULL_POINTER: [
                "// 安全版本：添加空指针检查\nvoid safe_free(void *ptr) {\n    if (ptr != NULL) {\n        free(ptr);\n    }\n}",
            ],
            VulnerabilityType.FORMAT_STRING: [
                "// 安全版本：使用固定格式字符串\nvoid safe_printf(const char *msg) {\n    printf(\"%s\", msg);\n}",
            ],
        }
    
    def synthesize(self, vuln_type: VulnerabilityType, original_code: str, summary: FunctionSummary) -> Optional[str]:
        """
        合成安全代码
        
        Args:
            vuln_type: 漏洞类型
            original_code: 原始代码
            summary: 函数摘要
            
        Returns:
            合成的安全代码，或None
        """
        templates = self.templates.get(vuln_type, [])
        
        if not templates:
            logger.warning(f"没有找到 {vuln_type.value} 的修复模板")
            return None
        
        # 选择最合适的模板
        best_template = templates[0]
        
        # 根据函数摘要定制模板
        customized = self._customize_template(best_template, summary)
        
        return customized
    
    def _customize_template(self, template: str, summary: FunctionSummary) -> str:
        """定制模板"""
        # 简化的定制逻辑
        return template


class VulnerabilityRewriter(BaseAnalyzer):
    """
    漏洞函数自动重写分析器
    
    继承 BaseAnalyzer，接入 DAG 任务调度。
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化重写器
        
        Args:
            config: 配置字典
        """
        self.config = config or {}
        self.strategy = RewriteStrategy()
            self.config.get('strategy', 'template_based')
        
        self.ir_builder = IRBuilder()
        self.constraint_solver = ConstraintSolver()
        self.code_synthesizer = CodeSynthesizer()
        self.sandbox_enabled = self.config.get('sandbox', True)
        self._results: List[RewriteResult] = []
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="vulnerability_rewriter",
            type=AnalyzerType.OTHER,
            version="1.0.0",
            description="漏洞函数自动重写模块",
            author="Binary Analysis Team",
            dependencies=["z3"],
            supported_platforms=["linux", "windows", "macos"],
            config_schema={
                "strategy": {"type": "string", "default": "template_based"},
                "sandbox": {"type": "boolean", "default": True},
                "verify_rewrite": {"type": "boolean", "default": True}
            })
        

    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        if 'code' not in kwargs:
            return False, "缺少必需参数: code"
        
        if 'vuln_type' not in kwargs:
            return False, "缺少必需参数: vuln_type"
        
        code = kwargs.get('code')
        if not isinstance(code, str) or len(code) == 0:
            return False, "code 必须是非空字符串"
        
        return True, None
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行漏洞重写分析
        
        Args:
            code: 易受攻击的代码
            vuln_type: 漏洞类型
            safe_example: 安全示例代码（可选）
            verify: 是否验证重写结果（可选）
            
        Returns:
            分析结果字典
        """
        valid, error = self.validate_input(**kwargs)
        if not valid:
            return {"success": False, "error": error}
        
        code = kwargs.get('code')
        vuln_type_str = kwargs.get('vuln_type')
        safe_example = kwargs.get('safe_example')
        verify = kwargs.get('verify', True)
        
        try:
            vuln_type = VulnerabilityType(vuln_type_str.lower(

        except ValueError:
            vuln_type = VulnerabilityType.OTHER
        
        logger.info(f"开始漏洞重写分析，类型: {vuln_type.value}")
        
        # Step 1: 构建IR
        ir = self.ir_builder.build_from_code(code)
        logger.debug(f"构建IR: {ir.to_string()}")
        
        # Step 2: 生成函数摘要
        func_name = self._extract_function_name(code)
        summary = self.ir_builder.generate_summary(func_name, ir)
        logger.debug(f"函数摘要: {summary.name}, 输入: {summary.inputs}")
        
        # Step 3: 根据策略重写
        if self.strategy == RewriteStrategy.CONSTRAINT_SOLVING:
            rewritten = self._rewrite_constraint_solving(code, summary, vuln_type)
        elif self.strategy == RewriteStrategy.TEMPLATE_BASED:
            rewritten = self.code_synthesizer.synthesize(vuln_type, code, summary)
        else:
            rewritten = self._rewrite_pattern_matching(code, vuln_type)
        
        if rewritten is None:
            return {
                "success": False,
                "error": "无法生成安全代码",
                "original_code": code
            }
        
        # Step 4: 验证重写结果
        verified = False,
        if verify and self.sandbox_enabled:
            verified = self._verify_rewrite(code, rewritten, vuln_type)
        
        # Step 5: 评估性能影响
        performance_impact = self._estimate_performance_impact(code, rewritten)
        
        result = RewriteResult()
            original_code=code,
            rewritten_code=rewritten,
            strategy=self.strategy,
            success=True,
            verified=verified,
            performance_impact=performance_impact,
            notes=self._generate_notes(verified, performance_impact)
        
        
        self._results.append(result)
        
        return {
            "success": True,
            "original_code": code,
            "rewritten_code": rewritten,
            "strategy": self.strategy.value,
            "verified": verified,
            "performance_impact": performance_impact,
            "notes": result.notes,
            "ir": ir.to_string(),
            "summary": {
                "name": summary.name,
                "inputs": summary.inputs,
                "outputs": summary.outputs
            }
        }
    
    def _extract_function_name(self, code: str) -> str:
        """提取函数名"""
        match = re.search(r'\w+\s+(\w+)\s*\(', code
        if match:
            return match.group(1)
        return "unknown_function"
    
    def _rewrite_constraint_solving(self, code: str, summary: FunctionSummary, vuln_type: VulnerabilityType) -> Optional[str]:
        """使用约束求解重写"""
        # 添加安全约束
        self.constraint_solver.add_constraint("no_buffer_overflow")
        self.constraint_solver.add_constraint("preserve_functionality")
        
        solution = self.constraint_solver.solve()
        
        if solution:
            # 根据解生成代码
            return self._generate_code_from_solution(solution, summary)
        
        return None
    
    def _generate_code_from_solution(self, solution: Dict[str, Any], summary: FunctionSummary) -> str:
        """从解生成代码"""
        return f"// 自动生成的安全版本\n// 解: {solution}"
    
    def _rewrite_pattern_matching(self, code: str, vuln_type: VulnerabilityType) -> Optional[str]:
        """使用模式匹配重写"""
        patterns = {
            VulnerabilityType.BUFFER_OVERFLOW: [
                (r'memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
                 'memcpy(dst, src, MIN(len, dst_size))'),
                (r'strcpy\s*\([^,]+,\s*[^)]+\)',
                 'strncpy(dst, src, dst_size)'),
            ],
            VulnerabilityType.FORMAT_STRING: [
                (r'printf\s*\([^)]+\)',
                 'printf("%s", arg)'),
            ],
        }
        
        vuln_patterns = patterns.get(vuln_type, [])
        rewritten = code
        
        for pattern, replacement in vuln_patterns:
            rewritten = re.sub(pattern, replacement, rewritten)
        
        if rewritten != code:
            return rewritten
        
        return None
    
    def _verify_rewrite(self, original: str, rewritten: str, vuln_type: VulnerabilityType) -> bool:
        """
        验证重写结果
        
        Args:
            original: 原始代码
            rewritten: 重写代码
            vuln_type: 漏洞类型
            
        Returns:
            是否验证通过
        """
        # 在沙箱中编译和测试
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(rewritten)
                temp_path = f.name
            
            # 尝试编译
            result = subprocess.run()
                ['gcc', '-c', temp_path, '-o', temp_path + '.o'],
                capture_output=True,
                timeout=30
            
            
            os.unlink(temp_path)
            if os.path.exists(temp_path + '.o'):
                os.unlink(temp_path + '.o')
            
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"验证失败: {e}")
            return False
    
    def _estimate_performance_impact(self, original: str, rewritten: str) -> float:
        """估算性能影响"""
        # 简化的估算：基于代码长度变化
        original_len = len(original)
        rewritten_len = len(rewritten)
        
        if original_len == 0:
            return 0.0
        
        # 增加的检查逻辑通常会有轻微性能开销
        overhead_ratio = (rewritten_len - original_len) / original_len
        
        # 假设每增加10%代码，性能下降约1%
        return max(0.0, min(50.0, overhead_ratio * 10

    
    def _generate_notes(self, verified: bool, performance_impact: float) -> List[str]:
        """生成备注"""
        notes = []
        
        if verified:
            notes.append("重写代码已通过编译验证")
        else:
            notes.append("重写代码未通过验证，建议人工检查")
        
        if performance_impact > 5.0:
            notes.append(f"预计性能开销较高: {performance_impact:.1f}%")
        elif performance_impact > 1.0:
            notes.append(f"预计性能开销轻微: {performance_impact:.1f}%")
        else:
            notes.append("预计性能开销可忽略")
        
        notes.append("建议在隔离环境中测试重写后的代码")
        
        return notes
    
    def cleanup(self) -> None:
        """清理资源"""
        self._results.clear()


class VulnerabilityRewriterTask:
    """漏洞重写任务 - 用于DAG调度"""
    
    def __init__(self, task_id: str, code: str, vuln_type: str):
        self.task_id = task_id
        self.code = code
        self.vuln_type = vuln_type
        self.analyzer = VulnerabilityRewriter()
    
    def execute(self) -> Dict[str, Any]:
        """执行任务"""
        return self.analyzer.analyze(code=self.code, vuln_type=self.vuln_type)


def rewrite_vulnerable_function(code: str, vuln_type: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    重写漏洞函数的便捷函数
    
    Args:
        code: 易受攻击的代码
        vuln_type: 漏洞类型
        config: 配置字典
        
    Returns:
        重写结果
    """
    analyzer = VulnerabilityRewriter(config)
    return analyzer.analyze(code=code, vuln_type=vuln_type)


# 别名，保持与 __init__.py 导入名称一致
VulnType = VulnerabilityType
PatchStrategy = RewriteStrategy
VulnRewriter = VulnerabilityRewriter
VulnPattern = VulnerabilityInfo
PatchCandidate = RewriteResult
PatternDatabase = IRBuilder)))))