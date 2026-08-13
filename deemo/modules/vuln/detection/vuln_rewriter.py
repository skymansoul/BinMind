# 漏洞驱动代码重写引擎——从漏洞描述符生成安全函数变体。
# 策略链：IR构造→约束求解→模板合成→编译验证。
# CGC(Cyber Grand Challenge)的CRS/CRS-NG自动补丁生成范式。

import logging, os, re, time, hashlib, tempfile, subprocess
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path

try: import z3
except ImportError: z3 = None

try: from loguru import logger
except ImportError: logger = logging.getLogger(__name__)

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from enum import Enum
from dataclasses import dataclass, field


class VulnerabilityType(Enum):
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
    CONSTRAINT_SOLVING = "constraint_solving"
    PATTERN_MATCHING = "pattern_matching"
    TEMPLATE_BASED = "template_based"
    SYNTHESIS = "synthesis"


@dataclass
class FunctionSummary:
    name: str
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    semantics: str = ""


@dataclass
class VulnerabilityInfo:
    vuln_type: str = ""
    location: str = ""
    description: str = ""
    severity: str = ""
    fix_suggestion: str = ""


@dataclass
class RewriteResult:
    original_code: str
    rewritten_code: str
    strategy: RewriteStrategy
    success: bool
    verified: bool
    performance_impact: float
    notes: List[str] = field(default_factory=list)


class IRNode:
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
    def __init__(self):
        self.variables: Set[str] = set()
        self.functions: Dict[str, FunctionSummary] = {}

    def build_from_code(self, code: str) -> IRNode:
        root = IRNode("Program")
        lines = code.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if re.match(r'^\w+\s+\w+\s*\(', line):
                func_node = self._parse_function(line)
                root.add_child(func_node)
            elif re.match(r'^\w+\s+\w+\s*=', line):
                var_node = self._parse_variable(line)
                root.add_child(var_node)
            else:
                stmt_node = IRNode("Statement", line)
                root.add_child(stmt_node)
        return root

    def _parse_function(self, line: str) -> IRNode:
        match = re.match(r'(\w+)\s+(\w+)\s*\(([^)]*)\)', line)
        if match:
            return_type, name, params = match.groups()
            func_node = IRNode("Function", name)
            func_node.add_child(IRNode("ReturnType", return_type))
            for param in params.split(','):
                param = param.strip()
                if param:
                    func_node.add_child(IRNode("Parameter", param))
            return func_node
        return IRNode("UnknownFunction", line)

    def _parse_variable(self, line: str) -> IRNode:
        match = re.match(r'(\w+)\s+(\w+)\s*=\s*(.+)', line)
        if match:
            type_, name, value = match.groups()
            var_node = IRNode("Variable", name)
            var_node.add_child(IRNode("Type", type_))
            var_node.add_child(IRNode("Value", value))
            self.variables.add(name)
            return var_node
        return IRNode("UnknownVariable", line)

    def generate_summary(self, func_name: str, ir: IRNode) -> FunctionSummary:
        inputs, outputs, side_effects, constraints = [], [], [], []
        for child in ir.children:
            if child.node_type == "Parameter":
                inputs.append(child.value)
            elif child.node_type == "ReturnType":
                outputs.append(child.value)
        return FunctionSummary(name=func_name, inputs=inputs, outputs=outputs,
                              side_effects=side_effects, constraints=constraints,
                              semantics=ir.to_string())


class ConstraintSolver:
    def __init__(self):
        self.constraints: List[Any] = []

    def add_constraint(self, constraint: str):
        self.constraints.append(constraint)

    def solve(self) -> Optional[Dict[str, Any]]:
        if z3 is None:
            logger.warning("z3未安装——约束求解不可用")
            return None
        try:
            solver = z3.Solver()
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
    def __init__(self):
        self.templates: Dict[VulnerabilityType, List[str]] = self._load_templates()

    def _load_templates(self) -> Dict[VulnerabilityType, List[str]]:
        return {
            VulnerabilityType.BUFFER_OVERFLOW: [
                "// 安全变体：边界检查拷贝\nvoid safe_copy(char *dst, const char *src, size_t dst_size) {\n    size_t src_len = strlen(src);\n    if (src_len >= dst_size) {\n        src_len = dst_size - 1;\n    }\n    memcpy(dst, src, src_len);\n    dst[src_len] = '\\0';\n}",
                "// 安全变体：长度限定的strncpy\nvoid safe_strcpy(char *dst, const char *src, size_t size) {\n    strncpy(dst, src, size - 1);\n    dst[size - 1] = '\\0';\n}",
            ],
            VulnerabilityType.INTEGER_OVERFLOW: [
                "// 安全变体：溢出检查加法\nint safe_add(int a, int b) {\n    if (a > 0 && b > INT_MAX - a) return -1;\n    if (a < 0 && b < INT_MIN - a) return -1;\n    return a + b;\n}",
            ],
            VulnerabilityType.NULL_POINTER: [
                "// 安全变体：空指针防护释放\nvoid safe_free(void *ptr) {\n    if (ptr != NULL) {\n        free(ptr);\n    }\n}",
            ],
            VulnerabilityType.FORMAT_STRING: [
                "// 安全变体：固定格式字符串\nvoid safe_printf(const char *msg) {\n    printf(\"%s\", msg);\n}",
            ],
        }

    def synthesize(self, vuln_type: VulnerabilityType, original_code: str,
                    summary: FunctionSummary) -> Optional[str]:
        templates = self.templates.get(vuln_type, [])
        if not templates:
            logger.warning(f"漏洞类型无可用修复模板: {vuln_type.value}")
            return None
        return self._customize_template(templates[0], summary)

    def _customize_template(self, template: str, summary: FunctionSummary) -> str:
        return template


class VulnerabilityRewriter(BaseAnalyzer):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.strategy = RewriteStrategy(self.config.get('strategy', 'template_based'))
        self.ir_builder = IRBuilder()
        self.constraint_solver = ConstraintSolver()
        self.code_synthesizer = CodeSynthesizer()
        self.sandbox_enabled = self.config.get('sandbox', True)
        self._results: List[RewriteResult] = []

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="vulnerability_rewriter", type=AnalyzerType.OTHER,
            version="1.0.0", description="自动化漏洞驱动的函数重写模块",
            author="Binary Analysis Team", dependencies=["z3"],
            supported_platforms=["linux", "windows", "macos"])

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        if 'code' not in kwargs:
            return False, "缺少必要参数: code"
        if 'vuln_type' not in kwargs:
            return False, "缺少必要参数: vuln_type"
        code = kwargs.get('code')
        if not isinstance(code, str) or len(code) == 0:
            return False, "code必须为非空字符串"
        return True, None

    def analyze(self, **kwargs) -> Dict[str, Any]:
        valid, error = self.validate_input(**kwargs)
        if not valid:
            return {"success": False, "error": error}
        code = kwargs.get('code')
        vuln_type_str = kwargs.get('vuln_type')
        verify = kwargs.get('verify', True)
        try:
            vuln_type = VulnerabilityType(vuln_type_str.lower())
        except ValueError:
            vuln_type = VulnerabilityType.OTHER
        logger.info(f"漏洞重写分析开始，类型: {vuln_type.value}")
        ir = self.ir_builder.build_from_code(code)
        logger.debug(f"IR构造完成: {ir.to_string()}")
        func_name = self._extract_function_name(code)
        summary = self.ir_builder.generate_summary(func_name, ir)
        if self.strategy == RewriteStrategy.CONSTRAINT_SOLVING:
            rewritten = self._rewrite_constraint_solving(code, summary, vuln_type)
        elif self.strategy == RewriteStrategy.TEMPLATE_BASED:
            rewritten = self.code_synthesizer.synthesize(vuln_type, code, summary)
        else:
            rewritten = self._rewrite_pattern_matching(code, vuln_type)
        if rewritten is None:
            return {"success": False, "error": "安全代码合成失败", "original_code": code}
        verified = False
        if verify and self.sandbox_enabled:
            verified = self._verify_rewrite(code, rewritten, vuln_type)
        performance_impact = self._estimate_performance_impact(code, rewritten)
        result = RewriteResult(
            original_code=code, rewritten_code=rewritten, strategy=self.strategy,
            success=True, verified=verified, performance_impact=performance_impact,
            notes=self._generate_notes(verified, performance_impact))
        self._results.append(result)
        return {
            "success": True, "original_code": code, "rewritten_code": rewritten,
            "strategy": self.strategy.value, "verified": verified,
            "performance_impact": performance_impact, "notes": result.notes,
            "ir": ir.to_string(),
            "summary": {"name": summary.name, "inputs": summary.inputs,
                       "outputs": summary.outputs}}

    def _extract_function_name(self, code: str) -> str:
        match = re.search(r'\w+\s+(\w+)\s*\(', code)
        return match.group(1) if match else "unknown_function"

    def _rewrite_constraint_solving(self, code: str, summary: FunctionSummary,
                                      vuln_type: VulnerabilityType) -> Optional[str]:
        self.constraint_solver.add_constraint("no_buffer_overflow")
        self.constraint_solver.add_constraint("preserve_functionality")
        solution = self.constraint_solver.solve()
        if solution:
            return self._generate_code_from_solution(solution, summary)
        return None

    def _generate_code_from_solution(self, solution: Dict[str, Any],
                                       summary: FunctionSummary) -> str:
        return f"// 自动生成的安全变体\n// 解: {solution}"

    def _rewrite_pattern_matching(self, code: str,
                                    vuln_type: VulnerabilityType) -> Optional[str]:
        patterns = {
            VulnerabilityType.BUFFER_OVERFLOW: [
                (r'memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
                 'memcpy(dst, src, MIN(len, dst_size))'),
                (r'strcpy\s*\([^,]+,\s*[^)]+\)', 'strncpy(dst, src, dst_size)'),
            ],
            VulnerabilityType.FORMAT_STRING: [
                (r'printf\s*\([^)]+\)', 'printf("%s", arg)'),
            ],
        }
        vuln_patterns = patterns.get(vuln_type, [])
        rewritten = code
        for pattern, replacement in vuln_patterns:
            rewritten = re.sub(pattern, replacement, rewritten)
        return rewritten if rewritten != code else None

    def _verify_rewrite(self, original: str, rewritten: str,
                          vuln_type: VulnerabilityType) -> bool:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(rewritten)
                temp_path = f.name
            result = subprocess.run(
                ['gcc', '-c', temp_path, '-o', temp_path + '.o'],
                capture_output=True, timeout=30)
            os.unlink(temp_path)
            if os.path.exists(temp_path + '.o'):
                os.unlink(temp_path + '.o')
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"编译验证失败: {e}")
            return False

    def _estimate_performance_impact(self, original: str, rewritten: str) -> float:
        original_len = len(original)
        rewritten_len = len(rewritten)
        if original_len == 0:
            return 0.0
        return max(0.0, min(50.0, (rewritten_len - original_len) / original_len * 10))

    def _generate_notes(self, verified: bool, performance_impact: float) -> List[str]:
        notes = []
        if verified:
            notes.append("重写代码已通过编译验证")
        else:
            notes.append("重写代码验证失败——需人工审查")
        if performance_impact > 5.0:
            notes.append(f"估计性能开销较高: {performance_impact:.1f}%")
        elif performance_impact > 1.0:
            notes.append(f"估计性能开销轻微: {performance_impact:.1f}%")
        else:
            notes.append("估计性能开销可忽略")
        notes.append("部署前在隔离环境中测试重写代码")
        return notes

    def cleanup(self) -> None:
        self._results.clear()


class VulnerabilityRewriterTask:
    def __init__(self, task_id: str, code: str, vuln_type: str):
        self.task_id = task_id
        self.code = code
        self.vuln_type = vuln_type
        self.analyzer = VulnerabilityRewriter()

    def execute(self) -> Dict[str, Any]:
        return self.analyzer.analyze(code=self.code, vuln_type=self.vuln_type)


def rewrite_vulnerable_function(code: str, vuln_type: str,
                                  config: Optional[Dict[str, Any]] = None
                                  ) -> Dict[str, Any]:
    analyzer = VulnerabilityRewriter(config)
    return analyzer.analyze(code=code, vuln_type=vuln_type)


VulnType = VulnerabilityType
PatchStrategy = RewriteStrategy
VulnRewriter = VulnerabilityRewriter
VulnPattern = VulnerabilityInfo
PatchCandidate = RewriteResult
PatternDatabase = IRBuilder
