"""
补丁类型自适应路由

三级判定（CWE → 漏洞类型名 → 代码关键词），先归类到修复族，
再按修复族决定生成路径：
  - SYMBOLIC：符号约束合成（算术/边界守卫），对应 SynthFix 符号路径；
  - TEMPLATE：安全函数替换/free 后置空/格式化字面量，
    对应 SynthFix 安全改写路径；
  - HYBRID：双路并出，排序器裁决。

区别于 patch_suggestion 的单一策略：本路由器按漏洞语义分叉，
逻辑缺陷/资源管理/注入类分开处理，在生成阶段缩小搜索空间。

边界条件：
  - 判定优先级：CWE > 类型名 > 代码关键词；全缺失则 UNKNOWN；
  - 类型名兼容 auto_patcher（buffer_overflow）、auto_root_cause
    （STACK_BUFFER_OVERFLOW）、patch_suggestion（stack_overflow）三类命名；
  - 代码关键词为启发式降级，置信度 0.5。
"""
import re
import logging
from dataclasses import dataclass
from enum import Enum

_log = logging.getLogger(__name__)


class RepairFamily(str, Enum):
    """修复族 —— 漏洞语义高层归类。"""
    LOGIC_DEFECT = "logic_defect"                # 逻辑缺陷（整数溢出/空指针）
    RESOURCE_MANAGEMENT = "resource_management"  # 资源管理（泄漏/双释放）
    INJECTION = "injection"                      # 注入类（格式化串/命令注入）
    MEMORY_SAFETY = "memory_safety"              # 内存安全（越界/UAF）
    CONCURRENCY = "concurrency"                  # 并发（竞态/死锁）
    INPUT_VALIDATION = "input_validation"        # 输入验证
    UNKNOWN = "unknown"


class RepairRoute(str, Enum):
    """生成路径 —— 决定候选补丁由哪条管线产出。"""
    SYMBOLIC = "symbolic"   # 符号约束合成：依数据流操作数生成守卫
    TEMPLATE = "template"   # 安全改写：已知危险模式直接替换
    HYBRID = "hybrid"       # 双路并行，排序器择取


@dataclass
class RouteDecision:
    """路由决策 —— 单次修复请求的路径与依据。"""
    family: RepairFamily = RepairFamily.UNKNOWN
    route: RepairRoute = RepairRoute.TEMPLATE
    confidence: float = 0.0
    guard_hint: str = ""
    rationale: str = ""

    def to_dict(self):
        return {
            'family': self.family.value,
            'route': self.route.value,
            'confidence': round(self.confidence, 3),
            'guard_hint': self.guard_hint,
            'rationale': self.rationale,
        }


# 漏洞类型名 → 修复族（覆盖三类既有命名规范，下划线已归一）
_VULN_TYPE_FAMILY = {
    # 内存安全
    'buffer_overflow': RepairFamily.MEMORY_SAFETY,
    'stack_overflow': RepairFamily.MEMORY_SAFETY,
    'stack_buffer_overflow': RepairFamily.MEMORY_SAFETY,
    'heap_overflow': RepairFamily.MEMORY_SAFETY,
    'heap_buffer_overflow': RepairFamily.MEMORY_SAFETY,
    'heap_vulnerability': RepairFamily.MEMORY_SAFETY,
    'use_after_free': RepairFamily.MEMORY_SAFETY,
    'heap_use_after_free': RepairFamily.MEMORY_SAFETY,
    # 逻辑缺陷
    'integer_overflow': RepairFamily.LOGIC_DEFECT,
    'null_pointer': RepairFamily.LOGIC_DEFECT,
    'null_pointer_dereference': RepairFamily.LOGIC_DEFECT,
    'null_dereference': RepairFamily.LOGIC_DEFECT,
    # 注入类
    'format_string': RepairFamily.INJECTION,
    'injection': RepairFamily.INJECTION,
    # 资源管理
    'memory_leak': RepairFamily.RESOURCE_MANAGEMENT,
    'double_free': RepairFamily.RESOURCE_MANAGEMENT,
    # 并发
    'race_condition': RepairFamily.CONCURRENCY,
    'concurrency_issue': RepairFamily.CONCURRENCY,
    # 输入验证
    'input_validation': RepairFamily.INPUT_VALIDATION,
}

# CWE → 修复族（覆盖 cve_knowledge_base / auto_patch_spec 常见条目）
_CWE_FAMILY = {
    'CWE-120': RepairFamily.MEMORY_SAFETY,   # Buffer Copy without Checking Size
    'CWE-121': RepairFamily.MEMORY_SAFETY,   # Stack-based Buffer Overflow
    'CWE-122': RepairFamily.MEMORY_SAFETY,   # Heap-based Buffer Overflow
    'CWE-787': RepairFamily.MEMORY_SAFETY,   # Out-of-bounds Write
    'CWE-416': RepairFamily.MEMORY_SAFETY,   # Use After Free
    'CWE-415': RepairFamily.MEMORY_SAFETY,   # Double Free
    'CWE-476': RepairFamily.LOGIC_DEFECT,    # NULL Pointer Dereference
    'CWE-190': RepairFamily.LOGIC_DEFECT,    # Integer Overflow
    'CWE-191': RepairFamily.LOGIC_DEFECT,    # Integer Underflow
    'CWE-134': RepairFamily.INJECTION,       # Format String
    'CWE-78': RepairFamily.INJECTION,        # OS Command Injection
    'CWE-77': RepairFamily.INJECTION,        # Command Injection
    'CWE-89': RepairFamily.INJECTION,        # SQL Injection
    'CWE-79': RepairFamily.INJECTION,        # XSS
    'CWE-401': RepairFamily.RESOURCE_MANAGEMENT,  # Missing Release of Memory
    'CWE-362': RepairFamily.CONCURRENCY,     # Race Condition
    'CWE-20': RepairFamily.INPUT_VALIDATION, # Improper Input Validation
}

# 修复族 → 默认生成路径
_ROUTE_BY_FAMILY = {
    RepairFamily.LOGIC_DEFECT: RepairRoute.SYMBOLIC,
    RepairFamily.INPUT_VALIDATION: RepairRoute.SYMBOLIC,
    RepairFamily.MEMORY_SAFETY: RepairRoute.HYBRID,
    RepairFamily.INJECTION: RepairRoute.TEMPLATE,
    RepairFamily.RESOURCE_MANAGEMENT: RepairRoute.TEMPLATE,
    RepairFamily.CONCURRENCY: RepairRoute.TEMPLATE,
    RepairFamily.UNKNOWN: RepairRoute.TEMPLATE,
}

# 修复族 → 符号守卫提示（供生成器合成约束的语义锚点）
_GUARD_HINTS = {
    RepairFamily.LOGIC_DEFECT: "guard: 在算术/解引用前合成范围检查或 NULL 检查",
    RepairFamily.INPUT_VALIDATION: "guard: 使用前校验输入长度/格式边界",
    RepairFamily.MEMORY_SAFETY: "guard: 拷贝前校验长度不超过目标容量",
    RepairFamily.RESOURCE_MANAGEMENT: "guard: free 后立即置空指针, 校验 malloc 返回值",
    RepairFamily.INJECTION: "guard: 格式化串改为字面量, 用户输入仅作参数",
    RepairFamily.CONCURRENCY: "guard: 在共享访问路径加入同步原语",
    RepairFamily.UNKNOWN: "guard: 保守修复 — 最小改动并通过语法/静态验证",
}

# 代码关键词 → 修复族（vuln_type/cwe 缺失时的降级判定）
_CODE_KEYWORDS = [
    (RepairFamily.MEMORY_SAFETY, [r'\b(strcpy|strcat|memcpy|gets)\s*\(']),
    (RepairFamily.INJECTION, [r'printf\s*\(\s*\w+\s*\)']),
    (RepairFamily.RESOURCE_MANAGEMENT, [r'\bfree\s*\(', r'\bmalloc\s*\(']),
    (RepairFamily.LOGIC_DEFECT, [r'\b[a-zA-Z_]\w*\s*[+\-*/]\s*[a-zA-Z_]\w*']),
    (RepairFamily.CONCURRENCY, [r'\b(lock|unlock|mutex|pthread_mutex)\b']),
]


def _normalize_vuln_type(vuln_type):
    """归一化漏洞类型 —— 小写、连字符/空格转下划线，兼容三类既有命名。"""
    if not vuln_type:
        return ""
    return str(vuln_type).lower().strip().replace('-', '_').replace(' ', '_')


class VulnClassifier:
    """漏洞分类器 —— CWE > 类型名 > 代码关键词，逐级降级映射到修复族。"""

    def classify(self, vuln_type=None, cwe_id=None, code=None):
        """返回 (RepairFamily, source_tag)；source_tag 记录判定依据供审计。"""
        if cwe_id:
            cwe = str(cwe_id).upper().strip()
            fam = _CWE_FAMILY.get(cwe)
            if fam is not None:
                return fam, 'cwe:' + cwe
        vt = _normalize_vuln_type(vuln_type)
        if vt:
            fam = _VULN_TYPE_FAMILY.get(vt)
            if fam is not None:
                return fam, 'vuln_type:' + vt
        if code:
            for fam, patterns in _CODE_KEYWORDS:
                for pat in patterns:
                    if re.search(pat, code):
                        return fam, 'code_keyword:' + pat
        return RepairFamily.UNKNOWN, 'unknown'


class PatchTypeRouter:
    """自适应路由器 —— 按修复族选择符号/安全改写/混合路径。"""

    def __init__(self, classifier=None):
        self._classifier = classifier or VulnClassifier()

    def route(self, vuln_type=None, cwe_id=None, code=None):
        """对一次修复请求输出路径决策。

        置信度：CWE 精确命中 0.95，类型名命中 0.85，
        代码关键词命中 0.50 —— 反映依据确定性递减。
        """
        fam, source = self._classifier.classify(vuln_type, cwe_id, code)
        route = _ROUTE_BY_FAMILY.get(fam, RepairRoute.TEMPLATE)
        if source.startswith('cwe:'):
            confidence = 0.95
        elif source.startswith('vuln_type:'):
            confidence = 0.85
        elif source.startswith('code_keyword:'):
            confidence = 0.50
        else:
            confidence = 0.30
        return RouteDecision(
            family=fam,
            route=route,
            confidence=confidence,
            guard_hint=_GUARD_HINTS.get(fam, ""),
            rationale='classified via ' + source,
        )

    def classify(self, vuln_type=None, cwe_id=None, code=None):
        """便捷入口 —— 仅分类，不路由。"""
        return self._classifier.classify(vuln_type, cwe_id, code)
