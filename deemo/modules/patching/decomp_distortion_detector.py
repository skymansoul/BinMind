"""反编译失真检测 — FidelityGPT [arXiv:2510.19615] 启发的模式匹配引擎。

FidelityGPT 定义六类反编译失真并通过 RAG 修复。本模块将其模式匹配
部分工程化为独立检测器，不依赖外部调用即可识别 Ghidra/IDA/Hex-Rays
输出中的常见伪影。

六类失真 (FidelityGPT §3):
  D1: 类型信息丢失 (undefined4/byte/dword 等占位类型)
  D2: 控制流退化 (goto 泛滥、循环结构缺失)
  D3: 函数内联展开 (call 被替换为内联体)
  D4: 常量/字符串混淆 (magic number 未恢复)
  D5: 变量命名丢失 (v1/v2/var_* 等自动命名)
  D6: 复合操作拆分 (单条高级语句被拆为多条低级操作)
"""

import re, logging, os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import IntEnum
from functools import lru_cache

_llog = logging.getLogger(__name__)


class DistortionKind:
    """FidelityGPT 六类失真标签。"""
    TYPE_LOSS = "type_loss"                    # D1
    CFG_DEGRADATION = "cfg_degradation"        # D2
    INLINE_EXPANSION = "inline_expansion"      # D3
    CONSTANT_OBFUSCATION = "constant_obfuscation"  # D4
    NAMING_LOSS = "naming_loss"                # D5
    COMPOSITE_SPLIT = "composite_split"        # D6


@dataclass
class DistortionInstance:
    """单条失真实例 — 位置、片段、置信度。"""
    kind: str
    line_number: int
    snippet: str
    confidence: float
    suggestion: str = ""


@dataclass
class DistortionReport:
    """失真分析报告 — 汇总六类统计与整体质量评分。"""
    source: str = ""  # 反编译器输出来源
    total_functions: int = 0
    distorted_functions: int = 0
    total_instances: int = 0
    by_kind: Dict[str, int] = field(default_factory=dict)
    instances: List[DistortionInstance] = field(default_factory=list)
    fixable_count: int = 0  # 可自动修复的实例数
    overall_quality_score: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'source': os.path.basename(self.source) if self.source else '',
            'total_functions': self.total_functions,
            'distorted_functions': self.distorted_functions,
            'total_instances': self.total_instances,
            'by_kind': self.by_kind,
            'fixable_count': self.fixable_count,
            'overall_quality_score': round(self.overall_quality_score, 4),
            'top_instances': [
                {'kind': _i.kind, 'line': _i.line_number, 'confidence': _i.confidence}
                for _i in self.instances[:20]
            ],
        }


# ── D1: 类型信息丢失 ────────────────────────────────────────────
# 反编译器无法推断类型时填充的占位符模式

_D1_PATTERNS = [
    # Ghidra/IDA 常见伪类型
    (r'\bundefined4\b', 'undefined4 → uint32_t', 0.90),
    (r'\bundefined8\b', 'undefined8 → uint64_t', 0.90),
    (r'\bundefined\b(?![\d_])', 'undefined → uint8_t', 0.90),
    (r'\bundefined2\b', 'undefined2 → uint16_t', 0.85),
    (r'\bundefined\d+\b', 'undefinedN → uintN_t', 0.80),
    (r'\b_DAT_[0-9a-fA-F]+\b', 'data reference not resolved', 0.75),
    (r'\bPTR_[0-9a-fA-F]+\b', 'pointer not resolved', 0.70),
    (r'\bCONCAT\d+\b', 'register concatenation unresolved', 0.70),
    (r'\bZEXT\d*\b', 'zero-extension not normalized', 0.65),
    (r'\bSEXT\d*\b', 'sign-extension not normalized', 0.65),
    (r'\bSUB\d+\b', 'subtraction result unresolved', 0.60),
    # IDA 特有
    (r'\b__byte\b', '__byte → uint8_t', 0.85),
    (r'\b__word\b', '__word → uint16_t', 0.85),
    (r'\b__dword\b', '__dword → uint32_t', 0.85),
    (r'\b__qword\b', '__qword → uint64_t', 0.85),
]

# ── D2: 控制流退化 ───────────────────────────────────────────

_D2_PATTERNS = [
    (r'\bgoto\b', 'goto usage', 0.40),  # 单 goto 权重低
    (r'\bgoto\b.*\n.*\bgoto\b', 'multiple gotos — CFG degradation', 0.70),
    (r'\bLAB_\d+\b', 'IDA label — unresolved branch target', 0.65),
    (r'\bloc_[0-9a-fA-F]+\b', 'Ghidra label — unresolved target', 0.60),
    (r'\bcase\s+\d+:\s*\n\s*case\s+\d+:', 'adjacent case fallthrough — missing break?', 0.55),
    (r'// WARNING:.*switch', 'decompiler switch resolution failure', 0.80),
    (r'// WARNING:.*unreachable', 'unreachable code — CFG error', 0.85),
]

# ── D3: 函数内联展开 ─────────────────────────────────────────────
# 特征：函数体内嵌大量寄存器操作和直接内存访问

_D3_PATTERNS = [
    (r'^\s*(v\d+|var_\w+)\s*=\s*\*\((\w+\s*\*)?\s*\)\(0x[0-9a-fA-F]+\)',
     'direct memory dereference — likely inlined', 0.50),
    (r'0x[0-9a-fA-F]+\s*\|\s*0x[0-9a-fA-F]+',
     'magic constant OR — inline bit manipulation', 0.45),
    # 内联 asm 标记
    (r'__asm\s*\{', 'inline asm block', 0.60),
    (r'__emit\s*\(', 'inline byte emission', 0.70),
]

# ── D4: 常量/字符串混淆 ──────────────────────────────────────────

_D4_PATTERNS = [
    (r'0x[0-9a-fA-F]{8,16}', 'large magic constant — unresolved', 0.30),
    (r'0x[0-9a-fA-F]{2}\s*,\s*0x[0-9a-fA-F]{2}.*,\s*0x[0-9a-fA-F]{2}',
     'byte array — possibly a string literal', 0.55),
    (r'(?:\d+\s*<<\s*\d+)|(?:\d+\s*\|\s*\d+)',
     'shift/or of constants — composite constant not folded', 0.50),
]

# ── D5: 变量命名丢失 ─────────────────────────────────────────────────

_D5_PATTERNS = [
    (r'\bv\d+\b', 'auto-generated var name (vN)', 0.75),
    (r'\bvar_[0-9a-fA-F]+\b', 'stack variable not renamed', 0.70),
    (r'\barg_\d+\b', 'function argument not renamed', 0.65),
    (r'\blocal_\w{2,4}\b', 'auto-generated local name', 0.55),
    (r'\buVar\d+\b', 'Ghidra undefined variable', 0.80),
    (r'\biVar\d+\b', 'Ghidra integer variable', 0.75),
    (r'\bpuVar\d+\b', 'Ghidra pointer variable', 0.80),
]

# ── D6: 复合操作拆分 ─────────────────────────────────────────────────

_D6_PATTERNS = [
    (r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;\s*\n\s*\2\s*=\s*\1',
     'two-step accumulation — should be single compound', 0.50),
    (r'\*\w+\s*=\s*\*\w+\s*&\s*0x[fF]+',
     'mask then store — bitfield access decomposed', 0.55),
]


class DistortionDetector:
    """FidelityGPT 风格反编译失真检测器。

    对反编译器输出逐行扫描，匹配六类失真模式，生成结构化报告。
    兼容 Ghidra、IDA Pro Hex-Rays 和 radare2 输出格式。
    仅依赖模式匹配与启发式规则，不调用外部服务。
    """

    def __init__(self):
        self._all_patterns = {
            DistortionKind.TYPE_LOSS: _D1_PATTERNS,
            DistortionKind.CFG_DEGRADATION: _D2_PATTERNS,
            DistortionKind.INLINE_EXPANSION: _D3_PATTERNS,
            DistortionKind.CONSTANT_OBFUSCATION: _D4_PATTERNS,
            DistortionKind.NAMING_LOSS: _D5_PATTERNS,
            DistortionKind.COMPOSITE_SPLIT: _D6_PATTERNS,
        }

    # ============================================================
    # 主分析入口
    # ============================================================
    def analyze(self, decompiled_code: str,
                source_path: str = "") -> DistortionReport:
        """分析反编译输出，返回完整失真报告。"""
        _rpt = DistortionReport(source=source_path)
        if not decompiled_code:
            return _rpt

        _lines = decompiled_code.split('\n')
        _rpt.total_functions = self._count_functions(decompiled_code)

        # 逐类扫描
        for _kind, _patterns in self._all_patterns.items():
            _rpt.by_kind.setdefault(_kind, 0)
            _idx = 0
            _n = len(_lines)
            while _idx < _n:
                _line = _lines[_idx]
                for _pat, _desc, _conf in _patterns:
                    try:
                        if re.search(_pat, _line):
                            _i = DistortionInstance(
                                kind=_kind,
                                line_number=_idx + 1,
                                snippet=_line.strip()[:120],
                                confidence=_conf,
                                suggestion=_desc if '→' in str(_desc) else "")
                            _rpt.instances.append(_i)
                            _rpt.by_kind[_kind] += 1
                            break  # 每行至多归入一类
                    except re.error:
                        continue
                _idx += 1

        _rpt.total_instances = sum(_rpt.by_kind.values())

        # 受影响函数计数 — 基于实例行号估算函数边界
        _func_lines = set()
        for _i in _rpt.instances:
            # 定位该行所属函数入口
            _func_lines.add(self._find_function_boundary(_lines, _i.line_number - 1))
        _rpt.distorted_functions = len(_func_lines)

        # 可自动修复实例计数
        _rpt.fixable_count = sum(
            1 for _i in _rpt.instances
            if _i.kind == DistortionKind.TYPE_LOSS and _i.confidence >= 0.85)

        # 整体质量评分 (0..1)
        _rpt.overall_quality_score = self._compute_quality(_rpt, _lines)

        return _rpt

    # ── 自动修复：D1 类型替换 ────────────────────────────────────────
    # 对可安全替换的类型失真执行替换

    def auto_fix(self, decompiled_code: str) -> Tuple[str, int]:
        """D1 类型自动替换，返回 (修复后代码, 替换次数)。
        仅处理确定安全的映射（undefinedN → uintN_t）。"""
        _fixed = decompiled_code
        _count = 0

        _replacements = [
            # (模式, 替换值, 需词边界)
            (r'\bundefined8\b', 'uint64_t', True),
            (r'\bundefined4\b', 'uint32_t', True),
            (r'\bundefined2\b', 'uint16_t', True),
            (r'\bundefined\b(?![\d_])', 'uint8_t', True),
            (r'\b__byte\b', 'uint8_t', True),
            (r'\b__word\b', 'uint16_t', True),
            (r'\b__dword\b', 'uint32_t', True),
            (r'\b__qword\b', 'uint64_t', True),
            (r'\b__int64\b', 'int64_t', True),
            (r'\b__int32\b', 'int32_t', True),
            (r'\b__int16\b', 'int16_t', True),
            (r'\b__int8\b', 'int8_t', True),
            (r'\bbyte\b(?!\s*=)', 'uint8_t', True),  # 仅替换类型声明，不碰赋值
        ]

        for _pat, _repl, _wb in _replacements:
            _new, _n = re.subn(_pat, _repl, _fixed)
            if _n > 0:
                _fixed = _new
                _count += _n

        return _fixed, _count

    # ── 辅助 ──────────────────────────────────────────────────────

    def _count_functions(self, code: str) -> int:
        """通过函数声明模式估算函数数量。"""
        _cnt = 0
        for _line in code.split('\n'):
            _stripped = _line.strip()
            # 匹配常见函数签名
            if re.match(
                r'^(?:static\s+|extern\s+|inline\s+|__\w+\s+)*'
                r'(?:void|int|char|long|short|float|double|bool|'
                r'uint\d+_t|int\d+_t|size_t|ssize_t|'
                r'u?int\d+|DWORD|WORD|BYTE|BOOL|'
                r'\w+)\s+\w+\s*\([^)]*\)\s*\{?',
                _stripped):
                _cnt += 1
        return max(_cnt, 1)

    def _find_function_boundary(self, lines: List[str], line_idx: int) -> int:
        """从给定行向上查找最近的函数入口行号。"""
        _i = line_idx
        while _i >= 0:
            _stripped = lines[_i].strip()
            if _stripped.endswith('{') and not _stripped.startswith('if') and not _stripped.startswith('for') and not _stripped.startswith('while'):
                return _i
            _i -= 1
        return 0

    def _compute_quality(self, report: DistortionReport,
                        lines: List[str]) -> float:
        """FidelityGPT 风格质量分：基准 1.0，按失真密度扣分。
        高置信度失真和控制流退化惩罚权重更大。"""
        if not lines:
            return 1.0
        _density = report.total_instances / max(len(lines), 1)
        _q = 1.0
        # 高置信度失真惩罚
        _high_conf = sum(1 for _i in report.instances if _i.confidence > 0.8)
        _q -= _density * 0.5
        _q -= (_high_conf / max(len(lines), 1)) * 0.3
        # 控制流退化最严重
        _cfg_count = report.by_kind.get(DistortionKind.CFG_DEGRADATION, 0)
        _q -= (_cfg_count / max(len(lines), 1)) * 0.2
        return round(min(max(_q, 0.0), 1.0), 4)


# ── 便捷入口 ──────────────────────────────────────────────────────────

def detect_distortions(decompiled_code: str,
                       source_path: str = "") -> Dict:
    _detector = DistortionDetector()
    _rpt = _detector.analyze(decompiled_code, source_path)
    return {'success': True, 'result': _rpt.to_dict()}


def auto_fix_distortions(decompiled_code: str) -> Tuple[str, Dict]:
    """应用自动修复并返回修复后代码与统计摘要。"""
    _detector = DistortionDetector()
    _rpt = _detector.analyze(decompiled_code)
    _fixed, _n = _detector.auto_fix(decompiled_code)
    _info = {
        'original_distortions': _rpt.total_instances,
        'fixes_applied': _n,
        'remaining_distortions': 0,  # 修复后重新分析填充
    }
    # 修复后重新扫描
    _rpt2 = _detector.analyze(_fixed)
    _info['remaining_distortions'] = _rpt2.total_instances
    return _fixed, _info
