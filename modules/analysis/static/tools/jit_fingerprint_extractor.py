# 四引擎 JIT 指纹库: V8 TurboFan / JVM C2 / .NET RyuJIT / LuaJIT
# 去优化检查点密度: 每引擎有独特的 deopt checkpoint 模式
# JIT 优化指纹提取: 识别 JIT 编译器及其优化遍, 通过模式匹配+密度计算推断引擎

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# JIT 引擎指令模式指纹库

# 每模式: (正则表达式, 模式名, 权重)
_JIT_FINGERPRINTS: Dict[str, List[Tuple[str, str, float]]] = {
    # V8 TurboFan (x86_64)
    'V8_TurboFan': [
        # Deopt checkpoint: compare DeoptimizeIf + deopt index load
        (r'(?:cmp|cmpb)\s+\[r13\+0x[0-9a-f]+\]', 'deopt_compare', 0.25),
        (r'call\s+0x[0-9a-f]+\s+<Deoptimization', 'deopt_call', 0.30),
        # Code stub: Embedded builtin calls
        (r'mov\s+rax,\s*0x[0-9a-f]{8,16}\s*;\s*call\s+rax', 'embedded_builtin', 0.20),
        # Feedback vector access
        (r'mov(?:zx)?\s+\w+,\s*\[r\w+\+0x[0-9a-f]+\]\s*;\s*test.*\n.*j(?:ne|e)', 'feedback_vector', 0.15),
        # Jump table for switch
        (r'jmp\s+\[r\w+\*8\+0x[0-9a-f]+\]', 'jump_table', 0.10),
    ],
    # JVM HotSpot C2 (x86_64)
    'JVM_C2': [
        # Safepoint poll: test [rip+offset], eax
        (r'test\s+\[rip[+-]0x[0-9a-f]+\],\s*eax', 'safepoint_poll', 0.30),
        # Method entry: load klass from header
        (r'mov\s+\w+,\s*\[r\w+\+0x08\]\s*;\s*cmp\s+\w+,\s*0x[0-9a-f]+', 'klass_check', 0.20),
        # Inline cache: compare method pointer
        (r'mov\s+r10,\s*0x[0-9a-f]{8,16}\s*;\s*cmp\s+r10,\s*\[r\w+\]', 'inline_cache', 0.20),
        # Uncommon trap
        (r'int3\s*;\s*nop\s*;\s*nop', 'uncommon_trap', 0.15),
        # Array bounds check: cmp index, length
        (r'mov\s+\w+,\s*\[r\w+\+0x0[cC]\]\s*;\s*cmp\s+\w+,\s*\w+\s*;\s*j(?:ae|be|b|a)', 'bounds_check', 0.15),
    ],
    # .NET RyuJIT (x86_64)
    'NET_RyuJIT': [
        # GC info / safe point: mov [rsp+...], method table ptr
        (r'mov\s+\[rsp\+0x[0-9a-f]+\],\s*0x[0-9a-f]{8,16}', 'gc_info', 0.25),
        # Method table comparison for cast
        (r'cmp\s+\[r\w+\],\s*0x[0-9a-f]{8,16}', 'method_table_cmp', 0.20),
        # Array length access: [reg + 8] for length
        (r'mov\s+\w+,\s*\[r\w+\+0x08\]\s*;\s*cmp\s+\w+,\s*\w+\s*;\s*j(?:ae|b)', 'array_length', 0.20),
        # Interface dispatch: mov reg, [reg + method_table + slot]
        (r'mov\s+r\w+,\s*\[r\w+\+0x[0-9a-f]+\]\s*;\s*call\s+\[r\w+\+0x[0-9a-f]+\]', 'interface_dispatch', 0.18),
        # Write barrier for generational GC
        (r'mov\s+\[r\w+\+0x[0-9a-f]+\],\s*\w+\s*;\s*cmp\s+\[r\w+\],\s*\w+', 'write_barrier', 0.17),
    ],
    # LuaJIT (x86_64)
    'LuaJIT': [
        # Trace dispatch: jmp to trace number
        (r'jmp\s+0x[0-9a-f]+\s+->\d+', 'trace_dispatch', 0.30),
        # Type guard: cmp type tag, expected
        (r'cmp\s+(?:byte|dword)\s+\[r\w+\+?\d*\],\s*0x[0-9a-f]+', 'type_guard', 0.25),
        # NaN tagging check
        (r'(?:and|test)\s+\w+,\s*0x[0-9a-f]{8,16}\s*;\s*j(?:ne|e)', 'nan_tag_check', 0.20),
        # Sink exit to interpreter
        (r'mov\s+\w+,\s*0x[0-9a-f]+\s*;\s*jmp\s+\w+', 'trace_exit', 0.15),
        # IR constant in instruction
        (r'mov\s+\w+,\s*0xFFF[0-9A-F]{4}', 'ir_constant', 0.10),
    ],
}


@dataclass
class JITFingerprintResult:
    """JIT 指纹匹配结果"""
    engine: str                # V8_TurboFan | JVM_C2 | NET_RyuJIT | LuaJIT | unknown
    confidence: float          # [0,1]
    # 子模式匹配详情
    pattern_matches: Dict[str, int] = field(default_factory=dict)
    # 模式密度 (每千条指令的模式匹配数)
    pattern_density: float = 0.0
    # 检测到的优化特征
    detected_features: List[str] = field(default_factory=list)


class JITFingerprintExtractor:
    """JIT 编译器指纹提取器"""

    def __init__(self):
        self._total_insns = 0

    def extract(
        self,
        asm_lines: List[str],
        arch: str = 'x86_64',
    ) -> JITFingerprintResult:
        """从反汇编行提取 JIT 指纹

        asm_lines: 反汇编文本行列表 (每行一条指令)
        arch: 目标架构 (目前仅支持 x86_64)

        返回 JITFingerprintResult
        """
        self._total_insns = len(asm_lines)
        text_full = '\n'.join(asm_lines)

        # 对每引擎计算模式匹配得分
        engine_scores: Dict[str, float] = {}
        all_matches: Dict[str, Dict[str, int]] = {}

        for engine, patterns in _JIT_FINGERPRINTS.items():
            score = 0.0
            matches: Dict[str, int] = {}

            for pattern_re, pattern_name, weight in patterns:
                count = len(re.findall(pattern_re, text_full, re.I | re.M))
                if count > 0:
                    matches[pattern_name] = count
                    # 加权得分: 权重 x log2(1+匹配数) - 对数衰减防止过匹配
                    score += weight * (1.0 + __import__('math').log2(1 + count))

            engine_scores[engine] = score
            all_matches[engine] = matches

        # 归一化得分 + 选择最佳引擎
        total_score = sum(engine_scores.values())
        if total_score < 1e-9:
            return JITFingerprintResult(engine='unknown', confidence=0.0)

        best_engine = max(engine_scores, key=engine_scores.get)
        best_score = engine_scores[best_engine]

        # 置信度: 最佳得分 / 总分 (若最佳占绝对优势->高置信度)
        confidence = best_score / max(0.01, total_score)
        # 调整: 第二名的得分越接近->置信度越低
        sorted_scores = sorted(engine_scores.values(), reverse=True)
        if len(sorted_scores) >= 2 and sorted_scores[0] > 0:
            runner_up_ratio = sorted_scores[1] / sorted_scores[0]
            confidence *= (1.0 - 0.5 * runner_up_ratio)

        matches = all_matches.get(best_engine, {})
        density = sum(matches.values()) / max(1, self._total_insns / 1000)

        # 检测到的特征 (匹配数>=2 的模式)
        features = [
            f'{name}({count})'
            for name, count in sorted(matches.items(), key=lambda x: -x[1])
            if count >= 2
        ]

        return JITFingerprintResult(
            engine=best_engine,
            confidence=round(min(1.0, confidence), 4),
            pattern_matches=matches,
            pattern_density=round(density, 4),
            detected_features=features,
        )
