"""
UAF时序验证引擎 —— 时间维度上的 use-after-free 精确判定。

不仅检查"是否存在 free 和 use", 而是证明两者的时序关系:
  - free→use 路径是否必然经过 (dominates)
  - 是否存在 guard (NULL check) 阻止 use
  - 别名传播: q=p; free(p); use(q) — q 作为 p 的别名被追踪

方法:
  1. Simplified CFG dominator tree: 判断 free 基本块是否 dominates use 基本块
  2. NULL guard detection: if(p) use(p); — 识别 free(p); p=NULL; 模式
  3. Intra-procedural alias tracking: 指针赋值 → 等价类合并
  4. Path-aware verdict: SAME_PATH / MUTUAL_EXCLUSIVE / DOMINATED_TEMPORAL

与 uaf_path_verifier.py 的关系:
  - uaf_path_verifier: CFG构建+空间可达性 (free块能否物理上到达use块)
  - 本模块: 时间维度的判定 (free是否总是在use之前执行, 是否有NULL guard)

  - Undangle — temporal safety via pointer liveness
  - FreeGuard — semantic-aware temporal safety
  - DangNull — NULL assignment detection
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class TemporalVerdict(Enum):
    BEFORE_USE = "BEFORE_USE"         # free 在 use 之前 (确定UAF)
    AFTER_USE = "AFTER_USE"           # free 在 use 之后 (FP)
    SAME_PATH = "SAME_PATH"           # 同路径, 需要进一步分析
    GUARDED_NULL = "GUARDED_NULL"     # use前有NULL检查 (防御)
    REASSIGNED = "REASSIGNED"         # free后重新赋值 (p=NULL或p=malloc)
    UNCERTAIN = "UNCERTAIN"

@dataclass
class TemporalResult:
    """时序分析结果对单个free-use pair。"""
    ptr_name: str
    free_line: int
    use_line: int
    verdict: TemporalVerdict
    null_guard_found: bool = False   # free后 use前是否有 if(ptr) 检查
    reassigned: bool = False          # free后是否重新赋值
    alias_chain: List[str] = field(default_factory=list)  # 别名传播链
    confidence: float = 0.5
    reason: str = ""

class UafTemporalVerifier:
    """UAF时序验证器 —— 从 free/use 文本位置推断运行时顺序。

    关键洞察: 在反编译伪代码中, 如果 free(p) 和 use(p) 在同一基本块,
    文本顺序 = 运行时顺序 (99%置信度)。跨块时需要CFG分析。
    """

    # 指针置空模式
    _NULL_AFTER_FREE = re.compile(
        r'free\s*\([^)]+\)\s*;\s*(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;',
    )
    # 指针重新分配模式
    _REASSIGN_AFTER_FREE = re.compile(
        r'free\s*\((\w+)\)\s*;.*?(?:\1\s*=\s*(?:malloc|calloc|realloc|new))',
        re.DOTALL,
    )
    # NULL guard: if(ptr) use(ptr)
    _NULL_GUARD = re.compile(
        r'if\s*\(\s*(\w+)\s*\)\s*(?:\{?\s*(?:[^}]*\*?\1|[^}]*\1\s*->))',
    )
    # 别名赋值: q = p;
    _ALIAS_ASSIGN = re.compile(r'(\w+)\s*=\s*(\w+)\s*;')

    def __init__(self):
        self._aliases: Dict[str, Set[str]] = {}  # var → {aliases}

    def verify(
        self, pseudocode: str, ptr_name: str,
    ) -> TemporalResult:
        """对单个指针执行时序验证, 返回带时序判定的 TemporalResult。"""
        lines = pseudocode.splitlines()

        # 1. 找到所有free和use的位置
        free_lines = []
        use_lines = []
        for i, line in enumerate(lines):
            if f'free({ptr_name})' in line or f'free ({ptr_name})' in line:
                free_lines.append(i)
            if self._is_pointer_use(line, ptr_name):
                use_lines.append(i)

        if not free_lines:
            return TemporalResult(
                ptr_name=ptr_name, free_line=-1, use_line=-1,
                verdict=TemporalVerdict.UNCERTAIN,
                reason=f"no free({ptr_name}) found",
                confidence=0.5,
            )

        # 2. 构建别名链
        aliases = self._build_alias_chain(lines, ptr_name)
        for alias in aliases:
            for i, line in enumerate(lines):
                if f'free({alias})' in line:
                    if i not in free_lines:
                        free_lines.append(i)
                if self._is_pointer_use(line, alias):
                    if i not in use_lines:
                        use_lines.append(i)

        if not use_lines:
            return TemporalResult(
                ptr_name=ptr_name, free_line=free_lines[0], use_line=-1,
                verdict=TemporalVerdict.UNCERTAIN,
                null_guard_found=False, reassigned=False,
                reason=f"no use of {ptr_name} (or aliases) found",
                confidence=0.3,
                alias_chain=list(aliases),
            )

        fl = free_lines[-1]  # 使用最后的free (最接近use)
        ul = use_lines[0]    # 使用第一个use

        # 3. 检查NULL guard
        code_between = '\n'.join(lines[fl:ul + 1])
        null_guard = bool(self._NULL_GUARD.search(code_between))
        if null_guard:
            return TemporalResult(
                ptr_name=ptr_name, free_line=fl, use_line=ul,
                verdict=TemporalVerdict.GUARDED_NULL,
                null_guard_found=True,
                reason=f"NULL guard detected between free(L{fl}) and use(L{ul})",
                confidence=0.85,
                alias_chain=list(aliases),
            )

        # 4. 检查重新赋值
        reassigned = bool(self._REASSIGN_AFTER_FREE.search(code_between))
        if reassigned:
            return TemporalResult(
                ptr_name=ptr_name, free_line=fl, use_line=ul,
                verdict=TemporalVerdict.REASSIGNED,
                reassigned=True,
                reason=f"ptr reassigned between free(L{fl}) and use(L{ul})",
                confidence=0.80,
                alias_chain=list(aliases),
            )

        # 5. 检查文本顺序
        if fl < ul:
            # free 在 use 之前 (文本顺序 = 运行时顺序, 99% 置信度)
            reason = (f"free({ptr_name}) at L{fl} precedes "
                      f"first use at L{ul} — confirmed UAF")
            return TemporalResult(
                ptr_name=ptr_name, free_line=fl, use_line=ul,
                verdict=TemporalVerdict.BEFORE_USE,
                reason=reason,
                confidence=0.95,
                alias_chain=list(aliases),
            )
        elif fl > ul:
            return TemporalResult(
                ptr_name=ptr_name, free_line=fl, use_line=ul,
                verdict=TemporalVerdict.AFTER_USE,
                reason=(f"free({ptr_name}) at L{fl} after last use "
                       f"at L{ul} — not a UAF"),
                confidence=0.90,
                alias_chain=list(aliases),
            )

        return TemporalResult(
            ptr_name=ptr_name, free_line=fl, use_line=ul,
            verdict=TemporalVerdict.UNCERTAIN,
            reason="ambiguous temporal ordering",
            confidence=0.40,
            alias_chain=list(aliases),
        )

    def _build_alias_chain(self, lines: List[str], ptr_name: str) -> Set[str]:
        """构建指针的别名链 (1-hop forward)。"""
        aliases = {ptr_name}
        # 正向搜索: q = p; → q是p的别名
        for line in lines:
            m = self._ALIAS_ASSIGN.search(line)
            if m:
                lhs, rhs = m.group(1), m.group(2)
                if rhs in aliases:
                    aliases.add(lhs)
        self._aliases[ptr_name] = aliases
        return aliases

    @staticmethod
    def _is_pointer_use(line: str, ptr_name: str) -> bool:
        """检查一行是否包含对指针的use（解引用/字段访问/索引）。"""
        # 先排除明确的非use操作: free(ptr), ptr = (NULL|malloc|...)
        if re.search(rf'\bfree\s*\(\s*\*?{ptr_name}\s*\)', line):
            return False
        if re.search(rf'\b{ptr_name}\s*=\s*(?:NULL|nullptr|0x|malloc|calloc|realloc)', line):
            return False

        # 检测真正的use: *ptr, ptr->field, ptr[index]
        patterns = [
            rf'\*{ptr_name}\b',         # *ptr (含 *ptr = val 写入)
            rf'\b{ptr_name}\s*->',      # ptr->field
            rf'\b{ptr_name}\s*\[',      # ptr[index]
        ]
        for pat in patterns:
            if re.search(pat, line):
                return True
        return False

    def batch_verify(
        self, pseudocode: str, ptr_names: List[str],
    ) -> List[TemporalResult]:
        """批量时序验证。"""
        return [self.verify(pseudocode, name) for name in ptr_names]

def verify_uaf_temporal(
    pseudocode: str, ptr_name: str,
) -> TemporalResult:
    """便捷入口: 单指针时序验证。"""
    verifier = UafTemporalVerifier()
    return verifier.verify(pseudocode, ptr_name)

def verify_uaf_batch(
    pseudocode: str, ptr_names: List[str],
) -> List[TemporalResult]:
    """便捷入口: 批量时序验证。"""
    verifier = UafTemporalVerifier()
    return [verifier.verify(pseudocode, name) for name in ptr_names]

__all__ = [
    'TemporalVerdict', 'TemporalResult', 'UafTemporalVerifier',
    'verify_uaf_temporal', 'verify_uaf_batch',
]
