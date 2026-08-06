# 整型溢出检测器 — 基于乘法/加法的溢出约束检查
# 决策: 检测乘/加后用于malloc/memcpy但缺少上界检查的模式
# 方法: 静态模式匹配 + 约束推断, 标记为需深度强化(待引入区间算术)
import re
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class IntOverflowFinding:
    location: str; operation: str  # 'mul'|'add'|'shift'
    operands: List[str]; used_in_alloc: bool
    has_bounds_check: bool; confidence: float

class IntOverflowChecker:
    _MUL_PAT = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)')
    _ADD_PAT = re.compile(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)')
    _ALLOC_PAT = re.compile(r'malloc\s*\(\s*(\w+)\s*\)')
    _GUARD_PAT = re.compile(r'if\s*\([^)]*[><=]+[^)]*\)')

    def check(self, pseudocode: str) -> List[IntOverflowFinding]:
        findings = []
        mul_vars = set()
        for m in self._MUL_PAT.finditer(pseudocode):
            lhs, a, b = m.group(1), m.group(2), m.group(3)
            mul_vars.add(lhs)
            used_in_alloc = bool(re.search(rf'malloc\s*\(\s*{lhs}\s*\)', pseudocode))
            has_guard = bool(re.search(rf'if\s*\([^)]*{lhs}[^)]*[><=]', pseudocode))
            findings.append(IntOverflowFinding(
                location=f'line_{pseudocode[:m.start()].count(chr(10))+1}',
                operation='mul', operands=[a,b],
                used_in_alloc=used_in_alloc, has_bounds_check=has_guard,
                confidence=0.7 if (used_in_alloc and not has_guard) else 0.3,
            ))
        for m in self._ADD_PAT.finditer(pseudocode):
            lhs, a, b = m.group(1), m.group(2), m.group(3)
            used_in_alloc = bool(re.search(rf'malloc\s*\(\s*{lhs}\s*\)', pseudocode))
            has_guard = bool(re.search(rf'if\s*\([^)]*{lhs}[^)]*[><=]', pseudocode))
            if used_in_alloc and not has_guard:
                findings.append(IntOverflowFinding(
                    location=f'line_{pseudocode[:m.start()].count(chr(10))+1}',
                    operation='add', operands=[a,b],
                    used_in_alloc=True, has_bounds_check=False, confidence=0.6,
                ))
        findings.sort(key=lambda f: f.confidence, reverse=True)
        return findings
