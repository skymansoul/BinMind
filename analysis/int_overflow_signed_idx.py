"""
整数下溢/负索引检测 — 检测有符号整数用作数组索引时缺少下界检查.
与 int_overflow_vrf.py 互补: VRF 侧重乘法溢出→堆分配, 本模块侧重索引下溢→越界访问.

模式: int idx = atoi(argv[1]); if (idx < 100) arr[idx] = 0;  // 仅上界, 无下界
CWE-190 变体: 有符号整数下溢绕过边界检查.
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional


def detect_signed_index_underflow(code: str) -> List[Dict]:
    """检测有符号整数负索引绕过边界检查.

    返回 {lineno, expr, var, upper_bound, reason} 列表.
    """
    lines = code.splitlines()
    results = []

    # 收集有符号int声明/参数
    signed_vars = set()
    for line in lines:
        # 匹配声明: int var 或 int var = ... 或函数参数中的 int var
        for m in re.finditer(r'\b(?:int|short)\s+(\w+)\s*[;,=)]', line):
            v = m.group(1)
            if v not in ('argc', 'main', 'void', 'NULL'):
                signed_vars.add(v)

    if not signed_vars:
        return results

    # 筛选用户可控的有符号变量
    user_vars = set()
    for var in signed_vars:
        if re.search(rf'{re.escape(var)}\s*=\s*(?:atoi|strtol|argv\[)', code):
            user_vars.add(var)
        # 也检查函数参数中的有符号int (通过参数名被调用处传入atoi结果)
        elif re.search(rf'(?:atoi|strtol)\s*\([^)]*\)\s*,?\s*{re.escape(var)}', code):
            user_vars.add(var)
        # 如果var是函数参数, 且调用处有atoi, var被用作 arr[var] 数组索引
        elif (re.search(r'(?:atoi|strtol)\s*\(', code) and
              re.search(rf'\[\s*{re.escape(var)}\s*\]', code)):
            user_vars.add(var)

    if not user_vars:
        return results

    # 上界检查 vs 下界检查
    upper_checked = {}  # var → upper_bound
    lower_checked = set()
    for line in lines:
        # 上界检查: if (var < N) 或 if (var <= N)
        for m in re.finditer(rf'if\s*\(\s*(\w+)\s*<=?\s*(\d+)\s*\)', line):
            v, n = m.group(1), int(m.group(2))
            if v in user_vars:
                upper_checked[v] = n
        # 下界检查: if (var >= 0) 或 if (var > -1) 或 if (var >= 0 && var < N)
        for v in user_vars:
            if re.search(rf'if\s*\([^)]*{re.escape(v)}\s*>=?\s*0', line):
                lower_checked.add(v)

    # 找 arr[var] 且仅上界无下界
    for var, upper_n in upper_checked.items():
        if var in lower_checked:
            continue
        for i, line in enumerate(lines):
            for m in re.finditer(rf'(\w+)\s*\[\s*{re.escape(var)}\s*\]', line):
                arr_name = m.group(1)
                if arr_name not in ('argv', 'sizeof', 'int', 'char'):
                    results.append({
                        'lineno': i + 1,
                        'expr': line.strip()[:100],
                        'var': var,
                        'arr': arr_name,
                        'upper_bound': upper_n,
                        'type': 'signed_index_underflow',
                        'verdict': 'DEFINITE',
                        'reason': f'{var}<0时可绕过if({var}<{upper_n}) → {arr_name}[{var}]负索引越界',
                    })
                    break  # 每个var只报一次
    return results


def analyze_int_underflow(code: str) -> Dict:
    """便捷入口, 与统一基准格式兼容."""
    findings = detect_signed_index_underflow(code)
    definite = [f for f in findings if f.get('verdict') == 'DEFINITE']
    return {
        'total': len(findings),
        'definite': len(definite),
        'possible': len(findings) - len(definite),
        'detected': len(findings) > 0,
        'findings': findings,
    }


__all__ = ['detect_signed_index_underflow', 'analyze_int_underflow']
