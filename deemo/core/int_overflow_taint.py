"""
整数溢出污点验证 -- 检查溢出操作数是否来自用户可控输入。

设计理由:
  并非所有整数溢出都可利用。若溢出操作数均为编译时常量或内部计算值,
  攻击者无法控制溢出方向, 利用价值极低。本模块对每个溢出告警做污点溯源:
  若参与运算的变量可追溯到用户输入(atoi/strtol/recv/read等),
  则标记为"可利用", 否则降权为"理论溢出"。

与 generic taint_tracker 的区别:
  针对性追踪整数变量的数值来源, 而非通用指针/内存污染。
  仅关心"这个整数值是否来自用户输入", 不追踪内存写/控制流污染。
"""
import re
from typing import Dict, List, Optional, Tuple, Set

# 整数污染源——用户可通过输入控制数值的函数
_INT_TAINT_SOURCES = {
    'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'strtoll', 'strtoull',
    'scanf', 'fscanf', 'sscanf', 'getchar', 'fgetc', 'getc',
    'recv', 'recvfrom', 'read', 'fread',
    'ntohl', 'ntohs',  # 网络字节序转换——数据来自网络
    'strlen',          # 输入字符串长度
}

def _extract_int_assignments(pseudocode: str) -> Dict[str, str]:
    """提取整数变量的赋值表达式 {var: source_expression}。"""
    assigns = {}
    for m in re.finditer(r'(?:int|long|size_t|ssize_t|uint\w*|unsigned)\s+(\w+)\s*=\s*(.+?)\s*;', pseudocode):
        assigns[m.group(1)] = m.group(2).strip()
    for m in re.finditer(r'(\w+)\s*=\s*((?:atoi|strtol|strtoul|strlen|ntohl|ntohs)\s*\([^)]+\))\s*;', pseudocode):
        assigns[m.group(1)] = m.group(2)
    return assigns

def _trace_to_source(var: str, assigns: Dict[str, str],
                     visited: Optional[Set[str]] = None, depth: int = 0) -> Tuple[bool, str]:
    """反向追踪变量到污染源。返回 (is_tainted, source_desc)。"""
    if visited is None: visited = set()
    if var in visited or depth > 5: return False, 'recursion_limit'
    visited.add(var)

    expr = assigns.get(var, '')
    if not expr:
        # var 可能是复合表达式(如 'len*4'), 直接作为表达式解析
        if any(op in var for op in ('+', '-', '*', '<<', '>>')):
            expr = var
        else:
            return False, 'no_assignment_found'

    # 直接调用污染源函数
    for src in _INT_TAINT_SOURCES:
        if expr.startswith(src + '(') or expr == src:
            return True, f'user_controlled_via_{src}'

    # 算术表达式: 递归检查操作数
    for op_pat in [r'(.+)\s*[\+\-\*]\s*(.+)', r'(.+)\s*<<\s*(.+)', r'(.+)\s*>>\s*(.+)']:
        m = re.match(op_pat, expr)
        if m:
            left_ok, left_src = _trace_to_source(m.group(1).strip(), assigns, visited, depth+1)
            right_ok, right_src = _trace_to_source(m.group(2).strip(), assigns, visited, depth+1)
            if left_ok: return True, left_src
            if right_ok: return True, right_src
            return False, 'all_operands_internal'

    # 纯数字字面量 → 不可控
    try: int(expr); return False, 'constant_literal'
    except ValueError: pass

    # 其他变量引用 → 递归
    if re.match(r'^\w+$', expr):
        return _trace_to_source(expr, assigns, visited, depth+1)

    return False, f'unknown_source:{expr[:40]}'


def verify_overflow_taint(pseudocode: str, findings: List[Dict]) -> List[Dict]:
    """对整数溢出告警做污点验证, 调整置信度。

    规则:
      所有操作数均不可控 → confidence *= 0.35 (理论溢出, 几乎不可利用)
      至少一个操作数可控 → confidence = max(0.75, old_confidence)
    """
    assigns = _extract_int_assignments(pseudocode)
    for f in findings:
        expr = f.get('expression', '')
        # 提取操作数
        operands = re.findall(r'\b(\w+)\b', expr)
        operands = [o for o in operands if o not in ('int','long','size_t','unsigned','char','short')]

        any_tainted = False
        sources = []
        for op in operands[:4]:
            tainted, src = _trace_to_source(op, assigns)
            if tainted:
                any_tainted = True
                sources.append(f'{op}←{src}')

        if any_tainted:
            f['confidence'] = max(0.75, f.get('confidence', 0.5))
            f['taint_verified'] = True
            f['taint_sources'] = sources
        else:
            f['confidence'] = round(f.get('confidence', 0.5) * 0.35, 3)
            f['taint_verified'] = False
            f['taint_sources'] = ['all_operands_internal']

    return findings
