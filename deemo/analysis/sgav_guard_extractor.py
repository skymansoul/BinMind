"""
SGAV 守卫约束提取器 — 路径敏感 if/else 条件解析.
提取每个写入操作所在路径上的守卫约束链.
"""
import re
from typing import List, Dict, Tuple, Optional
from analysis.sgav_types import GuardConstraint

# if 条件提取函数(处理嵌套括号)
def _extract_if_cond(text: str) -> Optional[str]:
    """从 'if (...) {' 行提取括号内的条件表达式."""
    idx = text.find('if')
    while idx >= 0:
        # 确认是词边界
        if idx > 0 and (text[idx-1].isalnum() or text[idx-1] == '_'):
            idx = text.find('if', idx + 2)
            continue
        # 找到 if 后的第一个 '('
        p = text.index('(', idx)
        depth = 1
        p2 = p + 1
        while p2 < len(text) and depth > 0:
            if text[p2] == '(':
                depth += 1
            elif text[p2] == ')':
                depth -= 1
            p2 += 1
        if depth == 0:
            return text[p+1:p2-1].strip()
        idx = text.find('if', idx + 2)
    return None
_CMP = re.compile(r'(\w[\w]*)\s*(<=|>=|<|>|==|!=)\s*(\d+|0x[0-9a-fA-F]+)')
_STRLEN_GUARD = re.compile(
    r'strlen\s*\(\s*(\w[\w]*)\s*\)\s*(<=|>=|<|>|==|!=)\s*(\d+)')
_SIZEOF_GUARD = re.compile(
    r'(\w[\w]*)\s*(<=|>=|<|>|==|!=)\s*sizeof\s*\(\s*(\w[\w]*)\s*\)')
_ELSE_IF = re.compile(r'\belse\s+if\s*\(\s*(.+?)\s*\)')
_AND = re.compile(r'\band\b|&&')


class GuardExtractor:
    """从源码提取路径敏感守卫约束."""

    def extract(self, lines: List[str]) -> Dict[int, List[GuardConstraint]]:
        """返回 {line_num: [guards]} 对每行有效的守卫约束."""
        result: Dict[int, List[GuardConstraint]] = {}
        # 栈: [(guards, enter_brace_depth)]
        # enter_brace_depth = 块体开始时的 brace_depth
        stack: List[Tuple[List[GuardConstraint], int]] = []
        brace_depth = 0

        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')):
                result[i] = []
                continue
            opens = text.count('{')
            closes = text.count('}')
            # 先移除因 closes 弹出的守护
            new_depth = brace_depth + opens - closes
            # 弹出: brace_depth 减到 < enter_brace_depth 时弹出
            # 注意: closes 在本行执行, 所以先检查弹窗
            temp_depth = brace_depth + opens  # 本行开括号后的深度
            # 但先检查 closes 弹出
            check_depth = brace_depth
            # 先处理本行的 closes（右大括号在行尾时表示退出块）
            # 策略: 在记录当前行守卫前先处理弹出
            while stack and (check_depth + opens - closes) < stack[-1][1]:
                stack.pop()
            # 若本行有 closes 但没有对应的 opens
            # 需要在记录守卫前检查
            active_guards: List[GuardConstraint] = []
            for gs, _ in stack:
                active_guards.extend(gs)
            # 记录当前行活动守卫（if 行本身不包含自己的守卫）
            result[i] = list(active_guards)
            # 如果是 else / else if, 替换栈顶守卫
            else_m = _ELSE_IF.search(text)
            is_else = bool(re.search(r'\belse\b', text))
            if else_m:
                cond = else_m.group(1)
                guards = self._parse_cond(cond, i, is_else=True)
                if stack:
                    stack[-1] = (guards, temp_depth)
            elif is_else:
                if stack:
                    old_g = stack[-1][0]
                    negated = [GuardConstraint(
                        var=g.var, op=self._negate_op(g.op),
                        bound=g.bound, line=i, is_else=True)
                        for g in old_g]
                    stack[-1] = (negated, temp_depth)
            elif _extract_if_cond(text) is not None:
                cond = _extract_if_cond(text)
                guards = self._parse_cond(cond, i, is_else=False)
                # 守卫从块体开始生效: enter_brace_depth = temp_depth
                stack.append((guards, temp_depth))
            # 更新深度
            brace_depth = new_depth
        return result

    def _parse_cond(self, cond: str, line: int,
                    is_else: bool) -> List[GuardConstraint]:
        guards = []
        for m in _STRLEN_GUARD.finditer(cond):
            guards.append(GuardConstraint(
                var=m.group(1), op=m.group(2), bound=int(m.group(3)),
                line=line, is_else=is_else))
        for m in _SIZEOF_GUARD.finditer(cond):
            guards.append(GuardConstraint(
                var=m.group(1), op=m.group(2), bound=-3,
                line=line, is_else=is_else))
        for m in _CMP.finditer(cond):
            var = m.group(1)
            op = m.group(2)
            bound = int(m.group(3), 0)
            # 去重: 同一 var+op+bound 才跳过
            if not any(g.var == var and g.op == op and g.bound == bound
                       for g in guards):
                guards.append(GuardConstraint(
                    var=var, op=op, bound=bound,
                    line=line, is_else=is_else))
        return guards

    @staticmethod
    def _negate_op(op: str) -> str:
        return {'<': '>=', '<=': '>', '>': '<=', '>=': '<',
                '==': '!=', '!=': '=='}.get(op, op)


__all__ = ['GuardExtractor']
