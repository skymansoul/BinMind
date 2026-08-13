"""
FOVF 格式参数值流分类.

核心判定: 格式参数是否可控.
  1. 字面量 -> LITERAL (安全)
  2. 用户输入源 -> USER (漏洞)
  3. 栈缓冲: 全部写入点仅常量 -> CONST_BUFFER (安全)
     由常量模板 + 用户实参生成 -> TEMPLATE (间接可控)
  4. 函数形参: 绑定调用点实参分类 (跨函数)
  5. 无法确定 -> UNKNOWN

与既有 format_string_taint (仅 user/safe/const 三元) 的差异:
  增加 CONST_BUFFER 负向证明 (缓冲全常量填充) 与 TEMPLATE 间接
  可控识别, 两者都需要跨写入点值流而非单点来源判定.
"""

import re
from typing import Dict, List, Optional, Set, Tuple

from core.fovf_types import ArgCategory
from core.hovf_write_extract import _strip_block_comments

from core.fovf_helpers import (
    _DANGER_SPEC, _CONST_WRITE_FUNCS, _INPUT_SOURCES, _FMT_POS,
    _fmt_position, _split_top, _paren_inner, _signature_params,
    _call_args, _is_user_expr, _user_or_unknown, has_var_rhs,
)

class FovfArgClassifier:
    """格式参数分类器. 构造一次, 可对多个参数分类."""

    def __init__(self, ir: List[str]):
        self.ir = _strip_block_comments(list(ir))
        self.params = _signature_params(self.ir)
        self.calls = _call_args(self.ir)
        self._cache: Dict[str, ArgCategory] = {}

    def classify(self, fmt_expr: str, depth: int = 0) -> Tuple[
            ArgCategory, List[str]]:
        """分类格式参数, 返回 (类别, 理由链)."""
        fmt_expr = (fmt_expr or '').strip()
        if not fmt_expr:
            return ArgCategory.UNKNOWN, ['空参数']
        if fmt_expr.startswith('"'):
            return ArgCategory.LITERAL, ['字符串字面量格式']
        if fmt_expr in self._cache:
            c = self._cache[fmt_expr]
            return c, ['缓存命中']
        if _is_user_expr(fmt_expr, self.ir):
            return ArgCategory.USER, ['直接来自用户输入']
        m = re.fullmatch(r'(\w+)', fmt_expr)
        if m:
            return self._classify_var(m.group(1), depth)
        return ArgCategory.UNKNOWN, ['复杂表达式']

    def _classify_var(self, var: str, depth: int) -> Tuple[
            ArgCategory, List[str]]:
        if var in self._cache:
            return self._cache[var], ['缓存命中']
        if depth > 4:
            return ArgCategory.UNKNOWN, ['递归深度超限']
        if _is_user_expr(var, self.ir):
            return ArgCategory.USER, ['变量即用户输入']
        # 形参: 绑定所有调用点实参
        for fname, plist in self.params.items():
            if var in plist:
                pos = plist.index(var)
                cats = []
                for arg_expr, argpos in self.calls.get(fname, []):
                    if argpos != pos:
                        continue
                    c, _ = self.classify(arg_expr, depth + 1)
                    cats.append(c)
                if cats:
                    if ArgCategory.USER in cats:
                        return ArgCategory.USER, ['形参绑定到用户实参']
                    if ArgCategory.LITERAL in cats and \
                            all(c == ArgCategory.LITERAL for c in cats):
                        return ArgCategory.LITERAL, ['形参绑定到字面量']
                    return ArgCategory.UNKNOWN, ['形参实参分类不一致']
                return ArgCategory.UNKNOWN, ['形参无调用点']
        # 栈缓冲内容分类
        content = self._buffer_content(var, depth)
        if content == 'const':
            return ArgCategory.CONST_BUFFER, ['缓冲仅常量填充']
        if content == 'user':
            return ArgCategory.USER, ['缓冲含用户数据']
        if content == 'template':
            return ArgCategory.TEMPLATE, ['缓冲由模板+用户实参生成']
        return ArgCategory.UNKNOWN, ['缓冲内容不可判定']

    def _buffer_content(self, var: str, depth: int = 0) -> str:
        """var 缓冲的全部写入点内容分类: const/user/template/unknown.

        同一行可能存在多个写入调用 (snprintf 后 strncat), 任一写入
        引入用户数据或不可判定即提前返回; 全部为常量才判 const.
        """
        found = False
        for line in self.ir:
            if var not in line:
                continue
            if re.search(rf'\b{re.escape(var)}\s*\[[^\]]*\]\s*=', line):
                found = True
                if not re.search(r"=\s*'", line):
                    return 'unknown' if _has_var_rhs(line) else 'const'
                continue
            m = re.search(
                rf'\b{re.escape(var)}\s*=\s*(\w+)\s*\(([^)]*)\)\s*;', line)
            if m:
                cls = self._write_class(var, m.group(1), m.group(2), depth)
                if cls:
                    found = True
                    if cls != 'const':
                        return cls
                continue
            for m2 in re.finditer(rf'\b(\w+)\s*\(\s*{re.escape(var)}\b',
                                  line):
                func = m2.group(1)
                if func in ('fgets', 'gets', 'scanf', 'fscanf', 'read',
                            'recv', 'recvfrom', 'getline', 'strdup'):
                    found = True
                    return 'user'
                if func not in ('sprintf', 'snprintf', 'strcpy', 'strncpy',
                                'memcpy', 'memmove', 'vsnprintf',
                                'vsprintf', 'strcat', 'strncat',
                                'strlcat'):
                    continue
                inner = _paren_inner(line, m2.start() + len(func))
                cls = self._write_class(var, func, inner or '', depth)
                if cls:
                    found = True
                    if cls != 'const':
                        return cls
        return 'unknown' if not found else 'const'

    def _arg_has_user(self, arg: str, depth: int) -> bool:
        """实参是否可能含用户数据.

        直接用户源、形参绑定用户、或表达式中任一标识符为
        用户源均判为含用户数据.
        """
        if _is_user_expr(arg, self.ir):
            return True
        m = re.fullmatch(r'([a-z_]\w*)', arg.strip())
        if m and depth < 3:
            cat, _ = self.classify(m.group(1), depth + 1)
            if cat in (ArgCategory.USER, ArgCategory.TEMPLATE):
                return True
        for ident in re.findall(r'\b([a-z_]\w*)\b', arg):
            if _is_user_expr(ident, self.ir):
                return True
        return False

    def _write_class(self, var: str, func: str, args_str: str,
                     depth: int) -> str:
        """单个写入调用的内容类别. '' 表示无需归类."""
        if func not in _CONST_WRITE_FUNCS:
            return ''
        args = [a.strip() for a in _split_top(args_str)]
        if func in ('snprintf', 'vsnprintf'):
            if len(args) >= 3:
                fmt_tpl = args[2]
                rest = args[3:]
                if fmt_tpl.startswith('"'):
                    if any(self._arg_has_user(a, depth) for a in rest):
                        return 'template'
                    return 'const'
                if _is_user_expr(fmt_tpl, self.ir):
                    return 'user'
                if re.fullmatch(r'[a-z_]\w*', fmt_tpl) and depth < 3:
                    cat, _ = self.classify(fmt_tpl, depth + 1)
                    if cat in (ArgCategory.USER, ArgCategory.TEMPLATE):
                        return 'user'
                    if cat in (ArgCategory.LITERAL, ArgCategory.CONST_BUFFER):
                        return 'const'
                return 'unknown'
            return 'unknown'
        if func in ('sprintf',):
            if len(args) >= 2:
                fmt_tpl = args[1]
                rest = args[2:]
                if fmt_tpl.startswith('"'):
                    if any(self._arg_has_user(a, depth) for a in rest):
                        return 'template'
                    return 'const'
                if _is_user_expr(fmt_tpl, self.ir):
                    return 'user'
                return 'unknown'
            return 'unknown'
        if func in ('strcat', 'strncat', 'strlcat'):
            src = args[1] if len(args) > 1 else ''
            if src.startswith('"'):
                return 'const'
            if not src:
                return 'unknown'
            if _is_user_expr(src, self.ir):
                return 'user'
            if re.fullmatch(r'[a-z_]\w*', src) and depth < 3:
                cat, _ = self.classify(src, depth + 1)
                if cat in (ArgCategory.USER, ArgCategory.TEMPLATE):
                    return 'user'
                if cat in (ArgCategory.LITERAL, ArgCategory.CONST_BUFFER):
                    return 'const'
            return 'unknown'
        src = args[1] if len(args) > 1 else ''
        if src.startswith('"'):
            return 'const'
        if src:
            return _user_or_unknown(src, self.ir)
        return 'unknown'

    # TODO: 宽字符格式与 va_list 可变参数深度未建模
    def danger_specs(self, fmt_expr: str) -> bool:
        """格式是否含危险说明符 %n/%x/%s (字面量时)."""
        if fmt_expr.startswith('"'):
            return bool(_DANGER_SPEC.search(fmt_expr))
        return True

