"""
HOVF 跨函数相关性核验.

分配大小与写入大小同源时, 写入 ≤ 分配恒成立, 可直接判安全:
  1. 同函数同变量: malloc(size); memset(buf, 0, size)
  2. 跨函数同根 + 钳位支配: 两形参绑定调用方同一实参, 且
     写入钳位 ≤ 分配钳位
本模块只提供解析与相关性判定, 由 hovf_engine 调用.
"""

import re
from typing import Dict, List, Optional, Tuple

from core.hovf_types import ValueInterval
from core.hovf_size_vflow import resolve_alloc_size
from core.heap_overflow_detector import (
    HeapAllocSite, HeapOverflowCandidate,
)

_SIG_RE = re.compile(r'^[A-Za-z_][\w \*]*\b(\w+)\s*\(([^)]*)\)\s*\{')
_CALL_RE = re.compile(r'\b([a-z_]\w*)\s*\(')
_SKIP = ('if', 'while', 'for', 'switch', 'sizeof', 'return', 'main',
         'else', 'do')
_CLAMP_RE = re.compile(
    rf'if\s*\(\s*(\w+)\s*>\s*(0x[0-9a-fA-F]+|\d+)\s*\)')

def _split_args(args: str) -> List[str]:
    parts, depth, cur = [], 0, []
    for ch in args:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return parts


def _find_close(line: str, open_idx: int) -> Optional[int]:
    depth = 0
    for i in range(open_idx, len(line)):
        ch = line[i]
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth == 0:
                return i
    return None


class CrossFuncResolver:
    """函数签名/调用/钳位/分配返回的解析器."""

    def __init__(self, ir: List[str]):
        self.ir = ir
        self.signatures: Dict[str, List[str]] = {}
        self.calls: Dict[str, List[Tuple[str, int, str]]] = {}
        self.clamps: Dict[str, Dict[str, int]] = {}
        self.alloc_vars: Dict[str, str] = {}
        self.func_of_line: List[str] = []
        self._parse()

    def _body_end(self, start: int) -> int:
        depth = 0
        for i in range(start, len(self.ir)):
            depth += self.ir[i].count('{') - self.ir[i].count('}')
            if depth <= 0 and i > start:
                return i
        return len(self.ir)

    def _find_clamps(self, start: int, end: int) -> Dict[str, int]:
        clamps: Dict[str, int] = {}
        for i in range(start, end):
            m = _CLAMP_RE.search(self.ir[i])
            if not m:
                continue
            var, cap = m.group(1), int(m.group(2), 0)
            # 单行或拆行钳位赋值
            if re.search(rf'{var}\s*=\s*(?:0x[0-9a-fA-F]+|\d+)', self.ir[i]):
                clamps[var] = cap
            else:
                for j in range(i + 1, min(end, i + 3)):
                    if re.search(rf'{var}\s*=\s*(?:0x[0-9a-fA-F]+|\d+)',
                                 self.ir[j]):
                        clamps[var] = cap
                        break
        return clamps

    def _find_return_alloc(self, start: int, end: int) -> Optional[str]:
        for i in range(start, end):
            m = re.search(r'return\s*\(?[^;]*\)?\s*'
                          r'(malloc|calloc)\s*\(\s*(\w+)\s*\)', self.ir[i])
            if m:
                return m.group(2)
        return None

    def _parse(self) -> None:
        cur = ''
        for i, line in enumerate(self.ir):
            m = _SIG_RE.match(line)
            if m:
                cur = m.group(1)
                params = [p.strip().split()[-1] for p in m.group(2).split(',')
                          if p.strip()]
                self.signatures[cur] = params
                end = self._body_end(i)
                self.clamps[cur] = self._find_clamps(i, end)
                av = self._find_return_alloc(i, end)
                if av:
                    self.alloc_vars[cur] = av
                self.func_of_line.append(cur)
                continue
            for cm in _CALL_RE.finditer(line):
                fname = cm.group(1)
                if fname in _SKIP:
                    continue
                close = _find_close(line, cm.end() - 1)
                if close is None:
                    continue
                after = line[close + 1:].lstrip()
                if after.startswith('{'):
                    continue
                inner = line[cm.end():close]
                args = _split_args(inner)
                for pos, a in enumerate(args):
                    self.calls.setdefault(fname, []).append(
                        (a.strip(), pos, cur))
            self.func_of_line.append(cur)

    def enclosing_func(self, pc: int) -> str:
        if 0 <= pc < len(self.func_of_line):
            return self.func_of_line[pc]
        return ''

    def _clamp_upper(self, func: str, var: str) -> Optional[int]:
        return self.clamps.get(func, {}).get(var)

    def root_clamp(self, var: str, func: str, depth: int = 0
                   ) -> Tuple[str, Optional[int]]:
        """返回 (根变量, 钳位上界或 None). 深度受限防环."""
        if depth > 4:
            return var, self._clamp_upper(func, var)
        clamp = self._clamp_upper(func, var)
        params = self.signatures.get(func, [])
        if var not in params:
            return var, clamp
        pos = params.index(var)
        roots: List[str] = []
        clamps: List[int] = []
        for arg, ap, caller in self.calls.get(func, []):
            if ap != pos:
                continue
            if re.fullmatch(r'[a-z_]\w*', arg):
                r, c = self.root_clamp(arg, caller, depth + 1)
                roots.append(r)
                if c is not None:
                    clamps.append(c)
            elif 'argv' in arg or arg.startswith('atoi'):
                roots.append(arg)
        if roots and len(set(roots)) == 1:
            if clamps:
                return roots[0], min(clamps)
            return roots[0], clamp
        return var, clamp

    def resolve_param_size(self, base_var: str, write_pc: int
                           ) -> Optional[ValueInterval]:
        """base_var 为函数参数时, 从 caller 追溯分配大小.

        定位 write_pc 所属函数, 若 base_var 在其参数列表中,
        查找调用方传入的实参并解析其分配大小.
        """
        func = self.enclosing_func(write_pc)
        params = self.signatures.get(func, [])
        if base_var not in params:
            return None
        pos = params.index(base_var)
        for arg, ap, caller in self.calls.get(func, []):
            if ap != pos:
                continue
            # 实参为数字常量直接返回
            try:
                val = int(arg, 0)
                return ValueInterval(val, val)
            except (ValueError, TypeError):
                pass
            # 实参为变量时在 caller 中解析其分配大小
            if re.fullmatch(r'[a-z_]\w*', arg):
                res = resolve_alloc_size(arg, self.ir, 0)
                if res.interval is not None:
                    return res.interval
        return None
        pos = params.index(var)
        roots: List[str] = []
        clamps: List[int] = []
        for arg, ap, caller in self.calls.get(func, []):
            if ap != pos:
                continue
            if re.fullmatch(r'[a-z_]\w*', arg):
                r, c = self.root_clamp(arg, caller, depth + 1)
                roots.append(r)
                if c is not None:
                    clamps.append(c)
            elif 'argv' in arg or arg.startswith('atoi'):
                roots.append(arg)
        if roots and len(set(roots)) == 1:
            if clamps:
                return roots[0], min(clamps)
            return roots[0], clamp
        return var, clamp


def correlated_within_alloc(
        resolver: CrossFuncResolver,
        alloc_var: str, alloc_func: str,
        write_var: str, write_func: str) -> Optional[str]:
    """同源相关判定. 返回安全依据或 None.

    规则:
      - 同函数同变量: write == alloc, 恒安全.
      - 跨函数同根 + write_clamp <= alloc_clamp: write <= alloc.
    """
    if not alloc_var or not write_var:
        return None
    if alloc_var == write_var and alloc_func == write_func:
        return '同变量分配与写入'
    a_root, a_cap = resolver.root_clamp(alloc_var, alloc_func)
    w_root, w_cap = resolver.root_clamp(write_var, write_func)
    if a_root == w_root and a_cap is not None and w_cap is not None:
        if w_cap <= a_cap:
            return f'同根钳位支配 (写入≤{w_cap}≤分配≤{a_cap})'
    return None


class CrossFuncSafetyCheck:
    """跨函数相关性安全核验 mixin, 供 hovf_engine 组合."""

    def _resolve_size_expr(self, expr: str, pc: int) -> Optional[ValueInterval]:
        res = resolve_alloc_size(expr, self.ir, pc)
        return res.interval

    def _locate_alloc_pc(self, alloc: HeapAllocSite) -> int:
        """在 self.ir 中定位匹配 size_expr 的分配行."""
        expr = getattr(alloc, 'size_expr', '')
        if expr:
            pat = re.compile(
                r'(?:malloc|calloc|realloc)\s*\(\s*'
                + re.escape(expr) + r'\b')
            for i, line in enumerate(self.ir):
                if pat.search(line):
                    return i
        return alloc.pc

    def _locate_write_pc(self, c: HeapOverflowCandidate) -> int:
        """在 self.ir 中定位匹配 base_var 与 mnemonic 的写入行."""
        store = c.overflow_store
        pat = re.compile(
            r'\b' + re.escape(store.mnemonic) + r'\s*\([^)]*'
            + re.escape(store.base_var))
        for i, line in enumerate(self.ir):
            if pat.search(line):
                return i
        return store.pc

    def _crossfunc_safe(self, c: HeapOverflowCandidate) -> Optional[str]:
        """写入大小与分配大小同源相关: 返回安全依据或 None."""
        alloc_var = getattr(c.alloc_site, 'size_expr', '')
        if not alloc_var:
            return None
        write_var = getattr(c, '_hovf_write_size_var', '')
        if not write_var:
            # 基础通道候选未记录 size 变量, 从写入行末参解析
            write_pc = self._locate_write_pc(c)
            write_var = self._extract_write_size_var(
                self.ir[write_pc] if 0 <= write_pc < len(self.ir) else '')
        if not write_var:
            return None
        write_pc = self._locate_write_pc(c)
        alloc_pc = self._locate_alloc_pc(c.alloc_site)
        write_func = self.resolver.enclosing_func(write_pc)
        alloc_func = self.resolver.enclosing_func(alloc_pc)
        from core.hovf_crossfunc import correlated_within_alloc
        return correlated_within_alloc(
            self.resolver, alloc_var, alloc_func, write_var, write_func)

    @staticmethod
    def _extract_write_size_var(line: str) -> str:
        """从 memcpy/memset/memmove/strncpy 行提取末参变量名."""
        m = re.search(
            r'\b(memcpy|memset|memmove|strncpy)\s*\([^)]*?'
            r',\s*([a-z_]\w*)\s*\)', line)
        return m.group(2) if m else ''

    def _is_stack_array(self, base_var: str) -> bool:
        """base_var 是否为栈数组声明 (char data[64]), 非堆指针."""
        if not base_var:
            return False
        pat = re.compile(
            r'\b(?:char|short|int|long|float|double|void|bool|'
            r'uint\d+_t|int\d+_t)\s+\*?\s*'
            + re.escape(base_var) + r'\s*\[')
        return any(pat.search(line) for line in self.ir)

    def _free_is_guarded(self, free_idx: int) -> bool:
        """free 是否位于分支/循环块内.

        从 free 指令向前回溯, 遇到 if/for/while/switch 控制头
        即判定受控; 遇到函数定义标签停止, 限制回溯于当前函数.
        """
        for i in range(free_idx - 1, -1, -1):
            line = self.ir[i]
            if re.search(r'\b(if|for|while|switch|case)\b', line):
                return True
            # 函数定义标签标记回溯边界
            if re.match(r'^\s*<\w+>:\s*$', line):
                break
        return False

    def _freed_before_write(self, base_var: str, store_pc: int) -> bool:
        """base_var 指向的分配是否在写入前已被 free.

        free 必须文本序上位于写入之前, 且不受分支控制: 分支内的
        free (如 `if (n>200) { free(buf); }`) 与写入互斥, 不是
        释放后写入. 常规样本 main 末尾 free(buf) 晚于写入, 不受影响.
        """
        if not base_var:
            return False
        pat = re.compile(r'free\s*\(\s*([^)]*?)\s*\)')
        token = re.compile(r'\b' + re.escape(base_var) + r'\b')
        for i, line in enumerate(self.ir):
            if i >= store_pc:
                break
            m = pat.search(line)
            if not m or not token.search(m.group(1)):
                continue
            if self._free_is_guarded(i):
                continue
            return True
        return False
