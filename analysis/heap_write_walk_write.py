"""
指针游走写检测. 目标模式:

  char* b = malloc(N); char* p = b;
  for (; *s; s++) { if (*s=='\\') *p++='\\'; *p++=*s; }
  *p = 0;

堆写模式验证的 find_writes 仅识别 buf[i]=.../memcpy/strcpy 等,
对 `*p++` 游走式写入漏检. 本模块补足该类写模式.

判定分两条路径:
  1. 循环上界可定: max_write = bound * steps_per_iter + trailing 与 usable 比较
  2. 循环由字符串指针驱动且上界不可定: 比较分配与写入相对 strlen 的
     增长系数, write_coef > alloc_coef 时对足够长输入必然溢出
"""

import re
from typing import Dict, List, Optional, Tuple

from analysis.heap_write_ext_types import ExtAlloc, ExtResult, WalkWrite
from analysis.heap_overflow_src_patterns import _is_comment_or_empty, _base_var


_WALK_ASSIGN_RE = re.compile(
    r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*$')
_PTR_INC_RE = re.compile(r'\*\s*(\w[\w]*)\s*\+\+\s*=')
_PTR_PLUS_RE = re.compile(r'\*\s*(\w[\w]*)\s*=\s*[^;]*;\s*(\w[\w]*)\s*\+\+\s*;')
_LOOP_SRC_COND_RE = re.compile(
    r'for\s*\([^;]*;\s*\*?\s*(\w[\w]*)\s*[;+\-]')
_LOOP_CONST_RE = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\d+)\s*;')
_STR_END_RE = re.compile(r'\*\s*(\w[\w]*)\s*=\s*0\s*;')
# 循环内 memcpy(p, src, n) 固定步长: memcpy 与 p+=n 成对
_MEMCPY_PTR_RE = re.compile(
    r'\bmemcpy\s*\(\s*(\w[\w]*)\s*,\s*[^,]+,\s*(\d+)\s*\)\s*;')
_PTR_ADVANCE_RE = re.compile(
    r'(\w[\w]*)\s*\+=\s*(\d+)\s*;')


def _estimate_iter_bound(line: int, lines: List[str],
                         src_ptr: str) -> Optional[int]:
    """估计循环迭代上界.

    三种来源:
      a) 常量上界 for(i=0;i<N;i++)
      b) 源指针条件 for(; *s; s++) → strlen(s) (需解析 s 的来源)
      c) while(*s++) 结构
    无法确定返回 None.

    TODO: 循环边界推断目前仅覆盖常量上界与源指针条件. 累积写
    (n += k) 与 while(i--) 变体未处理, 需要 SCEV 级统一解析.
    """
    for i in range(max(0, line - 6), line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        cm = _LOOP_CONST_RE.search(t)
        if cm:
            return int(cm.group(2))
        sm = _LOOP_SRC_COND_RE.search(t)
        if sm:
            sp = sm.group(1)
            if sp == src_ptr:
                return _resolve_strlen(sp, line, lines)
    return None


def _resolve_strlen(src: str, around_line: int,
                    lines: List[str]) -> Optional[int]:
    """尝试解析源指针指向的字符串长度.

    若 src 是参数或由 strlen(...) 赋值而来且上游无法解析, 保守
    无法定界 (返回 None) — 由调用方按"未知上界但存在游走写"处理.
    """
    for i in range(max(0, around_line - 12), around_line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        m = re.search(rf'\bstrlen\s*\(\s*(\w[\w]*)\s*\)', t)
        if m and m.group(1) == src:
            return None
    return None


def collect_walk_writes(alloc_vars: set, lines: List[str],
                        valid_lines: Optional[set] = None
                        ) -> List[WalkWrite]:
    """收集所有 `p = buf; ... *p++ = ...` 游走写候选.

    支持单行多语句 (分号分隔), 逐语句提取 `p = buf` 别名赋值.
    """
    walks: List[WalkWrite] = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        # 拆分为语句, 逐个匹配 `ptr = base;`
        for stmt in text.split(';'):
            stmt = stmt.strip()
            if not stmt:
                continue
            m = _WALK_ASSIGN_RE.search(stmt)
            if not m:
                continue
            ptr, base = m.group(1), _base_var(m.group(2))
            if base not in alloc_vars:
                continue
            # 在 ptr 后续生命周期内扫描游走写
            steps_per_iter = 0
            write_lines: List[int] = []
            loop_line = i
            loop_bound: Optional[int] = None
            trailing = 0
            src_ptr = ""
            memcpy_bytes_per_iter = 0
            for j in range(i + 1, min(len(lines) + 1, i + 60)):
                t2 = lines[j - 1].strip()
                if _is_comment_or_empty(t2):
                    continue
                # 先识别循环结构 (for/while 条件), 独立于游走写匹配,
                # 避免 *p++ 命中 continue 跳过 src 指针识别
                lm = _LOOP_SRC_COND_RE.search(t2)
                if lm and lm.group(1) and not loop_bound:
                    src_ptr = lm.group(1)
                lm2 = _LOOP_CONST_RE.search(t2)
                if lm2 and not loop_bound:
                    try:
                        loop_bound = int(lm2.group(2))
                    except ValueError:
                        loop_bound = None
                pm = _PTR_INC_RE.search(t2)
                if pm and _base_var(pm.group(1)) == ptr:
                    # 同一行可能多个 *p++ (如 if(*s=='\\') *p++='\\'; *p++=*s;)
                    hits = list(_PTR_INC_RE.finditer(t2))
                    n_hits = sum(1 for h in hits
                                 if _base_var(h.group(1)) == ptr)
                    steps_per_iter += n_hits
                    write_lines.append(j)
                    continue
                pm2 = _PTR_PLUS_RE.search(t2)
                if pm2 and _base_var(pm2.group(1)) == ptr:
                    steps_per_iter += 1
                    write_lines.append(j)
                    continue
                # 循环内 memcpy(p, src, n) + p+=n 固定步长游走
                mc = _MEMCPY_PTR_RE.search(t2)
                if mc and _base_var(mc.group(1)) == ptr:
                    memcpy_bytes_per_iter = int(mc.group(2))
                    write_lines.append(j)
                    continue
                adv = _PTR_ADVANCE_RE.search(t2)
                if adv and _base_var(adv.group(1)) == ptr:
                    if memcpy_bytes_per_iter:
                        steps_per_iter += memcpy_bytes_per_iter
                        memcpy_bytes_per_iter = 0
                        continue
                sm = _STR_END_RE.search(t2)
                if sm and _base_var(sm.group(1)) == ptr:
                    trailing = 1
                    continue
                if steps_per_iter:
                    # 同函数内 ptr 被重新赋值或 return, 结束该游走
                    if re.search(rf'\b{ptr}\s*=\s*\w[\w]*\s*;', t2) and \
                            '++' not in t2 and 'p++' not in t2:
                        break
                    if t2.startswith('return'):
                        break
            if not steps_per_iter:
                continue
            if loop_bound is None and src_ptr:
                loop_bound = _estimate_iter_bound(write_lines[0], lines, src_ptr)
            is_str = bool(src_ptr)
            walks.append(WalkWrite(
                base=base, ptr=ptr, loop_line=loop_line,
                write_line=write_lines[0], max_steps_per_iter=steps_per_iter,
                loop_bound=-1 if loop_bound is None else loop_bound,
                trailing_write=trailing, elem_size=1,
                driver=src_ptr, is_str_loop=is_str))
    return walks


def _find_strlen_var(size_expr: str, lines: Optional[List[str]],
                     alloc_line: int) -> Optional[str]:
    """从分配表达式定位 strlen 源变量.

    a) 表达式直接含 strlen(X) → 返回 X
    b) 表达式为变量 l, 且前文 l=strlen(X) → 返回 X
    c) 表达式为变量 l, 且前文 l=expr 含 strlen(X) → 返回 X
    """
    if not size_expr:
        return None
    dm = re.search(r'strlen\s*\(\s*(\w[\w]*)\s*\)', size_expr)
    if dm:
        return dm.group(1)
    if not lines:
        return None
    var = size_expr.strip()
    vm = re.search(r'\b([a-zA-Z_]\w*)\b', var)
    cand = vm.group(1) if vm else None
    if cand is None:
        return None
    for j in range(max(0, alloc_line - 8), alloc_line):
        t = lines[j].strip()
        if _is_comment_or_empty(t):
            continue
        am = re.search(
            rf'\b{re.escape(cand)}\s*=\s*strlen\s*\(\s*(\w[\w]*)\s*\)',
            t)
        if am:
            return am.group(1)
        am2 = re.search(
            rf'\b{re.escape(cand)}\s*=\s*([^;]+);', t)
        if am2:
            dm2 = re.search(r'strlen\s*\(\s*(\w[\w]*)\s*\)',
                            am2.group(1))
            if dm2:
                return dm2.group(1)
    return None


def _strlen_coef(size_expr: str, lines: Optional[List[str]],
                 alloc_line: int, strlen_var: str) -> int:
    """解析分配表达式中 strlen_var 对应变量的系数.

    l+1    (l=strlen(s)) → 1
    l*2+2  (l=strlen(s)) → 2
    l*l    → 2 (平方, 保守按 2 计 — 分配增长快)
    strlen(s)+1 直接 → 1
    """
    if 'strlen' in size_expr:
        dm = re.search(
            r'strlen\s*\(\s*' + re.escape(strlen_var) + r'\s*\)\s*(\*)',
            size_expr)
        if dm:
            m2 = re.search(r'\*', size_expr)
            if m2:
                return 1  # 保守: strlen(s)*N 至少线性
        return 1
    if not lines:
        return 1
    vm = re.search(r'\b([a-zA-Z_]\w*)\b', size_expr)
    var = vm.group(1) if vm else size_expr.strip()
    for j in range(max(0, alloc_line - 8), alloc_line):
        t = lines[j].strip()
        if _is_comment_or_empty(t):
            continue
        am2 = re.search(rf'\b{re.escape(var)}\s*=\s*([^;]+);', t)
        if am2:
            rhs = am2.group(1)
            cm = re.search(rf'\b{re.escape(var)}\s*\*\s*(\d+)', size_expr)
            if cm:
                return int(cm.group(1))
            cm2 = re.search(rf'(\d+)\s*\*\s*{re.escape(var)}', size_expr)
            if cm2:
                return int(cm2.group(1))
            break
    return 1


def asymptotic_check(w: WalkWrite, alloc: ExtAlloc,
                     lines: Optional[List[str]] = None) -> Optional[ExtResult]:
    """渐近溢出判定 — 循环上界未知时比较分配/写入的增长系数.

    适用形态:
      a) 分配直接含 strlen: malloc(strlen(s)+1)
      b) 中间变量: l=strlen(s); malloc(l+1)
      c) 循环指针为 driver: for(q=s;*q;q++) 扫描 s, 分配基于 strlen(s)
    """
    if not w.is_str_loop:
        return None
    write_coef = w.max_steps_per_iter
    if alloc.size_const > 0:
        return None
    strlen_var = _find_strlen_var(alloc.size_expr, lines, alloc.line)
    if strlen_var is None:
        return None
    alloc_coef = _strlen_coef(alloc.size_expr, lines, alloc.line, strlen_var)
    if write_coef <= alloc_coef:
        # 分配增长不慢于写入增长, 结构性安全
        return ExtResult(
            verdict="SAFE", alloc_line=alloc.line,
            write_line=w.write_line, var_name=alloc.var,
            alloc_size=-1, write_size=-1, confidence=0.90,
            kind="walk_write_asymptotic",
            reason=("'%s': malloc(%s) alloc_coef=%d >= "
                    "ptr-walk write_coef=%d (steps/iter, strlen(%s)-driven) "
                    "→ no asymptotic overflow"
                    % (alloc.var, alloc.size_expr, alloc_coef, write_coef,
                       strlen_var)))
    return ExtResult(
        verdict="VULN", alloc_line=alloc.line,
        write_line=w.write_line, var_name=alloc.var,
        alloc_size=-1, write_size=-1, confidence=0.85,
        kind="walk_write_asymptotic",
        reason=("'%s': malloc(%s) alloc_coef=%d vs "
                "ptr-walk write_coef=%d (steps/iter, strlen(%s)-driven) "
                "→ asymptotic overflow for long input"
                % (alloc.var, alloc.size_expr, alloc_coef, write_coef,
                   strlen_var)))


def verify_walk(w: WalkWrite, alloc: Optional[ExtAlloc],
                lines: List[str]) -> Optional[ExtResult]:
    """对单个游走写验证溢出.

    判定优先级:
      1. 渐近溢出判定 (strlen 驱动 + 系数比较)
      2. 有界循环: max_write = bound*steps + trailing vs usable
      3. 无法定界 → UNCERTAIN (不产生误报)
    """
    if alloc is None or alloc.size_const <= 0:
        if alloc is not None and alloc.size_const < 0:
            return asymptotic_check(w, alloc, lines)
        return None
    asym = asymptotic_check(w, alloc, lines)
    if asym:
        return asym
    usable = alloc.usable if alloc.usable > 0 else alloc.size_const
    if w.loop_bound < 0:
        return ExtResult(
            verdict="UNCERTAIN", alloc_line=alloc.line,
            write_line=w.write_line, var_name=alloc.var,
            alloc_size=alloc.size_const, write_size=-1,
            confidence=0.35,
            reason="walk-write with unbounded loop: conservatively kept")
    max_write = (w.loop_bound * w.max_steps_per_iter * w.elem_size
                 + w.trailing_write)
    if max_write > usable:
        return ExtResult(
            verdict="VULN", alloc_line=alloc.line,
            write_line=w.write_line, var_name=alloc.var,
            alloc_size=alloc.size_const, write_size=max_write,
            overflow_bytes=max_write - usable, confidence=0.82,
            kind="walk_write",
            reason=("'%s': malloc(%d) usable=%d, ptr-walk write "
                    "%d iters * %d steps + %d trailing = %d > %d"
                    % (alloc.var, alloc.size_const, usable, w.loop_bound,
                       w.max_steps_per_iter, w.trailing_write,
                       max_write, usable)))
    return ExtResult(
        verdict="SAFE", alloc_line=alloc.line,
        write_line=w.write_line, var_name=alloc.var,
        alloc_size=alloc.size_const, write_size=max_write,
        confidence=0.90, kind="walk_write",
        reason=("'%s': ptr-walk write %d <= usable %d"
                % (alloc.var, max_write, usable)))


__all__ = [
    'WalkWrite', 'collect_walk_writes',
    '_estimate_iter_bound', '_resolve_strlen',
]


