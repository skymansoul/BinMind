"""
整数溢出源级验证器 (IOSV). 值范围传播 + 守卫检测 + 跨函数常量传播.
5-phase: 分配点识别→表达式分类→值范围推断→守卫检测→溢出判定.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from analysis.int_overflow_types import (
    IovVerdict, OverflowKind, AllocSite, GuardSite, IovResult, VarRange)

_ALLOC_RE = re.compile(r'\b(malloc|calloc|realloc)\s*\(\s*(.+?)\s*\)\s*;?', re.IGNORECASE)
_ASSIGN_RE = re.compile(r'(\w[\w]*)\s*=\s*([^;]+);')
_GUARD_WRAP_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*([<>])\s*(\w+)\s*\)\s*(?:return|goto|break|continue)', re.IGNORECASE)
_GUARD_DIV_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*>\s*(?:INT_MAX|INT32_MAX|UINT_MAX|SIZE_MAX|'
    r'(?:0x[0-9a-fA-F]+|\d+))\s*/\s*(\w[\w]*)\s*\)', re.IGNORECASE)
_GUARD_BOUND_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*[<>]=?\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
    r'\s*(?:return|goto|break|continue)', re.IGNORECASE)
_CONST_RE = re.compile(r'(\w[\w]*)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;')
_FUNC_DEF_RE = re.compile(
    r'(?:void|int|char|long|short|float|double|unsigned|signed|static|const|inline|size_t)\s+'
    r'(?:\w+\s*\*?\s+)?(\w+)\s*\(\s*([^)]*)\s*\)\s*\{?')
_MUL_RE = re.compile(r'(\w[\w]*)\s*\*\s*(\w[\w]*)')
_ADD_RE = re.compile(r'(\w[\w]*)\s*\+\s*(\w[\w]*|0x[0-9a-fA-F]+|\d+)')
_SHL_RE = re.compile(r'(?:1|(\w[\w]*))\s*<<\s*(\w[\w]*|\d+)')
_THREE_MUL_RE = re.compile(r'(\w[\w]*)\s*\*\s*(\w[\w]*)\s*\*\s*(\w[\w]*)')
_NON_VAR = frozenset({
    'if','else','while','for','return','int','char','void','long',
    'short','float','double','size_t','ssize_t','unsigned','signed',
    'static','const','sizeof','NULL','malloc','calloc','realloc','free',
    'printf','main','include','struct','typedef','switch',
    'case','default','goto','break','continue','exit'})
_INT32_MAX = 0x7FFFFFFF


class IntOverflowSrcVerifier:
    """整数溢出源级验证 — 值范围传播 + 守卫检测 + 溢出判定."""

    def verify(self, source: str) -> List[IovResult]:
        lines = source.splitlines()
        allocs = self._find_alloc_sites(lines)
        if not allocs: return []
        consts = self._collect_constants(lines)
        guards = self._find_guards(lines)
        return [self._analyze(a, lines, consts, guards) for a in allocs]

    @staticmethod
    def _r(a: AllocSite, verdict, **kw) -> IovResult:
        return IovResult(verdict=verdict, alloc_line=a.line,
                         alloc_func=a.func, size_expr=a.size_expr, **kw)

    # Phase 1: 分配点识别

    def _find_alloc_sites(self, lines: List[str]) -> List[AllocSite]:
        allocs = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            am = _ALLOC_RE.search(text);
            if not am: continue
            func = am.group(1).lower()
            args = _split_args(am.group(2))
            if func == 'calloc' and len(args) >= 2:
                se = f'{args[0]}*{args[1]}'
                ops = [args[0], args[1]]; ok = OverflowKind.MUL
            else:
                se = args[0].strip() if args else ''
                ops, ok = self._classify(se)
            if not se: continue
            sv = _extract_var(se)
            allocs.append(AllocSite(line=i, func=func, size_expr=se,
                size_var=sv, operands=ops, op_kind=ok))
        return allocs

    # Phase 2: 表达式分类

    def _classify(self, expr: str) -> Tuple[List[str], OverflowKind]:
        tm = _THREE_MUL_RE.search(expr)
        if tm: return [tm.group(i) for i in range(1,4)], OverflowKind.MIXED
        mm = _MUL_RE.search(expr)
        if mm:
            ops = [mm.group(1), mm.group(2)]; kind = OverflowKind.MUL
            ad = re.search(r'(\w[\w]*)\s*\*\s*(\w[\w]*)\s*\+\s*(\w[\w]*|\d+)', expr)
            if ad: ops.append(ad.group(3)); kind = OverflowKind.MIXED
            return ops, kind
        am = _ADD_RE.search(expr)
        if am and '*' not in expr:
            return [am.group(1), am.group(2)], OverflowKind.ADD
        sm = _SHL_RE.search(expr)
        if sm and '*' not in expr:
            return [sm.group(1) or '1', sm.group(2)], OverflowKind.SHL
        v = _extract_var(expr)
        return ([v], OverflowKind.MUL) if v and v not in _NON_VAR else \
               ([], OverflowKind.MUL)

    # Phase 3: 常量收集 + 守卫检测

    def _collect_constants(self, lines: List[str]) -> Dict[str, Tuple[int, bool]]:
        c: Dict[str, Tuple[int, bool]] = {}
        for line in lines:
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            cm = _CONST_RE.search(text)
            if cm and cm.group(1) not in _NON_VAR:
                try: c[cm.group(1)] = (int(cm.group(2),0), 'unsigned' in text.lower())
                except ValueError: pass
        return c

    def _find_guards(self, lines: List[str]) -> List[GuardSite]:
        guards = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            gm = _GUARD_WRAP_RE.search(text)
            if gm and gm.group(2) == '<':
                # if(result < operand) return → result is guarded by operand
                guards.append(GuardSite(line=i, kind='wrap_check',
                    guarded_var=gm.group(1), operand=gm.group(3)))
                continue
            gm = _GUARD_DIV_RE.search(text)
            if gm:
                guards.append(GuardSite(line=i, kind='div_guard',
                    guarded_var=gm.group(1))); continue
            gm = _GUARD_BOUND_RE.search(text)
            if gm:
                guards.append(GuardSite(line=i, kind='bound_check',
                    guarded_var=gm.group(1)))
        return guards

    # Phase 4: 逐分配点分析

    def _analyze(self, a: AllocSite, lines: List[str],
                 consts: Dict[str, Tuple[int, bool]], guards: List[GuardSite]) -> IovResult:
        ranges = {op: self._eval_range(op, a.line, lines, consts) for op in a.operands}
        vr = self._compute_range(a.op_kind, a.operands, ranges)
        guarded, gline = self._is_guarded(a, lines, guards)
        ok = a.op_kind.value
        if guarded:
            return self._r(a, IovVerdict.SAFE, guarded=True, guard_line=gline,
                value_range=str(vr), reason=f'overflow guard at line {gline}')
        if vr.lo is not None and vr.hi is not None:
            if vr.may_overflow_32():
                return self._r(a, IovVerdict.VULN, overflow_kind=ok,
                    value_range=str(vr), reason=f'range {vr} exceeds INT32_MAX')
            return self._r(a, IovVerdict.SAFE, overflow_kind=ok,
                value_range=str(vr), reason=f'range {vr} within safe bounds')
        # 无精确范围 → 模式保守判定
        rmap = {OverflowKind.MUL: 'mul', OverflowKind.ADD: 'add',
                OverflowKind.SHL: 'shift', OverflowKind.MIXED: 'mixed'}
        return self._r(a, IovVerdict.VULN, overflow_kind=ok,
            reason=f'malloc({a.size_expr}): {rmap.get(a.op_kind,"")} overflow risk')

    # 值范围评估

    def _eval_range(self, var: str, line: int, lines: List[str],
                    consts: Dict[str, Tuple[int, bool]]) -> VarRange:
        # 字面量
        try: return VarRange(lo=int(var,0), hi=int(var,0))
        except ValueError: pass
        # 常量
        if var in consts:
            v, u = consts[var]; return VarRange(lo=v, hi=v, is_signed=not u)
        # sizeof
        sm = re.search(r'sizeof\s*\(\s*([^)]+)\s*\)', var)
        if sm:
            sz = _eval_sizeof(sm.group(1))
            if sz: return VarRange(lo=sz, hi=sz)
        # 赋值链追踪
        for i, tl in enumerate(lines[:line], start=1):
            text = tl.strip()
            if text.startswith(('//', '/*')): continue
            am = _ASSIGN_RE.search(text)
            if not am or am.group(1) != var: continue
            rhs = am.group(2).strip()
            mm = _MUL_RE.search(rhs)
            if mm:
                return self._eval_range(mm.group(1), line, lines, consts).mul(
                       self._eval_range(mm.group(2), line, lines, consts))
            # 1 << c / x << n
            sm = _SHL_RE.search(rhs)
            if sm:
                lhs = sm.group(1) or '1'
                try: lv = int(lhs, 0)
                except ValueError: lv = None
                sv = self._eval_range(sm.group(2), line, lines, consts)
                if lv is not None and sv.lo is not None:
                    return VarRange(lo=lv << sv.lo, hi=lv << sv.lo)
                return VarRange()  # unknown shift → TOP
            try: return VarRange(lo=int(rhs,0), hi=int(rhs,0))
            except ValueError: pass
            rv = _extract_var(rhs)
            if rv and rv not in _NON_VAR:
                return self._eval_range(rv, line, lines, consts)
        # 形参: 调用方常量
        cv = self._caller_const(var, line, lines, consts)
        return cv if cv else VarRange()

    def _compute_range(self, kind: OverflowKind, operands: List[str],
                       ranges: Dict[str, VarRange]) -> VarRange:
        ops = [ranges.get(o, VarRange()) for o in operands]
        if kind == OverflowKind.MUL and len(ops) >= 2: return ops[0].mul(ops[1])
        if kind == OverflowKind.ADD and len(ops) >= 2: return ops[0].add(ops[1])
        if kind == OverflowKind.SHL and len(ops) >= 2:
            if ops[0].lo is None: return VarRange()
            sh = ops[1] if len(ops) > 1 else VarRange()
            if sh.lo is None: return VarRange()
            return VarRange(lo=ops[0].lo << sh.lo, hi=ops[0].lo << sh.lo)
        if kind == OverflowKind.MIXED and len(ops) >= 3:
            r = ops[0].mul(ops[1])
            return r.add(ops[2]) if ops[2].lo is not None else r
        return ops[0] if ops else VarRange()

    def _is_guarded(self, a: AllocSite, lines: List[str], guards: List[GuardSite]) -> Tuple[bool, int]:
        # 扩展operands: 追踪size_var的赋值RHS中的操作数
        extended_ops = set(a.operands)
        if a.size_var and a.size_var not in _NON_VAR:
            for i, line in enumerate(lines[:a.line], start=1):
                text = line.strip()
                if text.startswith(('//', '/*')): continue
                am = _ASSIGN_RE.search(text)
                if not am or am.group(1) != a.size_var: continue
                rhs = am.group(2).strip()
                for v in re.findall(r'\b([a-z_]\w*)\b', rhs):
                    if v not in _NON_VAR:
                        extended_ops.add(v)
                break
        for g in guards:
            if g.line > a.line: continue  # > not >= : same-line guard precedes alloc textually
            if g.kind == 'wrap_check':
                # if(result < operand) return — result is guarded
                if g.guarded_var == a.size_var and g.operand in extended_ops:
                    return True, g.line
            elif g.kind in ('div_guard', 'bound_check'):
                if g.guarded_var == a.size_var or \
                   any(op == g.guarded_var for op in extended_ops):
                    return True, g.line
        return False, 0

    # 跨函数常量传播

    def _caller_const(self, var: str, line: int, lines: List[str],
                      consts: Dict[str, Tuple[int, bool]]) -> Optional[VarRange]:
        """检查 var 是否为函数形参, 调用方传入常量."""
        full = '\n'.join(lines)
        for m in _FUNC_DEF_RE.finditer(full):
            dl = full[:m.start()].count('\n') + 1
            if dl >= line: continue
            ps = m.group(2); params = []
            if ps.strip() and ps.strip() != 'void':
                for p in ps.split(','):
                    pm = re.search(r'(\w[\w]*)\s*$', p.strip())
                    if pm: params.append(pm.group(1))
            pidx = next((idx for idx, p in enumerate(params) if p == var), -1)
            if pidx < 0: continue
            fn = m.group(1)
            for i, tl in enumerate(lines):
                text = tl.strip()
                if text.startswith('//'): continue
                cm = re.search(rf'\b{re.escape(fn)}\s*\(([^)]*)\)', text)
                if not cm: continue
                args = _split_args(cm.group(1))
                if pidx >= len(args): continue
                try: return VarRange(lo=int(args[pidx],0), hi=int(args[pidx],0))
                except ValueError:
                    if args[pidx] in consts:
                        cv, _ = consts[args[pidx]]
                        return VarRange(lo=cv, hi=cv)
            break
        return None


# 模块级辅助

def _split_args(s: str) -> List[str]:
    args = []; depth = 0; cur = []
    for ch in s:
        if ch == '(': depth += 1; cur.append(ch)
        elif ch == ')': depth -= 1; cur.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(cur).strip()); cur = []
        else: cur.append(ch)
    if cur: args.append(''.join(cur).strip())
    return args

def _eval_sizeof(t: str) -> Optional[int]:
    t = t.strip()
    if '*' in t: return 8
    return {'int':4,'unsigned int':4,'long':8,'unsigned long':8,
            'short':2,'unsigned short':2,'char':1,'unsigned char':1,
            'float':4,'double':8,'size_t':8,'ssize_t':8,'void':1,
            'void*':8,'uint32_t':4,'uint64_t':8,'int32_t':4,'int64_t':8,
            'uintptr_t':8,'intptr_t':8}.get(t)

def _extract_var(expr: str) -> str:
    m = re.match(r'(\w[\w]*)', re.sub(r'\([^)]*\)\s*', '', expr.strip()))
    return m.group(1) if m else ''
