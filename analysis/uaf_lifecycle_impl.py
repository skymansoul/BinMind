# UAF 生命周期验证器 (Use-After-Free Lifecycle verifier).
#
# 定位: 补足既有 UAF 对象身份图管线的两类漏检:
#   1. 结构体字段指针 UAF: free(&v->items[idx]) 后经字段别名使用
#   2. realloc 旧指针 UAF: old = *buf_ptr; realloc 后 memcpy(*buf_ptr, old)
#   跨函数层补足包装 free 与参数传递:
#   3. free_ctx(ctx) 包装调用, 实参释放后使用
#   4. 多函数对同一参数重复 free, 双重释放
#   5. 链式释放包装 while(p){free(p);p=p->next;}
#
# 设计决策:
#   - 三阶段: 释放点提取, 别名闭包, 使用点判定
#   - 保守原则: 只能确认 (VULN/SAFE 有证据), 否则 UNCERTAIN
#
# 本文件实现 UAF 生命周期验证器 (UAF 对象身份图漏检补足): 释放点提取, 别名闭包, 使用点判定.


import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set


class UafVerdict(Enum):
    CONFIRMED = "CONFIRMED"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class FreeSite:
    line: int
    expr: str          # free 参数原文
    root: str          # 归一化根变量
    kind: str = "free"  # free|realloc
    new_var: str = ""   # realloc 返回值变量


@dataclass
class UseSite:
    line: int
    expr: str
    root: str
    kind: str = "deref"  # deref|memcpy|strcpy|array


@dataclass
class UafFinding:
    free_line: int
    use_line: int
    var: str
    verdict: UafVerdict
    confidence: float = 0.0
    reason: str = ""
    stage: str = ""      # field_alias|realloc_old|direct


def base_var(expr: str) -> str:
    """表达式归一根变量: v->items 得 items, *buf_ptr 得 buf_ptr."""
    e = expr.strip()
    e = e.lstrip('*').strip()
    e = re.sub(r'^\([^)]*\)\s*', '', e)
    if '->' in e:
        e = e.split('->')[-1].strip()
    elif '.' in e:
        e = e.split('.')[-1].strip()
    e = re.split(r'[+\-]', e)[0].strip()
    e = e.split('[')[0].strip()
    return e


def unqual(expr: str) -> str:
    """去限定符: &v->items[idx] 得 v->items; *buf_ptr 得 buf_ptr."""
    e = expr.strip()
    e = e.lstrip('&').strip()
    e = e.lstrip('*').strip()
    e = re.sub(r'\[\w*\]$', '', e.strip())
    return e.strip()


class UafLifecycleVerifier:
    """UAF 生命周期验证器."""

    def __init__(self):
        self._lines: List[str] = []

    def verify(self, source: str) -> List[UafFinding]:
        """主入口: 源码经 UAF 判定输出列表."""
        self._lines = source.splitlines()
        frees = self._find_frees()
        if not frees:
            return []
        aliases = self._build_aliases()
        findings = []
        for fs in frees:
            if fs.kind == 'realloc':
                findings.extend(self._check_realloc_old(fs, aliases))
            findings.extend(self._check_uses(fs, aliases))
        return self._dedup(findings)

    def _find_frees(self) -> List[FreeSite]:
        out = []
        for i, line in enumerate(self._lines, start=1):
            fm = re.search(r'\bfree\s*\(\s*([^)]+)\s*\)', line)
            if fm:
                expr = fm.group(1).strip()
                out.append(FreeSite(line=i, expr=expr,
                                    root=base_var(expr)))
            rm = re.search(
                r'(\w+)\s*=\s*realloc\s*\(\s*([^,]+)\s*,', line)
            if rm:
                old = rm.group(2).strip()
                out.append(FreeSite(line=i, expr=old,
                                    root=base_var(old), kind='realloc',
                                    new_var=rm.group(1)))
        return out

    def _build_aliases(self) -> Dict[str, Set[str]]:
        """字段别名: v.items 与 items 视为同根."""
        aliases: Dict[str, Set[str]] = {}
        for i, line in enumerate(self._lines, start=1):
            am = re.search(
                r'(\w+)\s*(?:->|\.)\s*(\w+)\s*=\s*(\w+)\s*;', line)
            if am:
                field = am.group(2)
                rhs = am.group(3)
                aliases.setdefault(field, set()).add(rhs)
                aliases.setdefault(rhs, set()).add(field)
            # 指针别名: p = q
            pm = re.search(r'\b(\w+)\s*=\s*(\w+)\s*;', line)
            if pm and pm.group(1) != pm.group(2):
                a, b = pm.group(1), pm.group(2)
                aliases.setdefault(a, set()).add(b)
                aliases.setdefault(b, set()).add(a)
        # 闭包 (2轮足够)
        for _ in range(2):
            for k in list(aliases):
                for v in list(aliases[k]):
                    aliases[k] |= aliases.get(v, set())
        return aliases

    def _check_realloc_old(self, fs: FreeSite,
                           aliases: Dict[str, Set[str]]) -> List[UafFinding]:
        """realloc 旧指针: old 变量在 realloc 后的使用."""
        findings = []
        old = unqual(fs.expr)
        if not old:
            return findings
        old_src = ''
        for j in range(fs.line - 5, fs.line):
            if j < 0 or j >= len(self._lines):
                continue
            m = re.search(
                r'\b' + re.escape(old) + r'\s*=\s*([^;]+);',
                self._lines[j])
            if m:
                old_src = m.group(1).strip()
                break
        new_var = fs.new_var
        for i in range(fs.line + 1, min(len(self._lines), fs.line + 25)):
            line = self._lines[i]
            if new_var and new_var in line and '=' in line:
                continue
            if re.search(r'\bfree\s*\(', line):
                continue
            if re.search(r'\b' + re.escape(old) + r'\b', line):
                if new_var and re.search(
                        r'\b' + re.escape(new_var) + r'\s*=', line):
                    continue
                findings.append(UafFinding(
                    free_line=fs.line, use_line=i + 1, var=old,
                    verdict=UafVerdict.CONFIRMED, confidence=0.85,
                    stage='realloc_old',
                    reason=(f"realloc@L{fs.line}: old '{old}' used@L{i+1}"
                            f" after realloc to {new_var}")))
                break
        return findings

    def _check_uses(self, fs: FreeSite,
                    aliases: Dict[str, Set[str]]) -> List[UafFinding]:
        """free 后使用: 同根变量或字段别名的使用."""
        findings = []
        root = fs.root
        start = fs.line
        end = min(len(self._lines) + 1, fs.line + 40)
        # 守卫检测: free 与 use 之间隔有 if { ... return; } 块
        guarded_safe = False
        for j in range(max(0, fs.line - 8), fs.line):
            bl = self._lines[j]
            if not re.search(r'\bif\s*\(', bl):
                continue
            seg = '\n'.join(self._lines[j:fs.line + 4])
            free_pos = seg.find('free(')
            ret_pos = seg.find('return')
            if free_pos < 0 or ret_pos < 0 or ret_pos < free_pos:
                continue
            if_depth = 0
            block_line = None
            for k in range(j, min(len(self._lines), j + 10)):
                if_depth += self._lines[k].count('{') - \
                    self._lines[k].count('}')
                if k >= fs.line and if_depth <= 0:
                    block_line = k
                    break
            if block_line is not None and block_line < fs.line + 2:
                guarded_safe = True
        for i in range(start, end):
            line = self._lines[i - 1] if i - 1 < len(self._lines) else ''
            line_no = i
            if guarded_safe and line_no > fs.line:
                return findings
            if re.search(r'\bfree\s*\(\s*' + re.escape(fs.expr) +
                         r'\s*\)', line):
                continue
            used = False
            use_kind = 'direct'
            if re.search(
                    r'\b(?:memcpy|memmove|strcpy|strcat|memset|read|fread)'
                    r'\s*\(\s*[^,)]*' + re.escape(root) + r'\b', line):
                used = True
            elif re.search(
                    r'(?<![A-Za-z0-9_])' + re.escape(root) +
                    r'(?=\s*\[|\s*->|\s*\.\s*\w|\s*\*\s*=|\s*,|\s*\))',
                    line):
                used = True
            elif re.search(
                    r'(?<![A-Za-z0-9_*&])' + re.escape(root) +
                    r'(?![A-Za-z0-9_])', line):
                pre = line[:line.find(root)]
                if '=' not in pre or re.search(
                        r'return\s+' + re.escape(root) + r'\b', line) or \
                        re.search(
                            r'=\s*[^;]*' + re.escape(root) + r'\b', line):
                    used = True
            if used:
                findings.append(UafFinding(
                    free_line=fs.line, use_line=i + 1, var=root,
                    verdict=UafVerdict.CONFIRMED, confidence=0.80,
                    stage=use_kind,
                    reason=(f"free@L{fs.line}: '{root}' used@L{i+1}")))
                break
            for field, alias_set in aliases.items():
                if root not in alias_set and field != root:
                    continue
                fm2 = re.search(
                    r'\b(\w+)\s*(?:->|\.)\s*' + re.escape(root) +
                    r'(?=\s*\[|\s*[,)]|\s*=|\s*$)', line)
                if fm2:
                    findings.append(UafFinding(
                        free_line=fs.line, use_line=i + 1, var=root,
                        verdict=UafVerdict.CONFIRMED, confidence=0.75,
                        stage='field_alias',
                        reason=(f"free@L{fs.line}: field-alias '{root}'"
                                f" used@L{i+1} via "
                                f"'{fm2.group(1)}->{root}'")))
                    break
        return findings

    @staticmethod
    def _is_assignment_only(line: str, root: str) -> bool:
        """该行是否仅对 root 赋值 (赋值不算使用)."""
        m = re.search(r'\b' + re.escape(root) + r'\s*=', line)
        if m and not re.search(
                r'\b' + re.escape(root) + r'\s*\[\s*\w+\s*\]\s*=', line):
            return True
        return False

    @staticmethod
    def _dedup(findings: List[UafFinding]) -> List[UafFinding]:
        seen = set()
        out = []
        for f in findings:
            k = (f.free_line, f.use_line)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out


# 跨函数层

@dataclass
class FuncInfo:
    name: str
    params: List[str]
    body_lines: List[str]
    line_off: int          # 函数体在源码中的起始行 (1-based)


class UafCrossVerifier:
    """跨函数 UAF 验证器."""

    def __init__(self):
        self._lines: List[str] = []
        self._funcs: Dict[str, FuncInfo] = {}

    def verify(self, source: str) -> List[UafFinding]:
        self._lines = source.splitlines()
        self._collect_funcs()
        findings: List[UafFinding] = []
        for fname, finfo in self._funcs.items():
            findings.extend(self._check_func(finfo))
        check_double_free(self._lines, self._funcs, findings)
        check_freed_arg_passed(self._lines, findings)
        check_cond_free_use(self._lines, findings)
        check_chain_free(self._lines, self._funcs, findings)
        return self._dedup(findings)

    def _collect_funcs(self) -> None:
        """收集函数签名与体. 括号配平从函数头后开始."""
        i = 0
        n = len(self._lines)
        while i < n:
            m = re.search(
                r'\b(\w+)\s*\(([^)]*)\)\s*\{', self._lines[i])
            if m:
                name = m.group(1)
                params = [p.strip().split()[-1].lstrip('*').strip()
                          for p in m.group(2).split(',') if p.strip()]
                body = []
                hdr = self._lines[i]
                head = hdr[hdr.find('{'):]
                depth = head.count('{') - head.count('}')
                j = i + 1
                while j < n and depth > 0:
                    body.append(self._lines[j])
                    depth += self._lines[j].count('{') - \
                        self._lines[j].count('}')
                    j += 1
                self._funcs[name] = FuncInfo(
                    name=name, params=params, body_lines=body,
                    line_off=i + 1)
                i = j
            else:
                i += 1

    def _check_func(self, finfo: FuncInfo) -> List[UafFinding]:
        """检查单函数: 参数被 free / 包装 free 调用 / 双重释放."""
        findings = []
        hdr_line = self._lines[finfo.line_off - 1]
        freed_params = [p for p in finfo.params
                        if re.search(r'\bfree\s*\(\s*\*?\s*' +
                                     re.escape(p) +
                                     r'\s*\)',
                                     hdr_line + '\n' +
                                     '\n'.join(finfo.body_lines))]
        for p in freed_params:
            free_line = finfo.line_off
            for ci, cl in enumerate(self._lines, start=1):
                cm = re.search(
                    r'\b' + re.escape(finfo.name) +
                    r'\s*\(\s*([^)]*)\s*\)\s*;', cl)
                if not cm:
                    continue
                args = [a.strip() for a in cm.group(1).split(',')]
                pi = finfo.params.index(p)
                if pi >= len(args):
                    continue
                arg = args[pi]
                deref_target = ''
                if arg.startswith('&'):
                    deref_target = arg[1:].strip()
                cl_tail = cl[cl.find(finfo.name) + len(finfo.name):]
                if re.search(
                        r'(?<![A-Za-z0-9_])' + re.escape(arg) +
                        r'(?=\s*\[|\s*->|\s*\.|\s*[,)]|'
                        r'\s*\*\s*=)', cl_tail):
                    findings.append(UafFinding(
                        free_line=free_line, use_line=ci,
                        var=arg, verdict=UafVerdict.CONFIRMED,
                        confidence=0.85, stage='wrapped_free',
                        reason=(f"'{arg}' freed in {finfo.name}@L"
                                f"{free_line}, used@L{ci}")))
                    continue
                for ui in range(ci + 1,
                                min(len(self._lines) + 1, ci + 25)):
                    ul = self._lines[ui - 1]
                    if re.search(
                            r'(?<![A-Za-z0-9_])' + re.escape(arg) +
                            r'(?=\s*\[|\s*->|\s*\.|\s*[,)]|'
                            r'\s*\*\s*=)', ul):
                        findings.append(UafFinding(
                            free_line=free_line, use_line=ui,
                            var=arg, verdict=UafVerdict.CONFIRMED,
                            confidence=0.85, stage='wrapped_free',
                            reason=(f"'{arg}' freed in {finfo.name}@L"
                                    f"{free_line}, used@L{ui}")))
                        break
                    if deref_target:
                        am = re.search(
                            r'\b(\w+)\s*=\s*&' + re.escape(deref_target),
                            '\n'.join(self._lines[:ui]))
                        if am:
                            alias = am.group(1)
                            if re.search(
                                    r'\*' + re.escape(alias) +
                                    r'(?=\s*\[|\s*[,)]|$)|\*?\s*'
                                    + re.escape(alias) + r'\s*\[', ul):
                                findings.append(UafFinding(
                                    free_line=free_line, use_line=ui,
                                    var=deref_target,
                                    verdict=UafVerdict.CONFIRMED,
                                    confidence=0.80,
                                    stage='addr_alias_deref',
                                    reason=(f"'{deref_target}' freed via"
                                            f" &-arg in {finfo.name}@L"
                                            f"{free_line}, deref alias"
                                            f" '{alias}'@L{ui}")))
                                break
        return findings

    @staticmethod
    def _dedup(findings: List[UafFinding]) -> List[UafFinding]:
        seen = set()
        out = []
        for f in findings:
            k = (f.stage, f.var, f.free_line, f.use_line)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out


def check_double_free(lines: List[str], funcs: Dict,
                      findings: List[UafFinding]) -> None:
    """多函数对同一参数/字段重复 free, 双重释放."""
    free_funcs: Dict[str, List[str]] = {}
    for fname, fi in funcs.items():
        hdr = lines[fi.line_off - 1]
        text = hdr + '\n' + '\n'.join(fi.body_lines)
        for p in fi.params:
            if re.search(r'\bfree\s*\(\s*' + re.escape(p) +
                         r'\s*\)', text):
                free_funcs.setdefault(p, []).append(fname)
            if re.search(r'\bfree\s*\(\s*' + re.escape(p) +
                         r'\s*(?:->|\.)\s*\w+', text):
                free_funcs.setdefault(p + '->*', []).append(fname)
    for p, funcs_list in free_funcs.items():
        if len(set(funcs_list)) >= 2:
            findings.append(UafFinding(
                free_line=0, use_line=0, var=p,
                verdict=UafVerdict.CONFIRMED, confidence=0.80,
                stage='double_free_cross',
                reason=(f"'{p}' freed in multiple funcs: "
                        f"{sorted(set(funcs_list))}")))


_SAFE_FUNCS = {'memset', 'memcpy', 'memmove', 'strlen',
               'strcmp', 'printf', 'free', 'malloc'}


def check_freed_arg_passed(lines: List[str],
                           findings: List[UafFinding]) -> None:
    """free(arg) 后 arg 作为实参传入其他调用, 悬挂访问."""
    for ci, cl in enumerate(lines, start=1):
        fm = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', cl)
        if not fm:
            continue
        arg = fm.group(1)
        scan_end = min(len(lines) + 1, ci + 20)
        for ui in range(ci, scan_end):
            ul = lines[ui - 1] if ui - 1 < len(lines) else ''
            if ui == ci:
                pos = ul.find('free(')
                tail = ul[pos + 5:] if pos >= 0 else ul
                cm = re.search(
                    r'\b(\w+)\s*\(\s*[^)]*\b' + re.escape(arg) +
                    r'\b', tail)
                if cm and cm.group(1) in _SAFE_FUNCS:
                    continue
                if cm and '=' not in tail[:tail.find(cm.group(1))]:
                    findings.append(UafFinding(
                        free_line=ci, use_line=ui, var=arg,
                        verdict=UafVerdict.CONFIRMED,
                        confidence=0.80, stage='freed_arg_passed',
                        reason=(f"free({arg})@L{ci} then passed to"
                                f" {cm.group(1)}@L{ui}")))
                    break
                continue
            cm = re.search(
                r'\b(\w+)\s*\(\s*[^)]*\b' + re.escape(arg) +
                r'\b', ul)
            if cm and cm.group(1) in _SAFE_FUNCS:
                continue
            if cm and '=' not in ul[:ul.find(cm.group(1))]:
                findings.append(UafFinding(
                    free_line=ci, use_line=ui, var=arg,
                    verdict=UafVerdict.CONFIRMED, confidence=0.80,
                    stage='freed_arg_passed',
                    reason=(f"free({arg})@L{ci} then passed to"
                            f" {cm.group(1)}@L{ui}")))
                break


def check_cond_free_use(lines: List[str],
                        findings: List[UafFinding]) -> None:
    """条件 free 后立即使用: if(cond) free(p); *p = 0;"""
    for ci, cl in enumerate(lines, start=1):
        if re.search(r'\bif\s*\([^)]*\)\s*\{?\s*free\s*\(\s*(\w+)'
                     r'\s*\)\s*;?\s*\}?', cl):
            fm3 = re.search(r'free\s*\(\s*(\w+)\s*\)', cl)
            if not fm3:
                continue
            arg3 = fm3.group(1)
            tail3 = cl[cl.find('free(') + 5:]
            um3 = re.search(
                r'\*?\s*' + re.escape(arg3) + r'(?=\s*\[|\s*->|'
                r'\s*=|;)', tail3)
            if um3:
                findings.append(UafFinding(
                    free_line=ci, use_line=ci, var=arg3,
                    verdict=UafVerdict.CONFIRMED, confidence=0.75,
                    stage='cond_free_use',
                    reason=(f"conditional free({arg3})@L{ci} followed"
                            f" by use in same line")))
            if ci < len(lines):
                nl = lines[ci]
                if re.search(
                        r'(?<![A-Za-z0-9_])' + re.escape(arg3) +
                        r'(?=\s*\[|\s*->|\s*=|;|\s*\*)', nl):
                    findings.append(UafFinding(
                        free_line=ci, use_line=ci + 1, var=arg3,
                        verdict=UafVerdict.CONFIRMED, confidence=0.75,
                        stage='cond_free_use',
                        reason=(f"conditional free({arg3})@L{ci} used"
                                f"@L{ci+1}")))


def check_chain_free(lines: List[str], funcs: Dict,
                     findings: List[UafFinding]) -> None:
    """链式释放包装: while(p){free(p);p=p->next;} 调用者实参悬挂."""
    for fname, fi in funcs.items():
        hdr = lines[fi.line_off - 1]
        text = hdr + '\n' + '\n'.join(fi.body_lines)
        for p in fi.params:
            if not re.search(r'\bwhile\s*\(\s*' + re.escape(p) +
                             r'\s*\)', text):
                continue
            if not re.search(r'\bfree\s*\(\s*' + re.escape(p) +
                             r'\s*\)', text):
                continue
            for ci, cl in enumerate(lines, start=1):
                cm = re.search(
                    r'\b' + re.escape(fname) + r'\s*\(\s*([^)]*)\s*\)'
                    r'\s*;', cl)
                if not cm:
                    continue
                args = [a.strip() for a in cm.group(1).split(',')]
                pi = fi.params.index(p)
                if pi >= len(args):
                    continue
                arg = args[pi]
                cl_tail = cl[cl.find(fname) + len(fname):]
                if re.search(
                        r'(?<![A-Za-z0-9_])' + re.escape(arg) +
                        r'(?=\s*\[|\s*->|\s*\.|\s*[,)]|'
                        r'\s*\*\s*=)', cl_tail):
                    findings.append(UafFinding(
                        free_line=fi.line_off, use_line=ci,
                        var=arg, verdict=UafVerdict.CONFIRMED,
                        confidence=0.85, stage='chain_free',
                        reason=(f"chain-free in {fname}: '{arg}'"
                                f" freed@L{fi.line_off}, used@L{ci}")))
                    continue
                for ui in range(ci + 1,
                                min(len(lines) + 1, ci + 30)):
                    ul = lines[ui - 1]
                    if re.search(
                            r'(?<![A-Za-z0-9_])' + re.escape(arg) +
                            r'(?=\s*\[|\s*->|\s*\.|\s*[,)]|'
                            r'\s*\*\s*=)', ul):
                        findings.append(UafFinding(
                            free_line=fi.line_off, use_line=ui,
                            var=arg, verdict=UafVerdict.CONFIRMED,
                            confidence=0.85, stage='chain_free',
                            reason=(f"chain-free in {fname}: '{arg}'"
                                    f" freed@L{fi.line_off}, used@L{ui}")))
                        break


def verify_uaf_lite(source: str) -> List[UafFinding]:
    """便捷入口: 单函数 UAF 生命周期验证."""
    return UafLifecycleVerifier().verify(source)


def verify_uaf_cross(source: str) -> List[UafFinding]:
    """便捷入口: 跨函数 UAF 验证."""
    return UafCrossVerifier().verify(source)


__all__ = ["UafVerdict", "FreeSite", "UseSite", "UafFinding",
           "base_var", "unqual", "UafLifecycleVerifier",
           "UafCrossVerifier", "FuncInfo", "check_double_free",
           "check_freed_arg_passed", "check_cond_free_use",
           "check_chain_free", "verify_uaf_lite", "verify_uaf_cross"]
