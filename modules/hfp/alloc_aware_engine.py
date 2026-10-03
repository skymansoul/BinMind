"""
分配器感知过滤 主检测引擎 — 组装污点/守卫/边界/三态判定.

输入为归一化 IR 行 (objdump 反汇编经 asm_translator 翻译的
伪 IR), 输出带证据链的候选列表。流程:
  污点传播: size 变量来源等级
  分配表:   var -> alloc (跨块)
  守卫集合: guard 行 -> 上界约束 (过滤指针空值检查守卫)
  写点判定: store/copy 按 var 关联, 三态判定 + 证据
SAFE 项被抑制, 其余保留并按置信度排序。CRT 函数块的分配点
视为运行库噪声跳过。
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from .alloc_aware_extract import (HfpAlloc, HfpWrite, extract_alloc_exprs,
                           extract_alloc, extract_write)
from .alloc_aware_guard import GuardSet, loop_bound_from_region
from .alloc_aware_interval import Interval
from .alloc_aware_taint import TaintState, run_taint, taint_of_var
from .alloc_aware_verdict import Verdict, VerdictResult, judge_write

_RE_GUARD = re.compile(
    r'guard\s+(\w+)\s+(<|>|==)\s+(0x[0-9a-fA-F]+|\d+)\s*$', re.IGNORECASE)

# CRT 内部函数: 其 malloc/memcpy 为运行库自身的 argv/启动逻辑,
# 与本检测目标 (用户代码堆溢出) 无关, 产出告警一律视为噪声
CRT_FUNCS = {
    'duplicate_ppstrings', '__tmainCRTStartup', 'mainCRTStartup',
    'WinMainCRTStartup', '__mingw_invalidParameterHandler',
    'check_managed_app', '__gcc_register_frame', '__gcc_deregister_frame',
    '__do_global_dtors', '__do_global_ctors', '__main', '_setargv',
    '__dyn_tls_init', '__tlregdtor', '__dyn_tls_dtor', '_matherr',
    '__report_error', 'mark_section_writable', 'restore_modified_sections',
    '__write_memory', 'do_pseudo_reloc', '_pei386_runtime_relocator',
    'safe_flush', '_initterm', '_initterm_e', '__getmainargs',
    '__p___initenv', '_amsg_exit', '_cexit', '_exit', 'atexit', 'abort',
    'register_frame_ctor', '__mingw_TLScallback', '_fpreset',
    '__set_app_type', '__setusermatherr', '__mingw_setusermatherr',
    '__mingw_raise_matherr', '__mingw_SEH_error_handler',
    '_gnu_exception_handler', '___w64_mingwthr_add_key_dtor',
    '___w64_mingwthr_remove_key_dtor', '__mingwthr_run_key_dtors',
    '_ValidateImageBase', '_FindPESection', '_FindPESectionByName',
    '__mingw_GetSectionForAddress', '__mingw_GetSectionCount',
    '_FindPESectionExec', '_GetPEImageBase', '_IsNonwritableInCurrentImage',
    '__mingw_enum_import_library_names', '___chkstk_ms',
    '_set_invalid_parameter_handler', '_get_invalid_parameter_handler',
    '_configthreadlocale', '__acrt_iob_func', '__C_specific_handler',
    '__iob_func', '_crt_atexit',
}


def _parse_guard_lines(ir_lines: List[str]) -> List[Tuple[str, str, int]]:
    """解析 guard 伪 IR 行 → (var, cond, bound)."""
    out = []
    for line in ir_lines:
        m = _RE_GUARD.search(line)
        if m:
            out.append((m.group(1), m.group(2), int(m.group(3), 0)))
    return out


def _guard_interval(cond: str, bound: int) -> Interval:
    if cond == '<':
        return Interval(0, bound - 1)
    if cond == '>':
        return Interval(bound + 1, Interval.top().hi)
    if cond == '==':
        return Interval(bound, bound)
    return Interval.top()


def detect_heap_overflow_hfp(ir_lines: List[str]) -> List:
    """分配器感知过滤 主入口: 返回含三态判定与证据的发现列表."""
    from .alloc_aware_verdict import HfpFinding
    taint = run_taint(ir_lines)
    findings: List[HfpFinding] = []
    env = {f.var: Interval(f.const_val, f.const_val)
           for f in taint.facts.values() if f.const_val is not None}

    guards = _parse_guard_lines(ir_lines)
    gset = GuardSet()
    alloc_vars = set()
    for i, line in enumerate(ir_lines):
        if line.startswith('# fn '):
            pass
        alloc = extract_alloc(line, i)
        if alloc and alloc.var:
            alloc_vars.add(alloc.var)
    for var, cond, bound in guards:
        # 过滤指针变量守卫: malloc 返回变量被 cmp 的是其空值检查,
        # 不是 size 上界 — 绑定到分配变量会错误收窄写区间
        if var in alloc_vars:
            continue
        iv = _guard_interval(cond, bound)
        if iv.hi < Interval.top().hi:
            gset.upper_bounds.setdefault(var, iv.hi)

    alloc_by_var = extract_alloc_exprs(ir_lines)
    cur_fn = ''
    for var, alloc in alloc_by_var.items():
        alloc.resolve_bound(env)
    # 定位每个 alloc 所属函数 (用于 CRT 过滤)
    fn_of_alloc: Dict[str, str] = {}
    cur_fn = ''
    for i, line in enumerate(ir_lines):
        if line.startswith('# fn '):
            cur_fn = line[5:].strip()
        alloc = extract_alloc(line, i)
        if alloc and alloc.var:
            fn_of_alloc[alloc.var] = cur_fn

    # 统计每 var 的 store 数 (循环累积写检测)
    store_count: Dict[str, int] = {}
    loop_store_vars: set = set()
    for line in ir_lines:
        m = re.search(r'store\s+(\w+)\s+', line)
        if m:
            store_count[m.group(1)] = store_count.get(m.group(1), 0) + 1
            if '# loop' in line:
                loop_store_vars.add(m.group(1))

    cur_fn = ''
    for i, line in enumerate(ir_lines):
        if line.startswith('# fn '):
            cur_fn = line[5:].strip()
        w = extract_write(line, i, alloc_by_var, taint, env)
        if w is None:
            continue
        if fn_of_alloc.get(w.base_var, '') in CRT_FUNCS:
            continue
        alloc = alloc_by_var[w.base_var]
        # 循环累积写: 同缓冲多条偏移 0 字节写 (编译器循环展开
        # 常见形态) 或循环内 store (# loop 标记) 无法证明单条
        # 不越界, 禁止 SAFE 抑制
        multi = (store_count.get(w.base_var, 0) >= 2
                 or w.base_var in loop_store_vars)
        findings.extend(_judge(alloc, w, gset, taint, ir_lines, multi))

    # 回绕可疑合成 finding: 分配大小 > 2^32 (32 位乘法回绕特征)
    # 且无写点关联 (经结构体字段间接寻址无法解析) 时, 直接判
    # POTENTIAL — 捕获 CVE-2022-22620 类"分配回绕 + 循环写"
    # 模式, 不依赖 store 关联
    # TODO: 2^32 阈值未覆盖 16 位乘法回绕 (32 位平台), 待扩充分支
    for var, alloc in alloc_by_var.items():
        if fn_of_alloc.get(var, '') in CRT_FUNCS:
            continue
        if store_count.get(var, 0) > 0:
            continue
        if not alloc.bound.symbolic and alloc.bound.requested > (1 << 32):
            from .alloc_aware_verdict import HfpFinding, VerdictResult
            synth = HfpWrite(pc=alloc.pc, base_var=var, offset=0,
                             write_iv=Interval.top())
            findings.append(HfpFinding(
                alloc, synth, Verdict.POTENTIAL, 0.50,
                [type('E', (), {'kind': 'wrap_suspicious',
                                'detail': f'alloc {alloc.size_expr} '
                                f'> 2^32, 乘法回绕可疑, 无写点关联'})()]))
    findings.sort(key=lambda f: -f.confidence)
    return findings


def _judge(alloc: HfpAlloc, w: HfpWrite, gset: GuardSet,
           taint: TaintState, ir_lines: List[str],
           multi_write: bool) -> List:
    """对单个写点做三态判定, 返回 finding 列表."""
    from .alloc_aware_verdict import HfpFinding
    wiv = gset.narrow(w.base_var, w.write_iv)
    lb = loop_bound_from_region(ir_lines, w.pc, backward=True)
    if w.call_fn == '' and lb and lb > 1:
        wiv = Interval(wiv.lo, wiv.hi * lb)
    alloc_t = taint_of_var(taint, alloc.size_expr) \
        if re.fullmatch(r'\w+', alloc.size_expr) else None
    write_t = taint_of_var(taint, w.size_expr) \
        if re.fullmatch(r'\w+', w.size_expr) else None
    res = judge_write(alloc.bound, wiv, w.offset, alloc_t, write_t)
    wrap_suspicious = (not alloc.bound.symbolic
                       and alloc.bound.requested > (1 << 32))
    if wrap_suspicious and res.verdict == Verdict.SAFE:
        res = VerdictResult(Verdict.POTENTIAL, 0.50, wiv, res.usable,
                            res.evidence)
    if multi_write and res.verdict == Verdict.SAFE:
        res = VerdictResult(Verdict.POTENTIAL, max(0.35, res.confidence),
                            wiv, res.usable, res.evidence)
    return [HfpFinding(alloc, w, res.verdict, res.confidence,
                       res.evidence)]


def suppress_and_report(findings: List) -> Tuple[List, dict]:
    """过滤 SAFE, 汇总统计."""
    stats = {'total': len(findings), 'safe': 0, 'potential': 0,
             'overflow': 0, 'suppressed': 0}
    kept = []
    for f in findings:
        stats[f.verdict.value.lower()] += 1
        if f.verdict == Verdict.SAFE:
            stats['suppressed'] += 1
            continue
        kept.append(f)
    return kept, stats