# 堆溢出检测统一编排 — 5阶段流水线 + 4级FP过滤
"""Phase 1: alloc扫描+taint → Phase 2: 区间抽象 → Phase 3: 路径守卫+可行性
Phase 4: ptmalloc对齐 → Phase 5: 综合判定+置信度。
2026-08-06: 数据流追踪独立为heap_dataflow, alloc-write配对从25行窗口→函数级窗口+数据流验证, 路径守卫收紧上界注入Filter3/4。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class HeapOverflowFinding:
    """单个堆溢出检测发现。"""
    alloc_func: str = ""
    alloc_line: int = 0
    alloc_size_arg: str = ""
    alloc_size_val: int = 0
    write_func: str = ""
    write_line: int = 0
    write_size: int = 0
    is_tainted: bool = False
    taint_source: str = ""
    taint_path_len: int = 0
    size_lower_bound: int = 0
    size_upper_bound: int = 2**31 - 1
    has_bounds_check: bool = False
    path_feasible: bool = True
    path_guard_count: int = 0
    effective_upper_bound: int = 2**31 - 1
    glibc_usable_size: int = 0
    overflow_bytes: int = 0
    is_vulnerable: bool = False
    is_false_positive: bool = False
    confidence: float = 0.0
    severity: str = "UNKNOWN"
    reason: str = ""
    fp_source: str = ""
    dataflow_coupled: bool = False


@dataclass
class HeapOverflowReport:
    """堆溢出检测综合报告。"""
    function_name: str = ""
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    uncertain: int = 0
    fp_reduction_pct: float = 0.0
    phase_contributions: Dict[str, int] = field(default_factory=dict)
    findings: List[HeapOverflowFinding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'total': self.total_findings,
            'tp': self.true_positives,
            'fp': self.false_positives,
            'uncertain': self.uncertain,
            'fp_reduction': round(self.fp_reduction_pct, 1),
            'phase_contributions': self.phase_contributions,
            'findings': [
                {'alloc': f.alloc_func, 'alloc_line': f.alloc_line,
                 'write_size': f.write_size, 'is_vuln': f.is_vulnerable,
                 'is_fp': f.is_false_positive, 'confidence': round(f.confidence, 2),
                 'severity': f.severity, 'fp_source': f.fp_source,
                 'dataflow_coupled': f.dataflow_coupled,
                 'reason': f.reason[:150]}
                for f in self.findings[:20]
            ],
        }


# 统一检测器

class HeapOverflowDetector:
    """堆溢出检测统一编排器 — 5阶段流水线 + 数据流耦合验证。"""

    def __init__(self, enable_write_side: bool = True):
        self._components = None
        # 写侧双向区间交汇(核心创新)开关; 关闭时回退原Filter 4行为
        self.enable_write_side = enable_write_side

    def _init_components(self):
        if self._components is not None:
            return
        from .alloc_size_tracker import AllocSiteScanner, DemandDrivenTaintTracker
        from .heap_constraint_solver import IntervalAbstractor, OverflowSatisfiabilitySolver
        from .heap_path_sensitivity import PathAwareOverflowAnalyzer
        from .heap_allocator_model import AlignmentConstraintFilter
        self._components = {
            'scanner': AllocSiteScanner(),
            'taint_tracker': DemandDrivenTaintTracker(),
            'interval_abs': IntervalAbstractor(),
            'overflow_solver': OverflowSatisfiabilitySolver(),
            'path_analyzer': PathAwareOverflowAnalyzer(),
            'alignment_filter': AlignmentConstraintFilter(),
        }

    def detect(self, asm_lines: List[str],
               function_name: str = "") -> HeapOverflowReport:
        """执行完整5阶段堆溢出检测流水线。"""
        self._init_components()
        report = HeapOverflowReport(function_name=function_name)

        from .heap_write_scanner import find_write_sites
        from .heap_dataflow import (parse_function_bounds, trace_alloc_store,
                                     alloc_write_related)

        alloc_sites = self._components['scanner'].scan(asm_lines)
        write_sites = find_write_sites(asm_lines)
        if not alloc_sites:
            return report

        func_bounds = parse_function_bounds(asm_lines)
        # 预计算每个alloc的返回值存储槽
        alloc_slots = {
            a.line_index: trace_alloc_store(asm_lines, a.line_index)
            for a in alloc_sites}
        # 预计算每个alloc所在的函数名 (用于CRT过滤等)
        from .heap_dataflow import line_function
        alloc_func_names = {
            a.line_index: line_function(a.line_index, func_bounds)
            for a in alloc_sites}

        # CRT启动/清理代码中的malloc→memcpy并非用户输入驱动, 跳过
        _CRT_KNOWN = {'duplicate_ppstrings', 'do_pseudo_reloc',
                      'mark_section_writable', 'restore_modified_sections',
                      'register_frame_ctor', 'check_managed_app',
                      'dtoa_lock', 'dtoa_lock_cleanup', 'dtoa_unlock',
                      'safe_flush', 'fallback_IsDBCSLeadByteEx',
                      'init_fpreg_ldouble', '__write_memory',
                      '_pei386_runtime_relocator', '_gnu_exception_handler',
                      'bitstob', 'b2d_D2A'}
        findings = []
        for alloc in alloc_sites:
            alloc_fn = alloc_func_names.get(alloc.line_index, '')
            if alloc_fn.startswith('_') or alloc_fn in _CRT_KNOWN:
                continue
            is_tainted, source, path_len = self._components['taint_tracker'].trace(
                asm_lines, alloc.line_index, alloc.size_operand)

            lower, upper, has_bound = self._components['interval_abs'].extract_bounds(
                asm_lines, alloc.size_operand, alloc.line_index)

            from .heap_constraint_solver import SizeConstraint
            size_c = SizeConstraint(
                lower=lower, upper=upper, is_tainted=is_tainted,
                has_explicit_bound=has_bound, bound_value=upper if has_bound else 0)

            alloc_slot = alloc_slots.get(alloc.line_index, '')

            for w in write_sites:
                if w['line'] <= alloc.line_index:
                    continue
                if not alloc_write_related(
                        asm_lines, alloc.line_index, w['line'],
                        func_bounds, alloc_slot):
                    continue
                findings.append(self._analyze_pair(
                    asm_lines, alloc, size_c, w, is_tainted,
                    source, path_len, has_bound, alloc_slot,
                    alloc_func_names.get(alloc.line_index, '')))

            # 循环写检测: 逐字节/逐元素循环写(非memcpy sink)
            # 仅当alloc受控时启用, 避免对常量alloc引入误报
            if is_tainted:
                try:
                    from .loop_write_detector import LoopWriteDetector
                    lwd = LoopWriteDetector()
                    for lw in lwd.detect(
                            asm_lines, alloc.line_index,
                            size_c.lower, size_c.upper, is_tainted):
                        if not lw.may_overflow:
                            continue  # 守卫证明安全或无溢出 → 不告警
                        finding = self._loop_write_finding(
                            alloc, lw, source, path_len, has_bound)
                        if finding:
                            findings.append(finding)
                except Exception:
                    pass  # 循环写检测失败不阻塞主流程

        # 汇总
        report.total_findings = len(findings)
        report.true_positives = sum(1 for f in findings if f.is_vulnerable)
        report.false_positives = sum(1 for f in findings if f.is_false_positive)
        report.uncertain = sum(1 for f in findings
                              if not f.is_vulnerable and not f.is_false_positive)
        if report.total_findings > 0:
            report.fp_reduction_pct = report.false_positives / report.total_findings * 100
        report.phase_contributions = {
            'constant_size_filtered': sum(1 for f in findings if f.fp_source == 'constant_alloc_size'),
            'path_infeasible_filtered': sum(1 for f in findings if f.fp_source == 'path_infeasible'),
            'alignment_filtered': sum(1 for f in findings if f.fp_source == 'alignment_constraint'),
            'interval_filtered': sum(1 for f in findings if f.fp_source == 'interval_bound'),
            'confirmed_tp': sum(1 for f in findings if f.is_vulnerable and f.fp_source == ''),
        }
        report.findings = findings
        return report

# 单对分析: 4级过滤

    def _loop_write_finding(self, alloc, lw, source, path_len, has_bound
                            ) -> Optional[HeapOverflowFinding]:
        """将循环写结果转为HeapOverflowFinding。"""
        finding = HeapOverflowFinding(
            alloc_func=alloc.alloc_func,
            alloc_line=alloc.line_index,
            alloc_size_arg=alloc.size_operand,
            alloc_size_val=alloc.size_constant_value,
            write_func='loop_write',
            write_line=lw.loop_start,
            write_size=lw.cap_value or 0,
            is_tainted=True,
            taint_source=source,
            taint_path_len=path_len,
            size_lower_bound=alloc.size_lower_bound,
            size_upper_bound=alloc.size_upper_bound,
            has_bounds_check=has_bound,
        )
        finding.is_vulnerable = True
        finding.confidence = lw.confidence
        finding.severity = 'HIGH' if lw.confidence >= 0.5 else 'MEDIUM'
        finding.reason = f'[loop-write] {lw.reason}'
        return finding

    def _analyze_pair(self, asm_lines, alloc, size_c, w, is_tainted,
                      source, path_len, has_bound,
                      alloc_slot: str = "",
                      alloc_func_name: str = "") -> HeapOverflowFinding:

        from .heap_dataflow import trace_write_dst

        finding = HeapOverflowFinding(
            alloc_func=alloc.alloc_func,
            alloc_line=alloc.line_index,
            alloc_size_arg=alloc.size_operand,
            alloc_size_val=alloc.size_constant_value,
            write_func=w['func'],
            write_line=w['line'],
            write_size=w['write_size'],
            is_tainted=is_tainted,
            taint_source=source,
            taint_path_len=path_len,
            size_lower_bound=size_c.lower,
            size_upper_bound=size_c.upper,
            has_bounds_check=has_bound,
        )

        if alloc_slot:
            w_dst = trace_write_dst(asm_lines, w['line'])
            finding.dataflow_coupled = bool(
                w_dst and (w_dst == alloc_slot or
                           alloc_slot in w_dst or w_dst in alloc_slot))

        w_size = w['write_size']

        # ── 深度表达式分析 (w_size未知或unbounded write时, 在filter chain之前运行) ──
        # CRT函数(启动/清理代码)中的malloc→memcpy并非用户输入驱动, 跳过深度分析
        # MinGW CRT: _开头 + 特定内部函数
        _CRT_KNOWN = {'duplicate_ppstrings', 'do_pseudo_reloc',
                      'mark_section_writable', 'restore_modified_sections',
                      'register_frame_ctor', 'check_managed_app',
                      'dtoa_lock', 'dtoa_lock_cleanup', 'dtoa_unlock',
                      'safe_flush', 'fallback_IsDBCSLeadByteEx',
                      'init_fpreg_ldouble', '__write_memory',
                      '_pei386_runtime_relocator', '_gnu_exception_handler',
                      'bitstob', 'b2d_D2A'}
        _is_crt = bool(alloc_func_name and (
            alloc_func_name.startswith('_') or
            alloc_func_name in _CRT_KNOWN))
        from .heap_expr_tracker import _is_unbounded_write as _is_unbounded
        is_unbounded_w = _is_unbounded(w['func'])
        # 表达式分析入口: alloc被污染 或 w_size未知时进入
        # 常量alloc + w_size==0: 检查write是否来自污点源
        if ((is_tainted and not alloc.size_is_constant) or w_size == 0) and not _is_crt:
            try:
                from .heap_expr_tracker import (
                    build_alloc_expr, build_write_expr, compare_for_overflow,
                    detect_strlen_strcpy_off_by_one)
                from .heap_expr_engine import ExprKind
                lowered = [l.strip().lower().replace(',', ' ') for l in asm_lines]
                a_val, a_t, a_expr = build_alloc_expr(asm_lines, lowered, alloc.line_index)
                w_val, w_t, w_expr = build_write_expr(
                    asm_lines, lowered, w['line'], w['func'])
                if a_expr and w_expr:
                    # 常量alloc + 污点write: 比较alloc常量与write上界。
                    # write上界受cmova/cmov约束(如cmova rax,rdx cap 200)。
                    # eval_max已包含cap_value → 可直接比较。
                    # 仅在scanner确认alloc为常量时才信任表达式(const可能来自
                    # max(x,1)的fallback路径, 此时scanner看到的是寄存器→非const)
                    if (not a_expr.has_taint() and w_expr.has_taint()
                            and alloc.size_is_constant):
                        a_val = a_expr.eval_min()
                        w_max = w_expr.eval_max()
                        if a_val > 0 and w_max > a_val:
                            finding.is_vulnerable = True
                            finding.overflow_bytes = w_max - a_val
                            finding.confidence = 0.55
                            finding.severity = 'HIGH'
                            finding.reason = (
                                f'[expr] const_alloc={a_val}B vs '
                                f'tainted_write(max={w_max}B) → 潜在溢出')
                            return finding
                        # w_max <= a_val: cmova等约束使write不超出alloc
                        # 回退到filter chain确认, 触发w_size_unknown
                        w_val = 0
                    expr_overflow = compare_for_overflow(a_expr, w_expr)
                    if expr_overflow > 0:
                        finding.is_vulnerable = True
                        finding.overflow_bytes = expr_overflow
                        finding.confidence = 0.85
                        finding.severity = 'HIGH'
                        finding.reason = (
                            f'[expr] alloc={a_expr.to_str()} vs '
                            f'write={w_expr.to_str()} → 溢出{expr_overflow}B')
                        return finding
                    elif a_expr.has_taint() and w_expr.has_taint():
                        alloc_root = a_expr.get_taint_root()
                        write_root = w_expr.get_taint_root()
                        if (alloc_root and write_root
                                and alloc_root.taint_label == write_root.taint_label):
                            from .heap_expr_engine import _extract_const_offset
                            a_off = _extract_const_offset(a_expr)
                            w_off = _extract_const_offset(w_expr)
                            # 检查是否有MUL节点: 乘法因子使纯偏移比较无效
                            # 例: alloc=TAINT+54 vs write=TAINT*2
                            #   → w_off=0 <= a_off=54 但 TAINT>54时write更大
                            def _has_mul(e):
                                if e.kind == ExprKind.MUL: return True
                                if e.child: return _has_mul(e.child)
                                return False
                            if _has_mul(a_expr) or _has_mul(w_expr):
                                pass  # MUL→偏移比较无效, 回退到filter chain
                            elif a_off == 0 and w_off == 0:
                                # 偏移均为0 → 检查cap/floor约束能否证明安全
                                # 例: alloc=TAINT(floor=256), write=TAINT(cap=28)
                                # write_max(28) ≤ alloc_min(256) → 确定安全
                                w_max = w_expr.eval_max()
                                a_min = a_expr.eval_min()
                                if w_max <= a_min and a_min > 0:
                                    finding.is_false_positive = True
                                    finding.fp_source = 'expression_analysis'
                                    finding.confidence = 0.90
                                    finding.severity = 'NONE'
                                    finding.reason = (
                                        f'[expr] alloc={a_expr.to_str()} vs '
                                        f'write={w_expr.to_str()} → '
                                        f'write_max({w_max})≤alloc_min({a_min}) 安全')
                                    return finding
                                pass  # 无法确定, 回退到filter chain
                            elif w_off <= a_off:
                                finding.is_false_positive = True
                                finding.fp_source = 'expression_analysis'
                                finding.confidence = 0.85
                                finding.severity = 'NONE'
                                finding.reason = (
                                    f'[expr] alloc={a_expr.to_str()} vs '
                                    f'write={w_expr.to_str()} → 安全')
                                return finding
                        # 不同污点源 → 独立外部输入, 无法直接比较
                        # 不在此处判定, 回退到filter chain用路径守卫+区间求解器综合判定
                        # 将w_size清零以触发w_size_unknown路径(跳过对齐过滤)
                        pass
                # strlen↔strcpy off-by-one 检测
                if (is_unbounded_w
                        and detect_strlen_strcpy_off_by_one(
                            asm_lines, lowered, alloc.line_index, w['line'])):
                    finding.is_vulnerable = True
                    finding.overflow_bytes = 1
                    finding.confidence = 0.85
                    finding.severity = 'HIGH'
                    finding.reason = (
                        f'[expr] strlen↔strcpy off-by-one: '
                        f'malloc(strlen(src)) + strcpy(dst, src) → 溢出1B')
                    return finding
                # 表达式分析成功但无法确定 → 用推断的size继续filter chain
                # 若write被污染, w_val是最小值(如strlen+1→1), 不能直接用于对齐比较
                # 此时设w_size为0触发w_size_unknown路径, 跳过对齐过滤, 用区间求解器判定
                if w_val > 0:
                    if w_expr and w_expr.has_taint():
                        # 污点write的最小值不可靠, 强制w_size=0触发w_size_unknown
                        # 跳过对齐过滤, 用区间求解器+路径守卫综合判定
                        w_size = 0
                        finding.write_size = w_val  # 记录最小值供参考
                    else:
                        w_size = w_val
                        finding.write_size = w_val
                elif w_val == 0 and w_expr and w_expr.has_taint():
                    # 污点TAINT节点的eval_min=0 (最小值=0不意味着安全)
                    # 例: jmp-over-tainted → 跳过fallback常量, 识别污点源
                    # 但val=0, 不能用于对齐比较 → 强制w_size=0触发w_size_unknown
                    w_size = 0
            except Exception:
                pass  # 表达式分析失败, 继续正常filter chain

        # Filter 1: alloc常量且≥write_size → FP
        # 但w_size==0表示写入大小未确定(unbounded write或未知memcpy size),
        # 此时不能因"常量 >= 0"而判定安全
        if (alloc.size_is_constant and alloc.size_constant_value > 0
                and w_size > 0):
            if alloc.size_constant_value >= w_size:
                finding.is_false_positive = True
                finding.fp_source = 'constant_alloc_size'
                finding.confidence = 0.95
                finding.severity = 'NONE'
                finding.reason = (
                    f'malloc({alloc.size_constant_value})常量 ≥ '
                    f'{w["func"]}({w_size}) → 无溢出')
                return finding

        # Filter 2: 路径可行性 (仅tainted时执行)
        # 路径守卫收紧的上界必须注入后续过滤, 否则FP002等有guard的样本误报
        # w_size==0表示写入大小未确定(无法追踪或污点表达式仅知最小值)
        # 跳过Filter 3的对齐精确比较, 用Filter 4区间求解器判定
        w_size_unknown = (w_size == 0)
        effective_lower, effective_upper = size_c.lower, size_c.upper
        if is_tainted:
            from .heap_dataflow import resolve_size_reg
            size_reg = resolve_size_reg(asm_lines, alloc.line_index)
            pr = self._components['path_analyzer'].analyze(
                asm_lines, alloc.line_index, size_reg, w_size,
                base_lower=size_c.lower, base_upper=size_c.upper)
            finding.path_feasible = pr['path_feasible']
            finding.path_guard_count = pr['guards_collected']
            finding.effective_upper_bound = pr['effective_bounds'][1]
            if not pr['path_feasible']:
                finding.is_false_positive = True
                finding.fp_source = 'path_infeasible'
                finding.confidence = pr['fp_confidence']
                finding.severity = 'NONE'
                finding.reason = pr['reason']
                return finding
            # 路径守卫收紧的上界 → 更新effective区间
            if pr['effective_bounds'][1] < effective_upper:
                effective_upper = pr['effective_bounds'][1]
            if pr['effective_bounds'][0] > effective_lower:
                effective_lower = pr['effective_bounds'][0]

        # Filter 3: glibc对齐约束 (使用路径守卫收紧后的区间)
        # w_size==0时跳过对齐检查, 因为写入大小未确定
        if not w_size_unknown:
            ar = self._components['alignment_filter'].filter(
                (effective_lower, effective_upper), w_size)
            finding.glibc_usable_size = ar['usable_size']
            finding.overflow_bytes = ar['overflow_bytes']
            finding.severity = ar['severity']
            if not ar['keep']:
                finding.is_false_positive = True
                finding.fp_source = 'alignment_constraint'
                finding.confidence = 0.90
                finding.reason = ar['reason']
                return finding

        # Filter 4: 区间约束可满足性 (使用effective区间)
        # 写侧检查: w_size==0(未知)时先做双向区间交汇, 避免求解器
        # "alloc.lower>=0"恒真误判cannot_overflow导致真实溢出被滤。
        # 仅在write侧上界可知时介入; 其余情况继续原Filter链。
        if w_size_unknown:
            try:
                from .write_side_check import WriteSideCheck
                wsc = WriteSideCheck()
                wsc_res = wsc.run(
                    asm_lines, alloc, size_c, w, is_tainted,
                    effective_lower, effective_upper, alloc_func_name)
                if self.enable_write_side and wsc_res.activated and wsc_res.final_verdict == 'fp':
                    finding.is_false_positive = True
                    finding.fp_source = wsc_res.finding_update.get('fp_source', 'write_side_bounds')
                    finding.confidence = wsc_res.finding_update.get('confidence', 0.85)
                    finding.severity = wsc_res.finding_update.get('severity', 'NONE')
                    finding.reason = wsc_res.finding_update.get('reason', '')
                    finding.write_size = wsc_res.finding_update.get('write_size', 0)
                    return finding
                if self.enable_write_side and wsc_res.activated and wsc_res.final_verdict == 'vulnerable':
                    finding.is_vulnerable = True
                    finding.confidence = wsc_res.finding_update.get('confidence', 0.85)
                    finding.severity = wsc_res.finding_update.get('severity', 'HIGH')
                    finding.reason = wsc_res.finding_update.get('reason', '')
                    finding.write_size = wsc_res.finding_update.get('write_size', 0)
                    finding.overflow_bytes = wsc_res.finding_update.get('overflow_bytes', 0)
                    if finding.dataflow_coupled:
                        finding.confidence = min(finding.confidence + 0.15, 1.0)
                    return finding
                if self.enable_write_side and wsc_res.activated:
                    # 区间重叠: 用置信度提示更新, 继续原链
                    w_unknown_hint = wsc_res.finding_update.get('confidence_hint')
                    finding.write_size = wsc_res.finding_update.get('write_size', 0)
            except Exception:
                pass  # 写侧检查失败, 回退原Filter 4

        from .heap_constraint_solver import SizeConstraint as SC
        tightened_c = SC(
            lower=effective_lower, upper=effective_upper,
            is_tainted=is_tainted,
            has_explicit_bound=(has_bound or effective_upper < size_c.upper),
            bound_value=effective_upper)
        verdict = self._components['overflow_solver'].solve(
            tightened_c, w_size, w['size_is_constant'])
        if verdict.cannot_overflow:
            finding.is_false_positive = True
            finding.fp_source = 'interval_bound'
            finding.confidence = verdict.confidence
            finding.severity = 'NONE'
            finding.reason = verdict.reason
        elif verdict.will_overflow:
            finding.is_vulnerable = True
            finding.confidence = verdict.confidence
            finding.reason = verdict.reason
        else:
            # 路径守卫可能已在Filter2收紧了上界 → 用tightened_c判断
            path_has_bound = tightened_c.has_explicit_bound
            if is_tainted and not path_has_bound:
                finding.is_vulnerable = True
                finding.confidence = 0.55
                finding.reason = verdict.reason
            elif is_tainted and path_has_bound:
                # 有守卫但区间仍重叠: alloc∈[0,256], write=200
                # alloc可能小于200 → 不确定, 保守标记为潜在风险但低置信
                finding.confidence = 0.20
                finding.reason = verdict.reason
            else:
                finding.is_false_positive = True
                finding.fp_source = 'interval_bound'
                finding.confidence = 0.10
                finding.reason = verdict.reason

        if finding.dataflow_coupled and finding.is_vulnerable:
            finding.confidence = min(finding.confidence + 0.15, 1.0)

        return finding
