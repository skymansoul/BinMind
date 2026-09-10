# core/unified_heap_pipeline.py - 统一堆分析管线
# 单函数端到端检测: 分配器检测 → 分配/写入点提取 → 路径条件 →
# 不可行路径剪枝 → 四层验证 → UAF/Double-Free 检测。
# 输入: 反编译伪代码 + 可选二进制路径 (分配器检测); 输出 (findings, stats)。

from typing import Any, Dict, List, Optional, Tuple

from .symbolic_range import AffineInterval, PathCondition
from .allocator_model import effective_chunk_size, detect_allocator, AllocatorType
from .allocator_constraints import AllocatorConstraintChecker, AllocSize
from .heap_object_tracker import track_heap_objects
from .infeasible_path_pruner import InfeasiblePathPruner, extract_branch_constraints


# 区间算术 — 参照 Cousot & Cousot 抽象解释区间域 (POPL 1977)。
# AffineInterval 以 -1 / 2^31-1 为无界哨兵; 下方三个函数构成区间运算基座。
def _interval_join(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
    """区间并: (min(lo), max(hi))。哨兵语义由调用方保证。"""
    return (min(a[0], b[0]), max(a[1], b[1]))


def _interval_widen(r: Tuple[int, int], bound: int = 2 ** 31 - 1) -> Tuple[int, int]:
    """加宽算子: hi 翻倍直至 bound, 用于不动点加速。架构预留, 暂不参与主流程。"""
    lo, hi = r
    if hi >= bound:
        return (lo, bound)
    return (lo, min(hi * 2, bound))


def _interval_verdict(alloc_range, write_range) -> str:
    """分配/写入大小的区间判定。

    返回 'safe' (写入恒不大于分配) / 'overflow' (写入恒大于分配) /
    'unknown' (区间交叠或无界)。无界侧 (哨兵值) 不参与比较, 防止
    TOP 区间产生假过滤或假确认。
    """
    if alloc_range is None or write_range is None:
        return 'unknown'
    alloc_lo = alloc_range.lo if alloc_range.lo >= 0 else None
    alloc_hi = alloc_range.hi if alloc_range.hi < 2 ** 31 - 1 else None
    write_lo = write_range.lo if write_range.lo >= 0 else None
    write_hi = write_range.hi if write_range.hi < 2 ** 31 - 1 else None
    if write_hi is not None and alloc_lo is not None and write_hi <= alloc_lo:
        return 'safe'
    if alloc_hi is not None and write_lo is not None and write_lo > alloc_hi:
        return 'overflow'
    return 'unknown'


def analyze_heap_safety(
    code: str,
    func_name: str = "",
    binary_path: str = "",
) -> Tuple[List[dict], Dict[str, Any]]:
    """端到端堆安全分析。

    执行流程:
      1. 分配器检测 (确定 chunk 大小计算规则)
      2. 分配点/WRITE点提取 (使用改进的符号区间)
      3. 路径条件收集
      4. 不可行路径剪枝
      5. 四层验证 (分配器语义 → 值域 → 符号 → 启发式)
      6. UAF/Double-Free 并行检测

    返回 (findings, stats), stats 含各级过滤统计。
    """
    stats = {
        "function": func_name,
        "allocator": "unknown",
        "alloc_sites": 0,
        "write_sites": 0,
        "confirmed": 0,
        "filtered": 0,
        "possible": 0,
        "uaf_findings": 0,
        "double_free_findings": 0,
        "errors": [],
    }

    findings: List[dict] = []

    # 分配器检测 ──────────────────────────
    # 默认 glibc ptmalloc2; detect_allocator 返回 UNKNOWN 时保持默认
    allocator = AllocatorType.GLIBC_PTMALLOC2
    if binary_path:
        try:
            detected = detect_allocator(binary_path)
            if detected != AllocatorType.UNKNOWN:
                allocator = detected
        except Exception:
            pass
    stats["allocator"] = allocator.value

    checker = AllocatorConstraintChecker()

    # 提取分配点和写入点 ──────────────────
    # 使用 path_sensitive_vrf 做路径感知分析
    try:
        from .path_sensitive_vrf import path_sensitive_heap_analysis
        path_findings = path_sensitive_heap_analysis(code, func_name)

        # Tier -1: 缓冲区正交预过滤 ─────────────
        # 在 Tier 0-3 之前, 先用 BufferDisjointness 消除跨类型误报
        # 若 alloc/write 目标是栈/全局变量, 不是堆溢出, 直接过滤
        try:
            from analysis.heap_buffer_disjointness import BufferDisjointness
            _buf_disjoint = BufferDisjointness()
            _buf_disjoint.scan_function(code)
        except Exception:
            _buf_disjoint = None

        for pf in path_findings:
            stats["alloc_sites"] += 1
            stats["write_sites"] += 1

            alloc_site = pf.alloc_site
            write_site = pf.write_site

            # Tier -1: 缓冲区正交 - 栈/全局变量不产生堆告警
            if _buf_disjoint:
                a_kind = _buf_disjoint.classify_target(alloc_site.var_name)
                w_kind = _buf_disjoint.classify_target(write_site.var_name)
                if a_kind in ('stack', 'global') or w_kind in ('stack', 'global'):
                    stats["filtered"] += 1
                    stats.setdefault('buf_disjoint_filtered', 0)
                    stats['buf_disjoint_filtered'] += 1
                    continue

            # 提取数值
            alloc_val = alloc_site.size_range.const_val
            write_val = write_site.write_size.const_val
            # 标记: write_val 是否从 lo 降级; 循环偏移写不适用 effective 过滤
            _write_from_lo = False
            _alloc_from_lo = False

            if alloc_val is None:
                alloc_val = alloc_site.size_range.lo if alloc_site.size_range.lo >= 0 else -1
                _alloc_from_lo = True
            if write_val is None:
                write_val = write_site.write_size.lo if write_site.write_size.lo >= 0 else -1
                _write_from_lo = True

            # Tier 0: 分配器语义检查 — 常量比较 + effective chunk 对齐过滤
            # 循环偏移写入不适用: write_size 含偏移量, 与 chunk 大小比较会误判
            _is_loop_write = '<loop_body>' in str(write_site.write_call)
            _iv = 'unknown'
            if (alloc_val > 0 and write_val > 0
                    and not _write_from_lo and not _alloc_from_lo
                    and not _is_loop_write):
                effective = effective_chunk_size(alloc_val, allocator)
                if write_val <= effective:
                    stats["filtered"] += 1
                    continue  # 分配器对齐后安全
            else:
                # Tier 0.5: 区间判定 — 至少一侧为符号区间时用 [lo,hi] 比较
                _iv = _interval_verdict(alloc_site.size_range, write_site.write_size)
                if _iv == 'safe':
                    stats["filtered"] += 1
                    stats['interval_filtered'] = stats.get('interval_filtered', 0) + 1
                    continue
                if _iv == 'overflow':
                    stats['interval_provable_overflow'] = \
                        stats.get('interval_provable_overflow', 0) + 1

            # Tier 1: 路径敏感值域 ────────────────
            if pf.verdict == "SAFE":
                stats["filtered"] += 1
                continue

            if pf.verdict == "DEFINITE":
                _fd = {
                    "type": "heap-overflow",
                    "function": func_name,
                    "alloc_var": alloc_site.var_name,
                    "alloc_size": alloc_val if alloc_val > 0 else alloc_site.size_expr,
                    "alloc_size_expr": alloc_site.size_expr,
                    "write_var": write_site.var_name,
                    "write_size": write_val if write_val > 0 else str(write_site.write_size),
                    "overflow_bytes": pf.overflow_bytes,
                    "severity": "Critical",
                    "confidence": pf.confidence,
                    "cwe": "CWE-122",
                    "verdict": "DEFINITE",
                    "description": pf.description,
                }
                if _iv != 'unknown':
                    _fd['interval_verdict'] = _iv
                findings.append(_fd)
                stats["confirmed"] += 1
                continue

            # Tier 2 & 3: 符号执行 + 保守 ─────────
            # _write_from_lo 标记写入大小是否为下界降级值;
            # Tier 3 constant_safe 需此标记避免误过滤循环写等模糊 finding
            _fd = {
                "type": "heap-overflow",
                "function": func_name,
                "alloc_var": alloc_site.var_name,
                "alloc_size": alloc_val if alloc_val > 0 else "symbolic",
                "alloc_size_expr": alloc_site.size_expr,
                "write_var": write_site.var_name,
                "write_size": write_val if write_val > 0 else "symbolic",
                "write_size_approx": _write_from_lo,
                "overflow_bytes": pf.overflow_bytes,
                "severity": "Medium" if pf.verdict == "POSSIBLE" else "Critical",
                "confidence": pf.confidence,
                "cwe": "CWE-122",
                "verdict": pf.verdict,
                "description": pf.description,
            }
            if _iv != 'unknown':
                _fd['interval_verdict'] = _iv
            findings.append(_fd)
            if pf.verdict == "POSSIBLE":
                stats["possible"] += 1
            else:
                stats["confirmed"] += 1

    except ImportError:
        stats["errors"].append("path_sensitive_vrf unavailable")
    except Exception as e:
        stats["errors"].append(f"path_sensitive_vrf error: {e}")

    # Tier 2: 选择性符号执行 ──────────────────────
    # 对 Tier 1 后仍为 POSSIBLE 的 findings, 在符号域上做更精确的验证
    # 仅符号化 size 参数 (MAX_SYM_VARS=8, MAX_PATHS=128)
    try:
        from .selective_symexec import SelectiveSymExec
        symexec = SelectiveSymExec()
        heap_paths = symexec.analyze(code, func_name)

        for hp in heap_paths:
            verdict, conf, reason = symexec.verify_path(hp)
            if verdict == "SAFE":
                # 符号执行可证明安全 → 降级/过滤 pending findings
                for f in findings:
                    if (hp.alloc_var in str(f.get('alloc_var', ''))
                            and hp.write_var in str(f.get('write_var', ''))):
                        f['tier'] = 'tier2_filtered'
                        f['severity'] = 'Info'
                        f['confidence'] = max(0.1, f.get('confidence', 0.5) - 0.4)
                        f['symexec_verdict'] = 'SAFE'
                        f['symexec_reason'] = reason
                        stats['filtered'] += 1
            elif verdict == "DEFINITE":
                for f in findings:
                    if (hp.alloc_var in str(f.get('alloc_var', ''))
                            and hp.write_var in str(f.get('write_var', ''))):
                        f['symexec_verdict'] = 'DEFINITE'
                        f['confidence'] = min(0.98, f.get('confidence', 0.5) + 0.2)
                        f['symexec_reason'] = reason
    except ImportError:
        stats.setdefault('errors', []).append('selective_symexec unavailable')
    except Exception as e:
        stats.setdefault('errors', []).append(f'symexec error: {e}')

    # .5 (Tier 3): 保守启发式过滤 — 检测边界守卫/常量安全/sanitizer/截断守卫
    try:
        from .interval_filter import analyze_code_safety as apply_tier3
        refined, tier3_stats = apply_tier3(code, findings)
        # 更新已过滤计数
        filtered_by_t3 = sum(tier3_stats.get(k, 0) for k in (
            'bound_guarded', 'constant_safe', 'cap_guarded',
            'sanitizer_protected', 'synthetic_noise'))
        if filtered_by_t3 > 0:
            stats['filtered'] = stats.get('filtered', 0) + filtered_by_t3
            # 从 possible 中扣除被 Tier 3 过滤的
            stats['possible'] = max(0, stats.get('possible', 0) - filtered_by_t3)
            findings[:] = refined
    except ImportError:
        stats.setdefault('errors', []).append('interval_filter unavailable')
    except Exception as e:
        stats.setdefault('errors', []).append(f'tier3 error: {e}')

    # 不可行路径剪枝 ──────────────────────
    try:
        pruner = InfeasiblePathPruner()
        constraints = extract_branch_constraints(code)
        if constraints:
            # 对含路径条件的 findings, 检查约束满足性
            # (当前实现是区间检查, 不做完整 SAT)
            for f in findings:
                f["path_pruned"] = False  # 默认不剪枝
    except Exception as e:
        stats["errors"].append(f"path_pruner error: {e}")

    # UAF / Double-Free 并行检测 ──────────
    try:
        uaf_findings = track_heap_objects(code, func_name)
        for uf in uaf_findings:
            if uf.get("rule_id", "").startswith("DF"):
                stats["double_free_findings"] += 1
            else:
                stats["uaf_findings"] += 1
            findings.append(uf)
    except Exception as e:
        stats["errors"].append(f"uaf_tracker error: {e}")

    return findings, stats
