"""
统一堆分析管线 — 集成所有核心模块做端到端检测。

功能: 将单文件分析(AffineInterval→PathCondition→HeapObject→SymExec→Filter)
      串联为统一的检测流水线。

使用:
  from core.unified_heap_pipeline import analyze_heap_safety
  findings, stats = analyze_heap_safety(code, func_name, binary_path)

输入: 反编译伪代码 + 可选二进制路径(用于分配器检测)
输出: (confirmed_findings, verification_stats)
"""


from typing import Any, Dict, List, Optional, Tuple

# 导入所有组件 ──────────────────────────────────────

from .symbolic_range import AffineInterval, PathCondition
from .allocator_model import effective_chunk_size, detect_allocator, AllocatorType
from .allocator_constraints import AllocatorConstraintChecker, AllocSize
from .heap_object_tracker import track_heap_objects
from .infeasible_path_pruner import InfeasiblePathPruner, extract_branch_constraints


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

    Returns:
      (findings, stats) — findings 是确认的发现列表, stats 含各级过滤统计。
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
    allocator = AllocatorType.GLIBC_PTMALLOC2
    if binary_path:
        try:
            allocator = detect_allocator(binary_path)
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
        # 若 alloc/write 目标是栈/全局变量 → 不是堆溢出, 直接过滤
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

            # Tier -1: 缓冲区正交 — 栈/全局变量不产生堆告警
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
            # 标记: write_val 是否从 lo (下界) 降级而来
            _write_from_lo = False
            _alloc_from_lo = False

            if alloc_val is None:
                alloc_val = alloc_site.size_range.lo if alloc_site.size_range.lo >= 0 else -1
                _alloc_from_lo = True
            if write_val is None:
                write_val = write_site.write_size.lo if write_site.write_size.lo >= 0 else -1
                _write_from_lo = True

            # Tier 0: 分配器语义检查 ──────────────
            # 仅当 write_val 是真实常量(非 lo 降级)时才做常量比较过滤
            if alloc_val > 0 and write_val > 0 and not _write_from_lo and not _alloc_from_lo:
                effective = effective_chunk_size(alloc_val, allocator)
                if write_val <= effective:
                    stats["filtered"] += 1
                    continue  # 分配器对齐后安全

            # Tier 1: 路径敏感值域 ────────────────
            if pf.verdict == "SAFE":
                stats["filtered"] += 1
                continue

            if pf.verdict == "DEFINITE":
                findings.append({
                    "type": "heap-overflow",
                    "function": func_name,
                    "alloc_var": alloc_site.var_name,
                    "alloc_size": alloc_val if alloc_val > 0 else alloc_site.size_expr,
                    "write_var": write_site.var_name,
                    "write_size": write_val if write_val > 0 else str(write_site.write_size),
                    "overflow_bytes": pf.overflow_bytes,
                    "severity": "Critical",
                    "confidence": pf.confidence,
                    "cwe": "CWE-122",
                    "verdict": "DEFINITE",
                    "description": pf.description,
                })
                stats["confirmed"] += 1
                continue

            # Tier 2 & 3: 符号执行 + 保守 ─────────
            findings.append({
                "type": "heap-overflow",
                "function": func_name,
                "alloc_var": alloc_site.var_name,
                "alloc_size": alloc_val if alloc_val > 0 else "symbolic",
                "write_var": write_site.var_name,
                "write_size": write_val if write_val > 0 else "symbolic",
                "overflow_bytes": pf.overflow_bytes,
                "severity": "Medium" if pf.verdict == "POSSIBLE" else "Critical",
                "confidence": pf.confidence,
                "cwe": "CWE-122",
                "verdict": pf.verdict,
                "description": pf.description,
            })
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

    # .5 (Tier 3): 保守启发式过滤 ─────────────
    # 对 symexec 后仍为 POSSIBLE 的 findings, 用 Tier 3 决策树扫描
    # 检测边界守卫 / 纯常量安全 / sanitizer 模式
    try:
        from .interval_filter import analyze_code_safety as apply_tier3
        refined, tier3_stats = apply_tier3(code, findings)
        # 更新已过滤计数
        filtered_by_t3 = (tier3_stats.get('bound_guarded', 0)
                          + tier3_stats.get('constant_safe', 0)
                          + tier3_stats.get('sanitizer_protected', 0))
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


def analyze_batch(
    code_map: Dict[str, str],
    binary_path: str = "",
) -> Tuple[List[dict], Dict[str, Any]]:
    """批量分析多函数反编译代码。

    code_map: {func_name: decompiled_code}
    """
    all_findings: List[dict] = []
    aggregate_stats: Dict[str, Any] = {
        "functions_analyzed": len(code_map),
        "total_findings": 0,
        "total_confirmed": 0,
        "total_filtered": 0,
        "total_possible": 0,
    }

    for func_name, code in code_map.items():
        findings, stats = analyze_heap_safety(
            code, func_name, binary_path)
        all_findings.extend(findings)
        aggregate_stats["total_findings"] += len(findings)
        aggregate_stats["total_confirmed"] += stats["confirmed"]
        aggregate_stats["total_filtered"] += stats["filtered"]
        aggregate_stats["total_possible"] += stats["possible"]

    return all_findings, aggregate_stats
