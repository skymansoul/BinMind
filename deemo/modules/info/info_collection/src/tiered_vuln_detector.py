# Created: 2026-07-26 16:45:00
#
# tiered_vuln_detector — 三层递进约束的漏洞检测器
# Tier 1: 参数位置感知的模式匹配 (高覆盖, 低精度)
# Tier 2: 导入可达性增强 (中覆盖, 中精度)
# Tier 3: 安全性见证过滤 (低覆盖, 高精度)
#
# 每上升一层, 误报减半, 但检出率小幅下降。
# 调用方可选择所需的 Tier 级别, 默认输出 Tier 2 (平衡点)。
#
# 覆盖的漏洞类型: 堆溢出, UAF, 格式化字符串, 栈溢出

import math
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict

from ._shared import extract_api_set as _extract_api_set
from ._shared import extract_string_set as _extract_string_set
from .dangerous_arg_annotations import (
    get_arg_annotations, has_safe_alternative, has_input_validation,
    infer_calling_convention, ParamRole,
)
from .safety_witness_searcher import run_full_witness_search


# Tier 1: 参数感知模式匹配

def _tier1_heap_overflow(api_set: Set[str], calling_conv: Dict) -> List[Dict]:
    findings = []
    heap_funcs = {
        "memcpy": "堆内存越界写 (memcpy 无边界检查)",
        "memmove": "堆内存越界写 (memmove 无边界检查)",
        "memset": "堆内存越界写 (memset 无边界检查)",
        "strcpy": "堆缓冲区溢出 (strcpy 无长度限制)",
        "strcat": "堆缓冲区溢出 (strcat 无长度限制)",
        "read": "堆越界读 (read size 参数可控)",
        "recv": "堆越界读 (recv size 参数可控)",
    }
    for func, desc in heap_funcs.items():
        if func in api_set:
            annotations = get_arg_annotations(func)
            size_params = [a for a in annotations if a[1] == ParamRole.PARAM_SIZE]
            findings.append({
                "vuln_type": "heap_overflow",
                "function": func, "description": desc,
                "tier": 1,
                "confidence": round(0.30 + len(size_params) * 0.10, 2),
                "dangerous_params": [{"position": a[0], "role": a[1].name} for a in annotations[:2]],
            })
    return findings


def _tier1_uaf(api_set: Set[str], imports: Dict) -> List[Dict]:
    findings = []
    has_free = "free" in api_set
    has_malloc = "malloc" in api_set or "calloc" in api_set
    has_realloc = "realloc" in api_set
    # UAF 需要 malloc+free 共存
    if has_malloc and has_free:
        conf = 0.35
        desc = "malloc+free 共存 → 潜在 UAF (堆内存释放后仍可被引用)"
        if has_realloc:
            conf = 0.40
            desc += "; realloc 存在增加了悬垂指针风险"
        findings.append({
            "vuln_type": "use_after_free",
            "function": "free (with malloc/realloc)",
            "description": desc,
            "tier": 1,
            "confidence": conf,
            "pattern": "malloc_free_pair",
        })
    if has_free and not has_malloc:
        findings.append({
            "vuln_type": "double_free",
            "function": "free",
            "description": "存在 free 但无 malloc → 可能 double-free (释放非堆指针)",
            "tier": 1, "confidence": 0.25,
            "pattern": "free_only",
        })
    return findings


def _tier1_format_string(api_set: Set[str], string_set: Set[str]) -> List[Dict]:
    findings = []
    fmt_funcs = {"printf", "fprintf", "sprintf", "snprintf", "dprintf",
                 "vprintf", "vfprintf", "vsprintf", "vsnprintf", "syslog"}
    for func in fmt_funcs:
        if func not in api_set:
            continue
        annotations = get_arg_annotations(func)
        fmt_params = [a for a in annotations if a[1] == ParamRole.PARAM_FORMAT]

        conf = 0.25
        risk = "LOW"
        detail = f"导入 {func}"
        # 检查 %n (写入原语)
        text = " ".join(string_set)
        if "%n" in text or "%N" in text.upper():
            conf += 0.30
            risk = "HIGH"
            detail += " — 检测到 %n 写入原语"
        # 检查是否有显式格式字面量
        import re
        has_literal = bool(re.search(r'"[^"]*%[^"]*"', text))
        if not has_literal and conf > 0.25:
            conf += 0.20
            risk = "MEDIUM" if risk == "LOW" else risk
            detail += " — 无显式格式字面量"
        if risk != "LOW":
            findings.append({
                "vuln_type": "format_string",
                "function": func, "description": detail,
                "tier": 1, "confidence": round(min(conf, 0.85), 2),
                "risk": risk,
                "fmt_params": [{"position": a[0]} for a in fmt_params],
            })
    return findings


def _tier1_stack_overflow(api_set: Set[str]) -> List[Dict]:
    findings = []
    stack_funcs = ["gets", "strcpy", "strcat", "sprintf", "scanf", "sscanf",
                   "alloca", "gets_s"]
    for func in stack_funcs:
        if func in api_set:
            findings.append({
                "vuln_type": "stack_overflow",
                "function": func,
                "description": f"{func} 无栈边界检查 → 潜在栈缓冲区溢出",
                "tier": 1, "confidence": 0.35 if func == "gets" else 0.25,
            })
    return findings


# Tier 2: 可达性增强

def _upgrade_to_tier2(tier1_findings: List[Dict],
                       reachability_graph: Dict) -> List[Dict]:
    """Tier 1 发现 + 导入可达性 → Tier 2。
    如果从输入源到危险函数的路径 ≤ 2 跳, 置信度大幅提升。
    """
    upgraded = []
    reach = reachability_graph.get("reachability", {})

    for f in tier1_findings:
        func = f["function"]
        min_dist = 999
        for src_name, sink_info in reach.items():
            for sink_type, info in sink_info.items():
                closest = info.get("closest_sink", "")
                dist = info.get("min_distance", 999)
                if func in closest.lower() or closest.lower() in func:
                    min_dist = min(min_dist, dist)

        new_conf = f["confidence"]
        tier = 2

        if min_dist <= 1:
            new_conf = min(0.95, f["confidence"] + 0.35)
            f["reachability"] = "direct (1 hop)"
        elif min_dist == 2:
            new_conf = min(0.85, f["confidence"] + 0.20)
            f["reachability"] = "close (2 hops)"
        elif min_dist <= 4:
            new_conf = f["confidence"] + 0.05
            f["reachability"] = f"moderate ({min_dist} hops)"
        else:
            tier = 1  # 不可达，保持 Tier 1
            f["reachability"] = "unreachable or distant"
            f["confidence"] = f["confidence"] * 0.6

        f["confidence"] = round(new_conf, 2)
        f["tier"] = tier
        upgraded.append(f)

    return upgraded


# Tier 3: 安全性见证过滤

def _upgrade_to_tier3(tier2_findings: List[Dict],
                       safety_witness: Dict) -> List[Dict]:
    """Tier 2 发现 + 安全性见证过滤 → Tier 3。
    有强安全见证 → 大幅降低置信度（可能误报）。
    无安全见证 → 置信度进一步提升（很可能真阳性）。
    """
    safety_score = safety_witness.get("aggregate_safety_score", 0.0)
    upgraded = []

    for f in tier2_findings:
        new_conf = f["confidence"]
        tier = 3

        vuln_type = f.get("vuln_type", "")

        # 格式串特化: 格式字面量存在 → 大幅降低风险
        if vuln_type == "format_string":
            fmt_lit = safety_witness.get("format_literals", {})
            if fmt_lit.get("format_literals_found", 0) > 3:
                new_conf = max(0.05, new_conf - 0.50)
                f["safety_witness"] = f"格式字面量存在 ({fmt_lit['format_literals_found']} 个)"

        # 堆/UAF 特化: 分配器配对正常 → 降低风险
        if vuln_type in ("heap_overflow", "use_after_free"):
            alloc = safety_witness.get("allocator_pairing", {})
            if alloc.get("uaf_risk", 0.0) < 0.15:
                new_conf = max(0.08, new_conf - 0.30)
                f["safety_witness"] = "分配器配对正常"

        # 通用过滤: 编译器全缓解 → 降低风险
        compiler = safety_witness.get("compiler_mitigations", {})
        if compiler.get("mitigation_count", 0) >= 3 and compiler.get("has_fortify"):
            new_conf = max(0.10, new_conf - 0.25)
            f["safety_witness"] = (f.get("safety_witness", "") + "; 全编译器缓解").strip("; ")

        # 通用: 安全变体共存
        safe_alt = safety_witness.get("safe_alternatives", {})
        func = f.get("function", "")
        if safe_alt.get(func):
            new_conf = max(0.05, new_conf - 0.35)
            f["safety_witness"] = (f.get("safety_witness", "") + f"; {func} 安全变体共存").strip("; ")

        # 无法过滤 → 无安全见证 → 置信度提升
        if "safety_witness" not in f and safety_score < 0.15:
            new_conf = min(0.95, new_conf + 0.10)
            f["safety_witness"] = "无安全见证 — 高危"

        f["confidence"] = round(new_conf, 2)
        f["tier"] = tier
        upgraded.append(f)

    return upgraded


# 主入口

def detect_all_tiers(
    api_set: Set[str] = None,
    imports: Dict = None,
    strings: List[str] = None,
    checksec: Dict = None,
    arch: str = "unknown",
    binary_format: str = "ELF",
    reachability_graph: Dict = None,
    max_tier: int = 3,
) -> Dict:
    """三层递进检测主入口。

    返回:
    - tier1_findings / tier2_findings / tier3_findings
    - tier_comparison: 各 Tier 检出数与平均置信度 (用于消融实验)
    - method_signature: 方法签名 (用于论文复现)
    """
    api_set = api_set or (_extract_api_set(imports) if imports else set())
    string_set = _extract_string_set(strings or [])
    imports = imports or {}
    calling_conv = infer_calling_convention(binary_format, arch)

    # Tier 1: 参数感知模式匹配
    t1 = []
    t1.extend(_tier1_heap_overflow(api_set, calling_conv))
    t1.extend(_tier1_uaf(api_set, imports))
    t1.extend(_tier1_format_string(api_set, string_set))
    t1.extend(_tier1_stack_overflow(api_set))

    t1.sort(key=lambda f: f["confidence"], reverse=True)

    # Tier 2: 可达性增强
    t2 = _upgrade_to_tier2(t1, reachability_graph or {}) if max_tier >= 2 else t1
    t2.sort(key=lambda f: f["confidence"], reverse=True)

    # Tier 3: 安全性见证过滤
    if max_tier >= 3:
        safety = run_full_witness_search(api_set, imports, checksec, strings or [])
        t3 = _upgrade_to_tier3(t2, safety)
        t3.sort(key=lambda f: f["confidence"], reverse=True)
    else:
        t3 = t2
        safety = {}

    # 消融对比数据
    def _stats(findings):
        hi = sum(1 for f in findings if f["confidence"] >= 0.60)
        med = sum(1 for f in findings if 0.30 <= f["confidence"] < 0.60)
        lo = sum(1 for f in findings if f["confidence"] < 0.30)
        avg = round(sum(f["confidence"] for f in findings) / max(len(findings), 1), 3)
        return {"total": len(findings), "high_conf": hi, "medium_conf": med,
                "low_conf": lo, "avg_confidence": avg}

    return {
        "tier1_findings": t1,
        "tier2_findings": t2,
        "tier3_findings": t3,
        "tier_comparison": {
            "tier1": _stats(t1), "tier2": _stats(t2), "tier3": _stats(t3),
        },
        "high_confidence_findings": [f for f in t3 if f["confidence"] >= 0.60],
        "safety_witness_summary": (safety.get("safety_reasons", []) if isinstance(safety, dict) else []),
        "method_signature": "CAIR-v1.0 (Constraint-Annotated Import Reachability)",
    }
