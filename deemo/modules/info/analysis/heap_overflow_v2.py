# analysis/heap_overflow_v2 — PSVR-HLM v3.0 堆溢出检测 (自包含)
# 管线: P0→P0.5(源码引导)→P1(VRA+循环感知)→P2(HLM)→P3(PFC)→P4(安全见证)
# P0-fallback: 无导入时从源码直接提取 alloc/write 函数对 (纯源码分析)
from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re
from .value_range_analyzer import (ValueRange, extract_value_ranges, check_heap_overflow_by_range)
from heap_layout_model import get_allocator_model
from path_feasibility_check import check_write_reachability

_ALLOC = {"malloc","calloc","realloc","alloca","__imp_malloc","__imp_calloc","__imp_realloc",
          "HeapAlloc","GlobalAlloc","LocalAlloc"}
_WRITE = {"memcpy","memmove","strcpy","strcat","strncpy","strncat","sprintf","snprintf",
          "vsprintf","read","fread","recv","gets","scanf","fgets","__imp_memcpy",
          "__imp_strcpy","__imp_sprintf","_read","wcscpy","_memcpy","_strcpy"}
_INPUT = {"recv","read","fread","scanf","gets","fgets","recvfrom","recvmsg","fscanf","getchar"}
_SAFE = {"snprintf","memcpy_s","strcpy_s","strncpy","strncat","__memcpy_chk",
         "__sprintf_chk","__fread_chk","__recv_chk"}

def _n(fname: str) -> str: return fname.lower().rstrip('aw')


def safety_filter(findings: List[Dict], checksec: Dict, imports: Dict) -> List[Dict]:
    """P4 安全性见证过滤: 基于导入表的安全变体与 FORTIFY 证据做置信度压制。"""
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(_n(f) for f in funcs)
    has_safe = bool(api_set & _SAFE)
    has_fort = checksec.get("fortify") or checksec.get("fortify_source") or \
               any("_chk" in f for f in api_set)
    for f in findings:
        if has_safe:
            f["confidence"] = round(max(0.05, f["confidence"] - 0.25), 2)
        if has_fort:
            f["confidence"] = round(max(0.05, f["confidence"] - 0.15), 2)
    return [f for f in findings if f["confidence"] >= 0.10]

# 源码安全模式检测 (P0.5)
def _source_safety(code: str, af: str, wf: str, alloc_expr: str, write_expr: str,
                   ranges: Dict) -> Tuple[float, str]:
    penalty, reasons = 0.0, []
    fn = _n(wf).replace("__imp_", "")
    # 1. 相同表达式 → 常量/sizeof/含sizeof宏=安全; 纯变量同名=危险
    if alloc_expr and write_expr and alloc_expr == write_expr:
        if bool(re.match(r'^(sizeof\s*\(|[0-9]+$)', alloc_expr)) or 'sizeof' in alloc_expr:
            penalty += 0.50; reasons.append("identical_safe_expr")
    # 2. 循环守卫
    if re.search(r'if\s*\([^)]*\+\s*\w+\s*[>]\s*\w+[^)]*\)\s*break', code):
        penalty += 0.45; reasons.append("loop_guard_break")
    # 3. 三元守卫/min() 上界
    if re.search(r'[?]\s*\w+\s*:', code) or 'min(' in code:
        penalty += 0.45; reasons.append("ternary_guard")
    # 4. realloc 安全增长 (写size匹配realloc新size)
    if 'realloc' in code.lower():
        rp, wp = code.lower().find('realloc'), code.lower().find(fn)
        if 0 <= rp < wp:
            rm = re.search(r'realloc\s*\([^,]+,\s*([^,)]+)\s*\)', code)
            if rm and rm.group(1).strip() == write_expr:
                penalty += 0.45; reasons.append("realloc_grow_safe")
    # 5. sizeof 匹配
    if alloc_expr and write_expr:
        sa = set(re.findall(r'sizeof\s*\(\s*\w+', alloc_expr))
        sw = set(re.findall(r'sizeof\s*\(\s*\w+', write_expr))
        if sa and sa == sw:
            penalty += 0.30; reasons.append("sizeof_match")
    return penalty, ";".join(reasons)

# 循环感知
def _in_loop(code: str, wf: str) -> bool:
    fn = _n(wf).replace("__imp_", "")
    m = re.search(rf'\b{fn}\s*\(', code)
    return bool(m and re.search(r'\b(for|while)\s*\(', code[:m.start()]))

def _has_loop_accumulation(code: str) -> bool:
    return bool(re.search(r'(\w+)\s*\+=\s*(\w+)\s*;', code))

# P0: 导入配对 (二进制模式)
def _make_pairs(imports: Dict, checksec: Dict) -> List[Dict]:
    api_set, dll_funcs = set(), {}
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for dll, funcs in all_imps.items():
            if isinstance(funcs, list):
                ns = {_n(f) for f in funcs}; api_set.update(ns); dll_funcs[dll] = ns
    a_in = {f for f in api_set if f in _ALLOC or
            any(a in f for a in ["malloc","calloc","realloc","heapalloc"])}
    w_in = {f for f in api_set if f in _WRITE or
            any(w in f for w in ["memcpy","strcpy","sprintf","memmove","strncpy",
                                 "recv","fread","gets","scanf","strcat","snprintf","fgets"])}
    if not a_in or not w_in: return []
    has_inp = bool(api_set & _INPUT)
    has_fort = checksec.get("fortify") or checksec.get("fortify_source") or \
               bool({f for f in api_set if "_chk" in f})
    pairs = []
    for af in sorted(a_in):
        for wf in sorted(w_in):
            risk = 0.85 if has_inp else 0.55; reason = "P0:pair"
            sd = any(af in fns and wf in fns for fns in dll_funcs.values())
            if sd: risk += 0.10; reason += "+sameDLL"
            if has_fort: risk = max(0.05, risk - 0.20); reason += "+FORTIFY"
            pairs.append({"alloc_func": af, "write_func": wf,
                "alloc_size_source": "INPUT_DERIVED" if has_inp else "UNKNOWN",
                "write_size_source": "INPUT_DERIVED" if has_inp else "UNKNOWN",
                "overflow_risk": round(min(risk, 1.0), 2),
                "reason": reason, "same_dll": sd})
    pairs.sort(key=lambda p: p["overflow_risk"], reverse=True)
    # 无源码的二进制路径仍为笛卡尔积配对, 可接入导入图做跨 DLL 关联
    return pairs

# P0-fallback: 源码直接提取函数对 (无二进制导入时使用)
def _make_pairs_from_code(code: str, checksec: Dict) -> List[Dict]:
    a_funcs = set(re.findall(r'\b(malloc|calloc|realloc|alloca|HeapAlloc)\s*\(', code))
    w_funcs = set(re.findall(r'\b(memcpy|memmove|strcpy|strcat|strncpy|strncat|sprintf|'
                              r'snprintf|vsprintf|read|fread|recv|gets|scanf|fgets|'
                              r'wcscpy|_read|_memcpy|_strcpy)\s*\(', code))
    if not a_funcs:
        return []
    has_inp = bool(re.search(r'\b(recv|read|fread|scanf|gets|fgets|fscanf|getchar)\s*\(', code))
    has_fort = checksec.get("fortify") or checksec.get("fortify_source") or \
               bool(re.search(r'\b\w+_chk\s*\(', code))
    pairs = []
    if w_funcs:
        for af in sorted(a_funcs):
            for wf in sorted(w_funcs):
                risk = 0.85 if has_inp else 0.55; reason = "P0:code_pair"
                if has_fort: risk = max(0.05, risk - 0.20); reason += "+FORTIFY"
                pairs.append({"alloc_func": af, "write_func": wf,
                    "alloc_size_source": "INPUT_DERIVED" if has_inp else "UNKNOWN",
                    "write_size_source": "INPUT_DERIVED" if has_inp else "UNKNOWN",
                    "overflow_risk": round(min(risk, 1.0), 2),
                    "reason": reason, "same_dll": True})
    # 手动逐字节循环写入检测: while/for体内arr[idx++]=...且arr由malloc分配
    for lm in re.finditer(r'(?:while|for)\s*\([^)]*\)\s*\{', code):
        d, p, body_s = 1, lm.end(), lm.end()
        while d > 0 and p < len(code):
            if code[p] == '{': d += 1
            elif code[p] == '}': d -= 1
            p += 1
        for am in re.finditer(r'(\w+)\s*\[[^\]]*\+\+[^\]]*\]\s*=', code[body_s:p-1]):
            an = am.group(1)
            if an not in a_funcs and re.search(rf'\b{an}\s*=\s*(?:malloc|calloc|realloc)\s*\(', code):
                pairs.append({"alloc_func": "manual_loop_alloc", "write_func": "manual_loop_write",
                    "alloc_size_source": "VARIABLE", "write_size_source": "LOOP_BOUNDED",
                    "overflow_risk": 0.90, "reason": "P0:manual_loop_write",
                    "same_dll": True, "manual_loop_target": an})
    pairs.sort(key=lambda p: p["overflow_risk"], reverse=True)
    return pairs

# 主检测入口
def detect_heap_overflow_v2(
    code: str = "", imports: Dict = None, strings: List[str] = None,
    checksec: Dict = None, min_confidence: float = 0.25, func_name: str = "",
) -> Dict:
    imports = imports or {}; strings = strings or []; checksec = checksec or {}
    alloc_model = get_allocator_model(checksec.get("arch", "x86_64"))
    raw_pairs = _make_pairs(imports, checksec)
    if not raw_pairs and code:
        raw_pairs = _make_pairs_from_code(code, checksec)
    if raw_pairs:
        try:
            from flow_pair_generator import correlate_to_v2_pairs
            raw_pairs = correlate_to_v2_pairs(code, raw_pairs)
        except Exception:
            pass
    if not raw_pairs:
        return {"findings": [], "stats": {"total": 0, "high_conf": 0, "medium_conf": 0,
            "low_conf": 0, "avg_confidence": 0}, "method": "PSVR-HLM-v3.0",
            "pipeline": ["P0: no pairs"], "fp_reduction_pct": 0.0,
            "vra_stats": {"pairs_analyzed": 0, "definitely_safe": 0,
                          "range_checked": 0, "layout_checked": 0},
            "false_positive_mitigations": {}}
    vra_stats = {"pairs_analyzed": len(raw_pairs), "definitely_safe": 0,
                 "range_checked": 0, "layout_checked": 0}
    pipeline_log, findings = [f"P0: {len(raw_pairs)} pairs"], []
    ranges = extract_value_ranges(code) if code else {}
    pipeline_log.append(f"P1(VRA): {len(ranges)} vars" if (code and ranges)
                       else "P1(VRA): skipped (no code)")
    # P0.5: 源码引导 — 惩罚导入中有但源码中无的函数
    sfx = {p for p in ["malloc","calloc","realloc","memcpy","strcpy","sprintf",
           "strncpy","memmove","read","recv","fread"] if code and re.search(r'\b'+p+r'\s*\(', code)}
    for pair in raw_pairs:
        base_conf, reason_parts = pair["overflow_risk"], [pair.get("reason", "")]
        if code and sfx:
            afn, wfn = _n(pair["alloc_func"]).replace("__imp_",""), _n(pair["write_func"]).replace("__imp_","")
            if afn not in sfx and wfn not in sfx:
                base_conf = max(0.03, base_conf - 0.40); reason_parts.append("src:neither")
            elif afn not in sfx:
                base_conf = max(0.03, base_conf - 0.25); reason_parts.append(f"src:!{afn}")
        # P1: VRA + 循环感知
        if code and ranges:
            vra_stats["range_checked"] += 1
            is_manual = pair.get("write_func") == "manual_loop_write"
            alloc_expr = pair.get("__alloc_expr__") or _infer_size_expr(code, pair["alloc_func"], True)
            write_expr = "unbounded" if is_manual else (pair.get("__write_expr__") or _infer_size_expr(code, pair["write_func"], False))
            alloc_range, write_range = _eval_range(alloc_expr, ranges), \
                ValueRange.top() if is_manual else _eval_range(write_expr, ranges)
            in_loop, loop_widened = (True, True) if is_manual else (_in_loop(code, pair["write_func"]), False)
            if in_loop and _has_loop_accumulation(code):
                write_range = ValueRange(write_range.lo, float("inf"))
                reason_parts.append("loop_accum:write→unbounded"); loop_widened = True
            overflow, vra_conf, vra_reason = check_heap_overflow_by_range(
                alloc_range, write_range)
            if not overflow and vra_conf < 0.10 and not in_loop:
                vra_stats["definitely_safe"] += 1; continue
            if not overflow:
                if not loop_widened and not (alloc_range.is_top and write_range.is_top):
                    base_conf = max(0.03, base_conf - 0.50)
                reason_parts.append(f"VRA:{vra_reason}")
            # P2: HLM
            if alloc_range.is_const and write_range.is_const:
                vra_stats["layout_checked"] += 1
                av, wv = alloc_range.const_value, write_range.const_value
                if av is not None and wv is not None:
                    lo, lc, lr = alloc_model.check_overflow_under_alignment(av, wv)
                    if not lo: base_conf = max(0.03, base_conf - 0.40); reason_parts.append(f"HLM:{lr}")
                    elif lc > 0.70: base_conf = min(0.95, base_conf + 0.10); reason_parts.append(f"HLM:{lr}")
            # P0.5b: 源码安全模式
            sp, sr = _source_safety(code, pair["alloc_func"], pair["write_func"],
                                     alloc_expr, write_expr, ranges)
            if sp > 0: base_conf = max(0.03, base_conf - sp); reason_parts.append(f"Safe:{sr}")
            # P3: PFC
        if code:
            try:
                pr = check_write_reachability(code, pair["write_func"], pair["alloc_func"])
                if pr.get("has_guard"):
                    base_conf = max(0.05, base_conf - pr["guard_strength"] * 0.35)
                    reason_parts.append(f"PFC:g={pr['guard_strength']:.2f}")
                if not pr.get("reachable", True):
                    base_conf = max(0.05, base_conf - 0.50); reason_parts.append("PFC:unreach")
            except Exception: pass
        if pair.get("alloc_size_source") == "CONSTANT" and pair.get("write_size_source") == "CONSTANT":
            base_conf = max(0.03, base_conf - 0.35)
        if "calloc" in pair["alloc_func"].lower(): base_conf = max(0.03, base_conf - 0.05)
        if base_conf >= min_confidence:
            findings.append({"type":"heap-overflow","cwe":"CWE-122",
                "alloc_func":pair["alloc_func"],"write_func":pair["write_func"],
                "alloc_size_source":pair.get("alloc_size_source","UNKNOWN"),
                "write_size_source":pair.get("write_size_source","UNKNOWN"),
                "confidence":round(base_conf,2),
                "severity":"High" if base_conf>0.60 else "Medium",
                "reason":"; ".join(reason_parts),"same_dll":pair.get("same_dll",False)})
    # P4: 安全见证
    if checksec:
        from v2_safety_filter import safety_filter
        findings = safety_filter(findings, checksec, imports)
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    hi = sum(1 for f in findings if f["confidence"] >= 0.70)
    med = sum(1 for f in findings if 0.35 <= f["confidence"] < 0.70)
    lo = sum(1 for f in findings if f["confidence"] < 0.35)
    fp_red = (1.0 - len(findings) / max(len(raw_pairs), 1)) * 100
    pipeline_log.append(f"Final: {len(findings)}f ({hi}H/{med}M/{lo}L)")
    tot = len(findings)
    return {"findings":findings,"stats":{"total":tot,"high_conf":hi,"medium_conf":med,
        "low_conf":lo,"avg_confidence":round(sum(f["confidence"] for f in findings)/max(tot,1),3)},
        "alloc_write_pairs_total":len(raw_pairs),"method":"PSVR-HLM-v3.0",
        "pipeline":pipeline_log,"fp_reduction_pct":round(fp_red,1),
        "vra_stats":vra_stats,"false_positive_mitigations":vra_stats}

# 辅助函数
def _infer_size_expr(code: str, func_name: str, is_alloc: bool) -> str:
    fn = _n(func_name).replace("__imp_", "")
    if is_alloc:
        if fn == "calloc":
            m = re.search(r"(?:calloc|__imp_calloc)\s*\(\s*([^,]+)\s*,\s*([^,)]+)\s*\)", code)
            if m: return f"{m.group(1).strip()} * {m.group(2).strip()}"
        if fn == "realloc":
            m = re.search(r"(?:realloc|__imp_realloc)\s*\([^,]+,\s*([^,)]+)\s*\)", code)
            if m: return m.group(1).strip()
    else:
        if fn in ("memcpy","memmove","strncpy","strncat"):
            m = re.search(rf"(?:{fn}|__imp_{fn})\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)", code)
            if m: return m.group(1).strip()
        if fn in ("read","recv","_read","fread"):
            m = re.search(rf"(?:{fn}|__imp_{fn})\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)", code)
            if m: return m.group(1).strip()
        if fn in ("strcpy","strcat","sprintf","gets"): return "unbounded"
    # 通用回退
    m = re.search(r"(?:malloc|calloc|realloc|__imp_malloc|__imp_calloc|__imp_realloc|"
                  r"memcpy|strcpy|sprintf|strncpy|memmove|read|recv|fread)"
                  r"\s*\(\s*([^,)]+)\s*\)", code)
    if m:
        if is_alloc: return m.group(1).strip()
        m2 = re.search(r"(?:memcpy|memmove|strncpy)\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)", code)
        if m2: return m2.group(1).strip()
        m3 = re.search(r"(?:read|recv|fread)\s*\([^,]+,\s*[^,]+,\s*([^,)]+)\s*\)", code)
        if m3: return m3.group(1).strip()
    return "unknown"

def _eval_range(expr: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    expr = expr.strip()
    if expr in ("unbounded", "unknown"): return ValueRange.top()
    try: return ValueRange.const(int(expr))
    except ValueError: pass
    smap = {"char":1,"short":2,"int":4,"long":4,"long long":8,"float":4,"double":8,
            "void*":4,"size_t":4}
    m = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if m: return ValueRange.const(smap.get(m.group(1).strip().replace(" ",""), 4))
    m = re.match(r"(\w+)\s*\*\s*(\w+)", expr)
    if m:
        a = _parse_or_top(m.group(1), ranges)
        b = _parse_or_top(m.group(2), ranges)
        return a.mul(b)
    m = re.match(r"(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if m:
        t = m.group(2).strip().replace(" ","")
        return ranges.get(m.group(1), ValueRange.top()).mul(ValueRange.const(smap.get(t, 4)))
    return ranges.get(expr, ValueRange.top())

def _parse_or_top(s: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    try: return ValueRange.const(int(s))
    except ValueError: return ranges.get(s, ValueRange.top())
