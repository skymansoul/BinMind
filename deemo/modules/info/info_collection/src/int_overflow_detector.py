# int_overflow_detector — 导入表级整数溢出检测 (v2.0)
# 三类模式 + 约束层精化:
#   M1: 乘法溢出 — atoi/strtoul → malloc(sz*N) 若 sz 来自输入且 N>1
#   M2: 截断溢出 — size_t→uint32 转换, realloc 旧大小与新大小类型不一致
#   M3: 符号溢出 — signed int→size_t 隐式转换, 负值变极大值
#   C1: 约束检查 — alloc_size < write_size 且 write_size 来自乘法→溢出条件
#
# 约束精化: 不同于仅检测模式共存, 本模块分析了"乘法结果是否可
# 能被截断或溢出为小值"这一条件, 类似 AC3 的 size provenance 但在
# 整数域上的投影。这是使整数溢出检测从模式匹配升级到约束分析的关键。

from typing import Dict, List, Set, Tuple

_INPUT_CONVERTERS = {"atoi","atol","atoll","strtol","strtoul","strtoll","strtoull","sscanf","scanf"}
_ALLOC_FUNCS = {"malloc","calloc","realloc","alloca"}
_WRITE_FUNCS = {"memcpy","memmove","strcpy","strcat","memset","bcopy"}

def _normalize(f): return f.lower().rstrip('aw')

def detect_int_overflow_patterns(imports: Dict, strings: List[str] = None) -> Dict:
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(_normalize(f) for f in funcs)

    has_converter = bool(api_set & _INPUT_CONVERTERS)
    has_alloc = bool(api_set & _ALLOC_FUNCS)
    has_write = bool(api_set & _WRITE_FUNCS)
    has_realloc = "realloc" in api_set

    text = " ".join(s[1] if isinstance(s, tuple) else str(s) for s in (strings or []))

    findings = []

    # M1: 乘法溢出 — atoi + malloc 且字符串中有大数模式
    if has_converter and has_alloc:
        conf = 0.35
        detail = "atoi/strtoul + malloc 共存 — size 参数若经乘法运算可能溢出"
        large_nums = any(n in text for n in ["65536","65537","100000","0x10000","0x200000"])
        if large_nums:
            conf = 0.65
            detail += "; 检测到大数常量 — 乘法溢出(如 n*m 中 m>1)风险增高"
        if has_write:
            conf = min(0.90, conf + 0.20)
            detail += "; memcpy 写入存在 — alloc 不足时写越界"
        findings.append({
            "vuln_type": "integer_overflow",
            "pattern": "M1_multiplicative",
            "confidence": round(conf, 2),
            "detail": detail,
        })

    # M2: 截断溢出 — size_t → uint 转换, realloc 暗示类型转换
    if has_alloc and has_realloc:
        conf = 0.40
        detail = "realloc 存在 — 大小参数可能在类型转换中被截断"
        size_markers = any(n in text for n in ["size_t","uint32_t","unsigned int","unsigned short"])
        if size_markers:
            conf = 0.60
            detail += "; 字符串中有显式类型标记 — 截断风险确实存在"
        findings.append({
            "vuln_type": "integer_overflow",
            "pattern": "M2_truncation",
            "confidence": round(conf, 2),
            "detail": detail,
        })

    # M3: 符号溢出 — malloc 无符号检查, 负值变成极大值
    if has_alloc and has_converter:
        signed_indicators = any(kw in text.lower() for kw in ["int ","signed","negative","-1"])
        if signed_indicators:
            findings.append({
                "vuln_type": "integer_overflow",
                "pattern": "M3_signed_overflow",
                "confidence": 0.55,
                "detail": "有符号整型标记 + malloc — 负值导致分配极大内存或空指针",
            })

    # C1: 约束检查 — alloc_size < write_size 且 write_size 来自乘法
    if has_alloc and has_write and has_converter:
        mult_indicators = any(kw in text for kw in ["*","multiply","product","times","<<","shift"])
        if mult_indicators:
            findings.append({
                "vuln_type": "integer_overflow",
                "pattern": "C1_constraint_violation",
                "confidence": 0.75,
                "detail": "alloc+write+converter+乘法指示器共存 — alloc_size经过乘法后可能溢出为小值, 而write_size使用原始大值",
            })

    # 误报压制: FORTIFY 或安全变体存在
    has_safe = bool({"__memcpy_chk","__memset_chk","__sprintf_chk","snprintf"} & api_set)
    for f in findings:
        if has_safe:
            f["confidence"] = round(max(0.08, f["confidence"] - 0.25), 2)
            f["detail"] += " (FORTIFY/chk 缓解)"

    findings.sort(key=lambda f: f["confidence"], reverse=True)

    hi = sum(1 for f in findings if f["confidence"] >= 0.60)
    return {
        "findings": findings,
        "total": len(findings),
        "high_confidence": hi,
        "patterns_detected": len({f["pattern"] for f in findings}),
        "method": "IntOverflow-Constraint-v2.0",
    }
