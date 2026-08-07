# Created: 2026-04-23 09:15:00
#
# allocation_tracker — 分配-写配对追踪器
# 在导入表层面识别 malloc/calloc/realloc 分配点与 memcpy/strcpy 写入点
# 的配对关系。核心假设: 若同一 DLL 中同时存在分配函数和写入函数,
# 且它们共享相同的 size 参数来源, 则存在堆溢出条件。
#
# 配对规则:
#   1. 同 DLL 内配对: 分配函数和写入函数在同一个 DLL 中→可能操作同一块内存
#   2. Size 参数同源: alloc_size 和 write_size 都来自外部输入→高风险
#   3. Size 参数非同源: alloc 用常量但 write 用输入→溢出条件

from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

from .size_arg_classifier import SizeSource, classify_size_arg


def _normalize(fname: str) -> str:
    return fname.lower().rstrip('aw')


# 分配函数集合 (返回堆指针)
_ALLOC_FUNCTIONS: Set[str] = {
    "malloc", "calloc", "realloc", "alloca",
    "HeapAlloc", "GlobalAlloc", "LocalAlloc",
    "new", "new[]",
}

# 写入函数集合 (操作已分配内存)
_WRITE_FUNCTIONS: Set[str] = {
    "memcpy", "memmove", "memset", "bcopy",
    "strcpy", "strcat", "strncpy", "strncat",
    "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "read", "fread", "recv",
    "WriteProcessMemory",
}


def track_allocation_pairs(imports: Dict, strings: List[str] = None,
                            checksec: Dict = None) -> Dict:
    """识别导入表中的分配-写配对。返回可能的堆溢出条件列表。

    每项包含:
    - alloc_func / write_func: 配对函数名
    - alloc_source / write_source: 各自的 size 参数来源分类
    - overflow_risk: 0-1 溢出风险评分
    - reason: 风险判定理由
    """
    api_set = set()
    dll_funcs: Dict[str, Set[str]] = defaultdict(set)
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for dll, funcs in all_imps.items():
            if isinstance(funcs, list):
                for f in funcs:
                    nf = _normalize(f)
                    api_set.add(nf)
                    dll_funcs[dll].add(nf)

    alloc_in_imports = api_set & _ALLOC_FUNCTIONS
    write_in_imports = api_set & _WRITE_FUNCTIONS

    if not alloc_in_imports or not write_in_imports:
        return {"pairs": [], "risk_summary": "无分配-写配对 (缺少分配函数或写入函数)",
                "alloc_functions": list(alloc_in_imports),
                "write_functions": list(write_in_imports)}

    # 分类 size 参数来源
    alloc_source = classify_size_arg("malloc", imports, strings)
    write_source = classify_size_arg("memcpy", imports, strings)

    pairs = []
    for alloc_f in sorted(alloc_in_imports):
        for write_f in sorted(write_in_imports):
            risk = 0.0
            reasons = []

            # 1. Size 同源且来自输入 → 极高风险
            if (alloc_source == SizeSource.INPUT_DERIVED and
                    write_source == SizeSource.INPUT_DERIVED):
                risk = 0.85
                reasons.append("alloc 和 write 的 size 参数都可能来自用户输入")
            # 2. Write 的 size 来自输入但 alloc 是常量 → 溢出风险
            elif (write_source == SizeSource.INPUT_DERIVED and
                    alloc_source == SizeSource.CONSTANT):
                risk = 0.90
                reasons.append("写 size 来自输入而分配 size 是常量→可能写越界")
            # 3. 同为常量 → 低风险
            elif (alloc_source == SizeSource.CONSTANT and
                    write_source == SizeSource.CONSTANT):
                risk = 0.10
                reasons.append("两者 size 均为编译期常量→通常是安全配对")
            # 4. 一方未知 → 中等风险
            elif (write_source == SizeSource.INPUT_DERIVED):
                risk = 0.60
                reasons.append("写 size 来自输入, 分配 size 来源不确定")
            else:
                risk = 0.30
                reasons.append("size 参数来源均不确定→无法排除风险")

            # 5. 同 DLL 内配对 → 风险增强
            same_dll = False
            for dll, funcs in dll_funcs.items():
                if alloc_f in funcs and write_f in funcs:
                    same_dll = True
                    break
            if same_dll:
                risk = min(1.0, risk + 0.10)
                reasons.append("同一 DLL 内配对→更可能操作同一缓冲区")

            # Fortify 缓解降权
            if checksec and checksec.get("fortify", checksec.get("fortify_source", False)):
                risk = max(0.05, risk - 0.20)
                reasons.append("FORTIFY_SOURCE 启用→缓解部分溢出")

            pairs.append({
                "alloc_func": alloc_f,
                "write_func": write_f,
                "alloc_size_source": alloc_source.name,
                "write_size_source": write_source.name,
                "overflow_risk": round(min(risk, 1.0), 2),
                "reason": "; ".join(reasons),
                "same_dll": same_dll,
            })

    pairs.sort(key=lambda p: p["overflow_risk"], reverse=True)

    high_risk = [p for p in pairs if p["overflow_risk"] >= 0.70]
    med_risk = [p for p in pairs if 0.35 <= p["overflow_risk"] < 0.70]
    low_risk = [p for p in pairs if p["overflow_risk"] < 0.35]

    return {
        "pairs": pairs,
        "high_risk_pairs": high_risk,
        "medium_risk_pairs": med_risk,
        "low_risk_pairs": low_risk,
        "alloc_functions": sorted(alloc_in_imports),
        "write_functions": sorted(write_in_imports),
        "risk_summary": (f"high={len(high_risk)} medium={len(med_risk)} "
                         f"low={len(low_risk)} (total={len(pairs)})"),
    }
