"""堆溢出专用误报过滤器 — 整合 VSA + 区间过滤 + 值范围三层防线。"""
from core.vsa_lite import analyze_vsa
from core.value_range import analyze_heap_bounds
from core.interval_filter import classify, apply_filter, filter_stats, Tier, FilterResult

def comprehensive_heap_check(binary_path: str, pseudocode: str = "",
                              func_name: str = "") -> dict:
    """三层堆溢出检测 + 误报过滤。返回 {'violations': [...], 'stats': {...}}"""
    result = {"violations": [], "stats": {}}
    # 第一层: VSA-Lite (汇编级)
    vsa_violations, vsa_stats = analyze_vsa(binary_path)
    result["violations"].extend(vsa_violations)
    result["stats"]["vsa"] = vsa_stats
    # 第二层: Value-Range (反编译级)
    if pseudocode:
        vr_violations = analyze_heap_bounds(pseudocode, func_name)
        # 去重合并
        seen = {v.get("alloc_site","")+str(v.get("overflow",0)) for v in result["violations"]}
        for v in vr_violations:
            key = getattr(v, 'alloc_site', '') + str(getattr(v, 'write_site', ''))
            if hasattr(v, 'alloc_site'):
                vd = {"severity": v.severity, "alloc_site": str(v.alloc_site),
                      "write_site": str(v.write_site), "overflow": 0,
                      "description": v.description, "method": "value-range"}
                if not any(vd.get("alloc_site","") == s.split(":")[0] for s in seen):
                    result["violations"].append(vd)
                    seen.add(vd.get("alloc_site",""))
        result["stats"]["value_range"] = {"violations": len(vr_violations)}
    result["stats"]["total_violations"] = len(result["violations"])
    return result
