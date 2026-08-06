# Created: 2025-08-01 20:15:37
#
# posture_regression — 跨版本安全态势退化检测
# 不关注功能变更，只追踪安全态势退化：保护移除、RWX新增、导入表面扩大、CFG结构突变
# 与 DiffRays/ghidriff 的区别：输出安全回归报告而非代码差异

import math
from typing import Dict, List, Tuple, Optional, Set
from enum import Enum


class RegressionSeverity(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


_REGRESSION_CHECKS = {
    # (维度, 检查项, 字段路径, 方向: "down"=值减小是退化, "up"=值增大是退化)
    "compile_time": [
        ("stack_canary_removed", "checksec.canary", "down"),
        ("fortify_source_disabled", "checksec.fortify", "down"),
        ("pie_disabled", "checksec.pie", "down"),
        ("nx_disabled", "checksec.nx", "down"),
        ("relro_weakened", "checksec.relro", "down"),
        ("full_relro_lost", "checksec.relro", "down"),
    ],
    "segment_layout": [
        ("rwx_segment_added", "sections", "rwx_check"),
        ("exec_stack_added", "checksec.noexecstack", "down"),
        ("guard_page_removed", "segment_risk.guard_page_coverage", "down"),
    ],
    "import_surface": [
        ("new_dangerous_imports", "imports.dangerous_functions", "new_items"),
        ("new_sensitive_dll", "imports.all_imports", "new_sensitive_dlls"),
        ("import_count_increased", "imports.all_imports", "up_count"),
    ],
    "structural": [
        ("cfg_entropy_shift", "cfg_fingerprint.composite_score", "large_shift"),
        ("code_ratio_anomaly", "cfg_fingerprint.section_entropy.layout_anomaly_score", "up"),
    ],
}

# 已知敏感 DLL：被 exploit 常用作代码执行载体
_SENSITIVE_DLLS = {
    "kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll",
    "ws2_32.dll", "wininet.dll", "urlmon.dll", "msvcrt.dll",
    "libc.so.6", "libpthread.so.0", "libdl.so.2",
    "libSystem.B.dylib", "libc++.1.dylib",
}


def _get_nested(d: Dict, path: str, default=None):
    """点分隔路径访问嵌套字典，如 'checksec.canary'。"""
    _parts = path.split(".")
    _cur = d
    for _p in _parts:
        if isinstance(_cur, dict):
            _cur = _cur.get(_p)
            if _cur is None:
                return default
        else:
            return default
    return _cur


def _check_protection_regression(
    prev_info: Dict,
    curr_info: Dict,
) -> List[Dict]:
    """检测编译期保护退化。遍历 _REGRESSION_CHECKS['compile_time']。"""
    _findings = []
    for _name, _path, _direction in _REGRESSION_CHECKS["compile_time"]:
        _prev_val = _get_nested(prev_info, _path)
        _curr_val = _get_nested(curr_info, _path)

        if _prev_val is None and _curr_val is None:
            continue

        _regressed = False
        if _direction == "down":
            # bool: True→False 是退化; str: "Full RELRO"→"Partial RELRO" 是退化
            if isinstance(_prev_val, bool) and isinstance(_curr_val, bool):
                _regressed = _prev_val is True and _curr_val is False
            elif isinstance(_prev_val, str) and isinstance(_curr_val, str):
                _severity_order = ["full", "full relro", "partial", "partial relro", "none", None]
                _prev_idx = next((i for i, v in enumerate(_severity_order) if v == _prev_val.lower()), 999)
                _curr_idx = next((i for i, v in enumerate(_severity_order) if v == _curr_val.lower()), 999)
                _regressed = _curr_idx > _prev_idx
        elif _direction == "up":
            if isinstance(_prev_val, bool) and isinstance(_curr_val, bool):
                _regressed = _prev_val is False and _curr_val is True

        if _regressed:
            _findings.append({
                "check": _name,
                "category": "compile_time",
                "previous_value": _prev_val,
                "current_value": _curr_val,
                "severity": _regression_severity(_name),
            })

    return _findings


def _check_segment_regression(
    prev_sections: List[Dict],
    curr_sections: List[Dict],
    prev_seg_risk: Dict = None,
    curr_seg_risk: Dict = None,
) -> List[Dict]:
    """检测段布局安全退化：新增 RWX 段，guard page 覆盖率下降。"""
    _findings = []

    # 检测新增 RWX 段
    def _has_rwx(sec: Dict) -> bool:
        _chars = sec.get("characteristics", [])
        if isinstance(_chars, list):
            return "MEM_EXECUTE" in _chars and "MEM_WRITE" in _chars
        _name = sec.get("name", sec.get("segment", "")).lower()
        return any(kw in _name for kw in ("rwx",))

    def _rwx_names(sections: List[Dict]) -> Set[str]:
        return {
            s.get("name", s.get("segment", ""))
            for s in sections if _has_rwx(s)
        }

    _prev_rwx = _rwx_names(prev_sections)
    _curr_rwx = _rwx_names(curr_sections)
    _new_rwx = _curr_rwx - _prev_rwx

    if _new_rwx:
        _findings.append({
            "check": "rwx_segment_added",
            "category": "segment_layout",
            "previous_value": list(_prev_rwx) if _prev_rwx else [],
            "current_value": list(_curr_rwx),
            "detail": f"新增 RWX 段: {', '.join(sorted(_new_rwx))}",
            "severity": RegressionSeverity.CRITICAL.name,
        })

    # Guard page 覆盖率下降
    _prev_guard = (prev_seg_risk or {}).get("guard_page_coverage", 1.0)
    _curr_guard = (curr_seg_risk or {}).get("guard_page_coverage", 1.0)
    if _curr_guard < _prev_guard - 0.15:
        _findings.append({
            "check": "guard_page_removed",
            "category": "segment_layout",
            "previous_value": round(_prev_guard, 4),
            "current_value": round(_curr_guard, 4),
            "detail": f"Guard page 覆盖率下降 {_prev_guard - _curr_guard:.2%}",
            "severity": RegressionSeverity.MEDIUM.name,
        })

    # 段邻接风险评分上升
    _prev_adj = (prev_seg_risk or {}).get("adjacency_risk_score", 0.0)
    _curr_adj = (curr_seg_risk or {}).get("adjacency_risk_score", 0.0)
    if _curr_adj > _prev_adj + 0.1:
        _findings.append({
            "check": "adjacency_risk_increased",
            "category": "segment_layout",
            "previous_value": round(_prev_adj, 4),
            "current_value": round(_curr_adj, 4),
            "detail": f"段邻接风险上升 {_curr_adj - _prev_adj:.3f}",
            "severity": RegressionSeverity.HIGH.name,
        })

    return _findings


def _check_import_regression(prev_imports: Dict, curr_imports: Dict) -> List[Dict]:
    """检测导入表面退化。"""
    _findings = []
    _prev_dangerous = set(prev_imports.get("dangerous_functions", []))
    _curr_dangerous = set(curr_imports.get("dangerous_functions", []))
    _new_dangerous = _curr_dangerous - _prev_dangerous
    if _new_dangerous:
        _findings.append({
            "check": "new_dangerous_imports", "category": "import_surface",
            "previous_value": sorted(_prev_dangerous), "current_value": sorted(_curr_dangerous),
            "detail": f"新增危险导入: {', '.join(sorted(_new_dangerous))}",
            "severity": RegressionSeverity.HIGH.name if len(_new_dangerous) >= 3 else RegressionSeverity.MEDIUM.name,
        })
    _prev_libs = set(prev_imports.get("all_imports", {}).keys())
    _curr_libs = set(curr_imports.get("all_imports", {}).keys())
    _new_sensitive = (_curr_libs - _prev_libs) & _SENSITIVE_DLLS
    if _new_sensitive:
        _findings.append({
            "check": "new_sensitive_dll", "category": "import_surface",
            "previous_value": sorted(_prev_libs & _SENSITIVE_DLLS),
            "current_value": sorted(_curr_libs & _SENSITIVE_DLLS),
            "detail": f"新增敏感 DLL 依赖: {', '.join(sorted(_new_sensitive))}",
            "severity": RegressionSeverity.MEDIUM.name,
        })
    return _findings


def _regression_severity(check_name: str) -> str:
    """编译期保护退化严重度映射。"""
    _map = {"stack_canary_removed": "CRITICAL", "nx_disabled": "CRITICAL",
            "full_relro_lost": "CRITICAL", "pie_disabled": "HIGH",
            "relro_weakened": "HIGH", "fortify_source_disabled": "MEDIUM"}
    return _map.get(check_name, "LOW")


def detect_posture_regression(
    prev_binary_info: Dict, curr_binary_info: Dict,
    prev_segment_risk: Dict = None, curr_segment_risk: Dict = None,
    prev_cfg_fingerprint: Dict = None, curr_cfg_fingerprint: Dict = None,
) -> Dict:
    """比较两个版本的二进制安全态势，检测所有退化项。
    输出: regressions / regression_count / worst_severity / security_score_delta / verdict。
    """
    _fmt = prev_binary_info.get("format", "UNKNOWN")
    if _fmt != curr_binary_info.get("format", "UNKNOWN"):
        return {"regressions": [], "regression_count": 0, "worst_severity": "NONE",
                "security_score_delta": 0.0, "verdict": "format_mismatch"}

    _all_findings = []
    _all_findings.extend(_check_protection_regression(prev_binary_info, curr_binary_info))
    _all_findings.extend(_check_segment_regression(
        prev_binary_info.get("sections", []), curr_binary_info.get("sections", []),
        prev_segment_risk, curr_segment_risk))
    _all_findings.extend(_check_import_regression(
        prev_binary_info.get("imports", {}), curr_binary_info.get("imports", {})))

    if prev_cfg_fingerprint and curr_cfg_fingerprint:
        _prev_score = prev_cfg_fingerprint.get("composite_score", 0.0)
        _curr_score = curr_cfg_fingerprint.get("composite_score", 0.0)
        if abs(_curr_score - _prev_score) > 0.30:
            _all_findings.append({
                "check": "cfg_entropy_shift", "category": "structural",
                "previous_value": round(_prev_score, 6),
                "current_value": round(_curr_score, 6),
                "detail": f"CFG 结构熵突变 (delta={abs(_curr_score-_prev_score):.4f})",
                "severity": RegressionSeverity.HIGH.name,
            })

    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    _all_findings.sort(key=lambda f: _sev_order.get(f["severity"], 99))

    _prev_posture = prev_binary_info.get("posture_analysis", {}).get("security_posture", {})
    _curr_posture = curr_binary_info.get("posture_analysis", {}).get("security_posture", {})
    _delta = round(_curr_posture.get("posture_score", 0.0) - _prev_posture.get("posture_score", 0.0), 4)

    _worst = _all_findings[0]["severity"] if _all_findings else "NONE"
    _verdict = "degraded" if _all_findings else ("unchanged" if abs(_delta) < 0.02 else "improved")

    return {
        "regressions": _all_findings, "regression_count": len(_all_findings),
        "worst_severity": _worst, "security_score_delta": _delta,
        "verdict": _verdict, "summary": _summarize_regression(_all_findings, _delta, _worst),
    }


def _summarize_regression(findings: List[Dict], delta: float, worst: str) -> str:
    """退化摘要：一行文本，适合嵌入 CI 报告。"""
    if not findings:
        if delta >= 0.01:
            return f"安全态势改善 (+{delta:.3f})"
        return "安全态势无变化"

    _cats = set(f["category"] for f in findings)
    return (
        f"检测到 {len(findings)} 项安全退化 (最高严重度:{worst}, "
        f"态势分变化:{delta:+.4f}, 涉及维度:{','.join(sorted(_cats))})"
    )
