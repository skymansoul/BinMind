# 2026-07-23
# spoofing — 进程伪造检测：Hollowing / Doppelganging / Token / PPID / RunPE
# 检测策略：双层 —— API 模式匹配 (高置信度) + 字符串特征 (辅助验证)
# PE section 不匹配检测需配合 binary_info 模块获取段信息

import re
from typing import List, Dict, Tuple, Set

# ---- 检测模式 ----

_PROCESS_HOLLOWING_APIS = [
    "CreateProcess", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "WriteProcessMemory", "VirtualAllocEx", "ResumeThread",
    "SetThreadContext", "GetThreadContext", "ReadProcessMemory",
]
_PROCHOL_STRINGS = [
    "NtUnmapViewOfSection", "hollow", "process hollow",
    "CREATE_SUSPENDED", "ZwUnmapViewOfSection",
]

_DOPPELGANGING_APIS = [
    "NtCreateUserProcess", "NtCreateTransaction",
    "NtRollbackTransaction", "CreateFileTransacted",
    "NtWriteFile", "NtCreateSection", "NtClose",
]
_DOPPEL_STRINGS = [
    "ProcessDoppelganging", "transact", "rollback",
    "TransactionManager", "TxF",
]

_TOKEN_MANIP_APIS = [
    "OpenProcessToken", "DuplicateTokenEx", "SetTokenInformation",
    "AdjustTokenPrivileges", "ImpersonateLoggedOnUser",
    "CreateProcessWithTokenW", "CreateProcessAsUser",
    "SeDebugPrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeImpersonatePrivilege", "SeTcbPrivilege",
]
_TOKEN_STRINGS = [
    "SeDebugPrivilege", "SeImpersonatePrivilege",
    "SeAssignPrimaryToken", "token steal", "token impersonat",
    "DuplicateTokenEx", "NT AUTHORITY\\SYSTEM",
]

_PPID_SPOOFING_APIS = [
    "InitializeProcThreadAttributeList", "UpdateProcThreadAttribute",
    "CreateProcess", "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
]
_PPID_STRINGS = [
    "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
    "parent process", "PPID spoof", "ppid",
]

_RUNPE_APIS = [
    "CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory",
    "VirtualAllocEx", "SetThreadContext", "ResumeThread",
    "NtReadVirtualMemory", "ZwQueryInformationProcess",
]
_RUNPE_STRINGS = [
    "RunPE", "pe loader", "memory execute",
    "manual map", "reflective exe",
]

_PARENT_CHILD_ANOMALIES = [
    # (suspicious_parent, suspicious_child)
    ("services.exe", "cmd.exe"),
    ("svchost.exe", "powershell.exe"),
    ("winlogon.exe", "cmd.exe"),
    ("lsass.exe", "cmd.exe"),
    ("explorer.exe", "rundll32.exe"),
]

# API 导入表 → 归一化集合
def _norm_api(imports: dict) -> Set[str]:
    _r = set()
    for _dll, _funcs in imports.items():
        for _f in _funcs:
            _f_lower = _f.lower().replace('a', '').replace('w', '')
            _r.add(_f_lower)
    return _r


def _norm_strings(strings: list) -> Set[str]:
    _r = set()
    for _s in strings:
        _t = _s[1].lower() if isinstance(_s, tuple) else _s.lower()
        _r.add(_t)
    return _r


def detect_process_hollowing(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _norm_api(imports)
    _strs = _norm_strings(strings)
    _api_m = sum(1 for a in _PROCESS_HOLLOWING_APIS if a.lower() in _apis)
    _str_m = sum(1 for s in _PROCHOL_STRINGS if s.lower() in str(_strs))
    _unmap = "ntunmapviewofsection" in _apis or "zwunmapviewofsection" in _apis
    _write = "writeprocessmemory" in _apis
    _resume = "resumethread" in _apis
    _conf = 0.25 * _unmap + 0.20 * _write + 0.15 * _resume + 0.10 * (_api_m / max(len(_PROCESS_HOLLOWING_APIS), 1))
    _conf += 0.10 * (_str_m / max(len(_PROCHOL_STRINGS), 1))
    # section 不匹配检测
    _s_anomaly = False
    if sections:
        _s_names = {s.get("name", "") if isinstance(s, dict) else str(s) for s in sections}
        _s_anomaly = len(_s_names) >= 3 and any("UPX" in n or ".text" not in str(_s_names) for n in _s_names)
        if _s_anomaly:
            _conf += 0.15
    _detected = _conf >= 0.45
    return {
        "technique": "process_hollowing",
        "detected": _detected, "confidence": min(_conf, 1.0),
        "section_anomaly": _s_anomaly,
        "api_matches": _api_m, "str_matches": _str_m,
    }


def detect_process_doppelganging(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _norm_api(imports)
    _strs = _norm_strings(strings)
    _nt_user = "ntcreateuserprocess" in _apis
    _nt_trans = "ntcreatetransaction" in _apis
    _nt_rollback = "ntrollbacktransaction" in _apis
    _transacted_file = "createfiletransacted" in _apis
    _str_hint = any(s in str(_strs) for s in ["doppel", "transact", "rollback"])
    _score = sum([_nt_user, _nt_trans, _nt_rollback, _transacted_file, _str_hint])
    _detected = _score >= 3
    return {
        "technique": "process_doppelganging",
        "detected": _detected, "confidence": min(0.30 + 0.15 * _score, 1.0),
        "api_matches": _score - int(_str_hint), "str_matches": int(_str_hint),
    }


def detect_token_manipulation(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _norm_api(imports)
    _strs = _norm_strings(strings)
    _token_apis = sum(1 for a in _TOKEN_MANIP_APIS if a.lower() in _apis)
    _token_strs = sum(1 for s in _TOKEN_STRINGS if s.lower() in str(_strs))
    _sedebug = "sedebugprivilege" in str(_apis) or "sedebugprivilege" in str(_strs)
    _duptoken = "duplicatetokenex" in _apis
    _detected = _token_apis >= 3 or (_sedebug and _token_apis >= 1)
    _conf = 0.20 * _sedebug + 0.25 * _duptoken + 0.10 * (_token_apis / max(len(_TOKEN_MANIP_APIS), 1))
    _conf += 0.10 * (_token_strs / max(len(_TOKEN_STRINGS), 1))
    return {
        "technique": "token_manipulation",
        "detected": _detected, "confidence": min(_conf, 1.0),
        "api_matches": _token_apis, "str_matches": _token_strs,
    }


def detect_ppid_spoofing(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _norm_api(imports)
    _strs = _norm_strings(strings)
    _init_attr = "initializeprocthreadattributelist" in _apis
    _update_attr = "updateprocthreadattribute" in _apis
    _createproc = "createprocess" in _apis
    _ppid_str = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS".lower() in str(_strs)
    _score = sum([_init_attr, _update_attr, _createproc, _ppid_str])
    _detected = _score >= 2
    return {
        "technique": "ppid_spoofing",
        "detected": _detected, "confidence": min(0.30 + 0.175 * _score, 1.0),
        "api_matches": _score - int(_ppid_str), "str_matches": int(_ppid_str),
    }


def detect_runpe(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _norm_api(imports)
    _strs = _norm_strings(strings)
    _api_m = sum(1 for a in _RUNPE_APIS if a.lower() in _apis)
    _str_m = sum(1 for s in _RUNPE_STRINGS if s.lower() in str(_strs))
    _core = ("createprocess" in _apis and "writeprocessmemory" in _apis and
             "virtualallocex" in _apis and "resumethread" in _apis)
    _conf = 0.30 * _core + 0.15 * (_api_m / max(len(_RUNPE_APIS), 1))
    _conf += 0.10 * (_str_m / max(len(_RUNPE_STRINGS), 1))
    return {
        "technique": "runpe",
        "detected": _conf > 0.4, "confidence": min(_conf, 1.0),
        "api_matches": _api_m, "str_matches": _str_m,
    }


def detect_parent_child_anomalies(strings: list) -> dict:
    _strs = _norm_strings(strings)
    _strs_joined = " ".join(_strs)
    _anomalies = []
    for _parent, _child in _PARENT_CHILD_ANOMALIES:
        if _parent.lower() in _strs_joined and _child.lower() in _strs_joined:
            _anomalies.append(f"{_parent} -> {_child}")
    _detected = len(_anomalies) > 0
    _conf = min(0.40 + 0.15 * len(_anomalies), 1.0) if _detected else 0.0
    return {
        "technique": "parent_child_anomaly",
        "detected": _detected, "confidence": _conf,
        "anomalies": _anomalies,
    }


_DETECTORS = {
    "process_hollowing": detect_process_hollowing,
    "process_doppelganging": detect_process_doppelganging,
    "token_manipulation": detect_token_manipulation,
    "ppid_spoofing": detect_ppid_spoofing,
    "runpe": detect_runpe,
}


def detect_all(imports: dict, strings: list, sections: list = None) -> dict:
    _results = {}
    _risk = 0.0
    _detected_count = 0
    _high_conf_count = 0

    for _name, _detector in _DETECTORS.items():
        _r = _detector(imports, strings, sections)
        _results[_name] = _r
        if _r["detected"]:
            _detected_count += 1
            _risk += _r["confidence"]
            if _r["confidence"] >= 0.6:
                _high_conf_count += 1

    _pca = detect_parent_child_anomalies(strings)
    _results["parent_child_anomaly"] = _pca
    if _pca["detected"]:
        _detected_count += 1
        _risk += _pca["confidence"]

    _overall = min(_risk * 100.0 / max(len(_DETECTORS) + 1, 1) * 1.8, 100.0)

    if _high_conf_count >= 2:
        _summary = "CRITICAL"
    elif _detected_count >= 2:
        _summary = "HIGH_RISK"
    elif _detected_count >= 1:
        _summary = "SUSPICIOUS"
    else:
        _summary = "CLEAN"

    return {
        "findings": _results,
        "overall_risk": round(_overall, 1),
        "detected_count": _detected_count,
        "high_confidence_count": _high_conf_count,
        "summary": _summary,
    }
