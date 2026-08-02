# 2026-07-20
# injection_detect — 10 种代码注入技术检测
# 每种技术按 MITRE ATT&CK 映射到 TID，检测方式为
# API 导入表模式匹配 + 字符串特征匹配的组合判定

import re
from typing import List, Dict, Tuple

# ===== MITRE ATT&CK 映射 =====
MITRE_ATTACK = {
    "pe_injection": "T1055.001",
    "process_hollowing": "T1055.012",
    "reflective_dll": "T1055.001",
    "apc_injection": "T1055.004",
    "thread_hijacking": "T1055.003",
    "atom_bombing": "T1055.012",
    "process_doppelganging": "T1055.013",
    "early_bird_apc": "T1055.004",
    "setwindowshookex": "T1056.004",
    "extra_window_memory": "T1055.011",
}

# ---- API 模式定义 ----
# 每组为 (required_apis, optional_apis, string_hints)
# required: 至少一组匹配才算 detected
# optional: 增加置信度
# string_hints: 字符串中出现的可疑模式

_INJECTION_PATTERNS = {
    "pe_injection": (
        ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        ["OpenProcess", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC"],
        ["CreateRemoteThread", "WriteProcessMemory"],
    ),
    "process_hollowing": (
        ["CREATE_SUSPENDED", "NtUnmapViewOfSection"],
        ["SetThreadContext", "ResumeThread", "GetThreadContext", "ZwUnmapViewOfSection"],
        ["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext"],
    ),
    "reflective_dll": (
        ["FindResource", "LockResource", "SizeofResource"],
        ["VirtualAlloc", "VirtualProtect", "GetProcAddress"],
        ["ReflectiveLoader", "reflective_loader", "LoadLibraryA", "GetProcAddress"],
    ),
    "apc_injection": (
        ["QueueUserAPC"],
        ["OpenThread", "SuspendThread", "ResumeThread", "NtQueueApcThread"],
        ["QueueUserAPC", "NtQueueApcThread", "APC"],
    ),
    "thread_hijacking": (
        ["SuspendThread", "SetThreadContext", "ResumeThread"],
        ["OpenThread", "GetThreadContext"],
        ["SuspendThread", "SetThreadContext"],
    ),
    "atom_bombing": (
        ["GlobalAddAtom"],
        ["GlobalGetAtomName", "NtQueueApcThread"],
        ["GlobalAddAtom", "GlobalGetAtomName", "NtQueueApcThread"],
    ),
    "process_doppelganging": (
        ["NtCreateUserProcess"],
        ["NtCreateTransaction", "NtRollbackTransaction"],
        ["NtCreateUserProcess", "ProcessDoppelganging"],
    ),
    "early_bird_apc": (
        ["CreateProcess", "QueueUserAPC"],
        ["CREATE_SUSPENDED", "ResumeThread"],
        ["QueueUserAPC", "CREATE_SUSPENDED"],
    ),
    "setwindowshookex": (
        ["SetWindowsHookEx"],
        ["GetMessage", "UnhookWindowsHookEx", "CallNextHookEx"],
        ["SetWindowsHookEx", "WH_KEYBOARD", "WH_MOUSE"],
    ),
    "extra_window_memory": (
        ["SetWindowLong", "GetWindowLong"],
        ["CallWindowProc", "EnumWindows"],
        ["SetWindowLong", "SetWindowLongPtr", "GetWindowLong"],
    ),
}

_NON_API_STRINGS = {
    "inject", "payload", "shellcode", "meterpreter", "beacon",
    "cobaltstrike", "cobalt_strike", "metasploit", "reverse_tcp",
    "bind_tcp", "connect_back", "download_exec", "reflective",
    "process_hollow", "migrate", "stealth", "hiding", "evasion",
    "obfusc", "encoded", "base64decode", "rc4_decrypt", "xor_decrypt",
}


def _normalize_api_name(name: str) -> str:
    """去除 A/W 后缀和大小写归一化。"""
    _n = name.strip().lower()
    if _n.endswith('a') and len(_n) > 1:
        _core = _n[:-1]
        return _core
    if _n.endswith('w') and len(_n) > 1:
        return _n[:-1]
    return _n


def _extract_api_set(imports: dict) -> set:
    """从导入表提取归一化 API 名称集合。"""
    _apis = set()
    for _dll, _funcs in imports.items():
        for _f in _funcs:
            _apis.add(_normalize_api_name(_f))
    return _apis


def _extract_string_set(strings: list) -> set:
    _r = set()
    for _s in strings:
        _text = _s[1].lower() if isinstance(_s, tuple) else _s.lower()
        _r.add(_text)
    return _r


# //// 单技术检测 ////
def detect_pe_injection(imports: dict, strings: list, sections: list = None) -> dict:
    """PE injection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread 链。"""
    _apis = _extract_api_set(imports)
    _strs = _extract_string_set(strings)
    _required = {"virtualallocex", "writeprocessmemory", "createremotethread"}
    _optional = {"openprocess", "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc"}
    _matched_req = _required & _apis
    _matched_opt = _optional & _apis
    _str_hints = [s for s in _strs if "createremotethread" in s or "writeprocessmemory" in s]
    _detected = len(_matched_req) >= 2
    _conf = 0.0
    if _detected:
        _conf = 0.60 + 0.15 * min(len(_matched_req), 3) / 3.0 + 0.10 * bool(_matched_opt) + 0.05 * bool(_str_hints)
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": list(_matched_req | _matched_opt),
        "mitre_id": MITRE_ATTACK["pe_injection"],
    }


def detect_process_hollowing(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _strs = _extract_string_set(strings)
    _s_flags = set()
    if sections:
        for _sec in sections:
            if isinstance(_sec, dict):
                _s_flags.add(_sec.get("name", "").lower())
    _matched = []
    for _api in ["createprocess", "createprocessinternal"]:
        for _a in _apis:
            if _api in _a:
                _matched.append(_a)
    _suspend_pattern = False
    _unmap = _apis & {"ntunmapviewofsection", "zwunmapviewofsection"}
    _suspend_pattern = "create_suspended" in str(_strs) or "create_suspended" in str(imports).lower()
    _detected = bool(_unmap) and (bool(_matched) or _suspend_pattern)
    _conf = 0.50 + 0.25 * bool(_unmap) + 0.15 * bool(_matched) + 0.10 * _suspend_pattern
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": list(_unmap) + _matched,
        "mitre_id": MITRE_ATTACK["process_hollowing"],
    }


def detect_reflective_dll(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _strs = _extract_string_set(strings)
    _find_resource = _apis & {"findresource", "lockresource", "sizeofresource"}
    _mem_ops = _apis & {"virtualalloc", "virtualprotect", "getprocaddress"}
    _str_reflective = any("reflectiveloader" in s or "reflective_loader" in s for s in _strs)
    _no_loadlibrary = "loadlibrary" not in str(_apis)
    _detected = (bool(_find_resource) and _no_loadlibrary) or _str_reflective
    _conf = 0.40 + 0.20 * bool(_find_resource) + 0.20 * bool(_mem_ops) + 0.20 * _str_reflective
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": list(_find_resource | _mem_ops),
        "mitre_id": MITRE_ATTACK["reflective_dll"],
    }


def detect_apc_injection(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _strs = _extract_string_set(strings)
    _apc = _apis & {"queueuserapc", "ntqueueapcthread"}
    _thread = _apis & {"openthread", "suspendthread", "resumethread"}
    _str_apc = any("apc" in s for s in _strs)
    _detected = bool(_apc and _thread) or (bool(_apc) and _str_apc)
    _conf = 0.45 + 0.30 * bool(_apc and _thread) + 0.15 * _str_apc
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": list(_apc | _thread),
        "mitre_id": MITRE_ATTACK["apc_injection"],
    }


def detect_thread_hijacking(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _suspend = "suspendthread" in str(_apis)
    _setctx = "setthreadcontext" in str(_apis)
    _resume = "resumethread" in str(_apis)
    _open = "openthread" in str(_apis)
    _getctx = "getthreadcontext" in str(_apis)
    _score = sum([_suspend, _setctx, _resume, _open, _getctx])
    _detected = _score >= 3
    return {
        "detected": _detected, "confidence": min(0.40 + 0.12 * _score, 1.0),
        "matched_patterns": [x for x, v in [
            ("SuspendThread", _suspend), ("SetThreadContext", _setctx),
            ("ResumeThread", _resume), ("OpenThread", _open),
            ("GetThreadContext", _getctx),
        ] if v],
        "mitre_id": MITRE_ATTACK["thread_hijacking"],
    }


def detect_atom_bombing(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _strs = _extract_string_set(strings)
    _addatom = "globaladdatom" in str(_apis)
    _getatom = "globalgetatomname" in str(_apis)
    _apc = _apis & {"queueuserapc", "ntqueueapcthread"}
    _detected = _addatom and _getatom and bool(_apc)
    _conf = 0.60 + 0.20 * _addatom + 0.10 * _getatom + 0.10 * bool(_apc)
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": [x for x, v in [
            ("GlobalAddAtom", _addatom), ("GlobalGetAtomName", _getatom),
        ] if v] + list(_apc),
        "mitre_id": MITRE_ATTACK["atom_bombing"],
    }


def detect_process_doppelganging(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _strs = _extract_string_set(strings)
    _ntcreate_user = "ntcreateuserprocess" in str(_apis)
    _ntcreate_trans = "ntcreatetransaction" in str(_apis)
    _ntrollback = "ntrollbacktransaction" in str(_apis)
    _str_hint = any("doppel" in s for s in _strs)
    _detected = _ntcreate_user and (_ntcreate_trans or _ntrollback or _str_hint)
    _conf = 0.50 + 0.30 * _ntcreate_user + 0.10 * (_ntcreate_trans or _ntrollback) + 0.10 * _str_hint
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": [x for x, v in [
            ("NtCreateUserProcess", _ntcreate_user),
            ("NtCreateTransaction", _ntcreate_trans),
            ("NtRollbackTransaction", _ntrollback),
        ] if v],
        "mitre_id": MITRE_ATTACK["process_doppelganging"],
    }


def detect_early_bird_apc(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _createproc = "createprocess" in str(_apis)
    _apc = "queueuserapc" in str(_apis)
    _susp = "create_suspended" in str(_apis).lower() or "CREATE_SUSPENDED" in str(strings)
    _detected = _createproc and _apc and _susp
    _conf = 0.55 + 0.20 * _createproc + 0.15 * _apc + 0.10 * _susp
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": [x for x, v in [
            ("CreateProcess+APC", _createproc and _apc),
        ] if v],
        "mitre_id": MITRE_ATTACK["early_bird_apc"],
    }


def detect_setwindowshookex(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _strs = _extract_string_set(strings)
    _hook = "setwindowshookex" in str(_apis)
    _msg = "getmessage" in str(_apis) and "unhookwindowshookex" in str(_apis)
    _str_hooks = any(s for s in _strs if "hook" in s and ("key" in s or "mouse" in s))
    _detected = _hook and (_msg or _str_hooks)
    _conf = 0.50 + 0.25 * _hook + 0.15 * _msg + 0.10 * _str_hooks
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": [x for x, v in [
            ("SetWindowsHookEx", _hook),
        ] if v],
        "mitre_id": MITRE_ATTACK["setwindowshookex"],
    }


def detect_extra_window_memory(imports: dict, strings: list, sections: list = None) -> dict:
    _apis = _extract_api_set(imports)
    _set = "setwindowlong" in str(_apis)
    _get = "getwindowlong" in str(_apis)
    _call = "callwindowproc" in str(_apis)
    _detected = _set and (_get or _call)
    _conf = 0.40 + 0.30 * _set + 0.15 * _get + 0.15 * _call
    return {
        "detected": _detected, "confidence": min(_conf, 1.0),
        "matched_patterns": [x for x, v in [
            ("SetWindowLong", _set), ("GetWindowLong", _get),
            ("CallWindowProc", _call),
        ] if v],
        "mitre_id": MITRE_ATTACK["extra_window_memory"],
    }


_DETECTORS = {
    "pe_injection": detect_pe_injection,
    "process_hollowing": detect_process_hollowing,
    "reflective_dll": detect_reflective_dll,
    "apc_injection": detect_apc_injection,
    "thread_hijacking": detect_thread_hijacking,
    "atom_bombing": detect_atom_bombing,
    "process_doppelganging": detect_process_doppelganging,
    "early_bird_apc": detect_early_bird_apc,
    "setwindowshookex": detect_setwindowshookex,
    "extra_window_memory": detect_extra_window_memory,
}


# //// 批量检测 ////
def detect_all(imports: dict, strings: list, sections: list = None) -> dict:
    """运行全部 10 种注入检测器，返回综合结果与风险评分。

    风险评分 = 各技术 confidence 加权求和，归一化到 0-100。
    返回:
        { "findings": {...}, "overall_risk": float, "summary": str }
    """
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
            if _r["confidence"] >= 0.7:
                _high_conf_count += 1

    _overall = min(_risk * 100.0 / max(len(_DETECTORS), 1) * 1.5, 100.0)

    _summary = "CLEAN"
    if _high_conf_count >= 2:
        _summary = "CRITICAL"
    elif _high_conf_count >= 1 or _detected_count >= 3:
        _summary = "SUSPICIOUS"
    elif _detected_count >= 1:
        _summary = "LOW_RISK"

    # 额外的字符串可疑度评分
    _str_set = _extract_string_set(strings)
    _suspicious_strings = _str_set & _NON_API_STRINGS
    if _suspicious_strings:
        _overall = min(_overall + 10.0 * len(_suspicious_strings), 100.0)

    return {
        "findings": _results,
        "overall_risk": round(_overall, 1),
        "detected_count": _detected_count,
        "high_confidence_count": _high_conf_count,
        "summary": _summary,
        "suspicious_strings": list(_suspicious_strings),
    }
