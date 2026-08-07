# lateral — 10 种横向移动技术 + 凭据转储检测
# 基于 API 导入表 + 字符串特征双通道匹配，跨平台覆盖 Windows/Linux SSH

import re
from typing import List, Dict, Set, Tuple
import hashlib

# 技术名 → MITRE ATT&CK TID
_LATERAL_TIDS = {
    "wmi": "T1047",
    "psexec": "T1021.002",
    "schtasks": "T1053.005",
    "winrm": "T1021.006",
    "dcom": "T1021.003",
    "rdp": "T1021.001",
    "smb": "T1021.002",
    "passthehash": "T1550.002",
    "credential_dumping": "T1003",
    "ssh": "T1021.004",
}

# API 与字符串特征库
_WMI_APIS = [
    "IWbemServices", "IWbemLocator", "ConnectServer",
    "ExecMethod", "ExecQuery", "Win32_Process",
]
_WMI_STRINGS = ["Win32_Process", "root\\cimv2", "SELECT * FROM", "IWbem"]

_PSXEC_APIS = [
    "CreateService", "StartService", "OpenSCManager",
    "OpenService", "ChangeServiceConfig",
]
_PSXEC_STRINGS = ["ADMIN$", "psexec", "PSEXESVC", "IPC$"]

_SCHTASKS_APIS = [
    "ITaskScheduler", "ITask", "NewWorkItem",
    "SetTargetComputer", "AddWorkItem",
]
_SCHTASKS_STRINGS = ["schtasks", "Task Scheduler", "Microsoft\\Windows\\TaskScheduler"]

_WINRM_APIS = [
    "WSManInitialize", "WSManCreateSession",
    "WSManRunShellCommand", "WSManCloseSession",
]
_WINRM_STRINGS = ["winrm", "wsman", "5985", "5986", "http://schemas.microsoft.com/wbem/wsman"]

_DCOM_APIS = [
    "CoCreateInstance", "CoInitializeSecurity",
    "CLSIDFromProgID", "CoGetClassObject",
]
_DCOM_CLSIDS = [
    "MMC20.Application", "ShellWindows", "ShellBrowserWindow",
    "Excel.Application", "Word.Application", "C08AFD90-F2A1-11D1-8455-00A0C91F3880",
]
_DCOM_STRINGS = _DCOM_CLSIDS + ["DCOM", "IID_DCOM", "CLSCTX_REMOTE_SERVER"]

_RDP_APIS = ["WTSEnumerateSessions", "WTSQuerySessionInformation", "WTSLogoffSession"]
_RDP_STRINGS = ["tsclient", "mstsc", "rdp", "3389", "Remote Desktop"]

_SMB_APIS = ["NetUseAdd", "WNetAddConnection2", "NetShareEnum", "NetShareAdd"]
_SMB_STRINGS = ["\\\\", "IPC$", "SMB", "CIFS", "445"]

_SSH_APIS = ["ssh_session", "ssh_connect", "libssh2", "ssh2_exec"]
_SSH_STRINGS = ["ssh", "sshd", "22", "authorized_keys", "openssh", "libssh"]

_PTH_APIS = [
    "LsaLogonUser", "InitializeSecurityContext",
    "AcquireCredentialsHandle", "ImpersonateSecurityContext",
]
_PTH_STRINGS = ["mimikatz", "pth", "sekurlsa", "wdigest", "lsadump", "pass the hash"]

_CRED_DUMP_APIS = [
    "OpenProcessToken", "AdjustTokenPrivileges", "MiniDumpWriteDump",
    "ReadProcessMemory", "SamEnumerateUsersInDomain",
]
_CRED_DUMP_STRINGS = [
    "lsass.exe", "lsass", "sam", "system", "security",
    "ntds.dit", "SECURITY\\Policy\\Secrets",
    "mimikatz", "procdump", "sekurlsa",
    "samsrv.dll", "cachedump", "lsadump",
]


def _norm_apis(imports: dict) -> Set[str]:
    _r = set()
    for _dll, _funcs in imports.items():
        for _f in _funcs:
            _r.add(_f.lower().replace('a', '').replace('w', ''))
    return _r


def _norm_strs(strings: list) -> Set[str]:
    _r = set()
    for _s in strings:
        _text = _s[1].lower() if isinstance(_s, tuple) else _s.lower()
        _r.add(_text)
    return _r


def _score(api_matches: int, api_total: int, str_matches: int, str_total: int,
           api_weight: float = 0.6, str_weight: float = 0.4) -> float:
    _a = (api_matches / max(api_total, 1)) * api_weight
    _s = (str_matches / max(str_total, 1)) * str_weight
    return min(_a + _s, 1.0)


def detect_wmi(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _WMI_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _WMI_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_WMI_APIS), _sm, len(_WMI_STRINGS))
    return {"technique": "wmi", "detected": _conf > 0.3, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["wmi"], "api_matches": _am, "str_matches": _sm}


def detect_psexec(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _PSXEC_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _PSXEC_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_PSXEC_APIS), _sm, len(_PSXEC_STRINGS))
    return {"technique": "psexec", "detected": _conf > 0.3, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["psexec"], "api_matches": _am, "str_matches": _sm}


def detect_schtasks(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _SCHTASKS_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _SCHTASKS_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_SCHTASKS_APIS), _sm, len(_SCHTASKS_STRINGS))
    return {"technique": "schtasks", "detected": _conf > 0.25, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["schtasks"], "api_matches": _am, "str_matches": _sm}


def detect_winrm(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _WINRM_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _WINRM_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_WINRM_APIS), _sm, len(_WINRM_STRINGS))
    return {"technique": "winrm", "detected": _conf > 0.25, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["winrm"], "api_matches": _am, "str_matches": _sm}


def detect_dcom(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _DCOM_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _DCOM_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_DCOM_APIS), _sm, len(_DCOM_STRINGS), api_weight=0.4, str_weight=0.6)
    return {"technique": "dcom", "detected": _conf > 0.25, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["dcom"], "api_matches": _am, "str_matches": _sm}


def detect_rdp(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _RDP_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _RDP_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_RDP_APIS), _sm, len(_RDP_STRINGS))
    return {"technique": "rdp", "detected": _conf > 0.25, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["rdp"], "api_matches": _am, "str_matches": _sm}


def detect_smb(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _SMB_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _SMB_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_SMB_APIS), _sm, len(_SMB_STRINGS))
    return {"technique": "smb", "detected": _conf > 0.25, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["smb"], "api_matches": _am, "str_matches": _sm}


def detect_ssh(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _SSH_APIS if a.lower() in str(_apis))
    _sm = sum(1 for s in _SSH_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_SSH_APIS), _sm, len(_SSH_STRINGS))
    return {"technique": "ssh", "detected": _conf > 0.2, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["ssh"], "api_matches": _am, "str_matches": _sm}


def detect_passthehash(imports: dict, strings: list) -> dict:
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _am = sum(1 for a in _PTH_APIS if a.lower() in str(_apis))
    _mimikatz_str = any(s in str(_strs) for s in ["mimikatz", "sekurlsa", "wdigest", "lsadump"])
    _sm = sum(1 for s in _PTH_STRINGS if s.lower() in str(_strs))
    _conf = _score(_am, len(_PTH_APIS), _sm + (2 if _mimikatz_str else 0), len(_PTH_STRINGS) + 2,
                   api_weight=0.3, str_weight=0.7)
    _detected = _conf > 0.2 or _mimikatz_str
    return {"technique": "passthehash", "detected": _detected, "confidence": _conf,
            "mitre_id": _LATERAL_TIDS["passthehash"],
            "api_matches": _am, "str_matches": _sm, "mimikatz_strings": _mimikatz_str}


def credential_dumping_detect(imports: dict, strings: list, sections: list = None) -> dict:
    """凭据转储专用检测：mimikatz/lsass/注册表HIVE/NTDS.dit 多重指标。
    灵敏度高于普通横向移动检测器，对 mimikatz 关键词给予更高权重。
    """
    _apis = _norm_apis(imports)
    _strs = _norm_strs(strings)
    _strs_joined = " ".join(_strs).lower()

    _indicators = {
        "mimikatz": any(kw in _strs_joined for kw in ["mimikatz", "sekurlsa", "wdigest", "lsadump", "cachedump"]),
        "lsass_access": any(kw in _strs_joined for kw in ["lsass", "lsass.exe", "lsass.dmp"]),
        "sam_hive": any(kw in _strs_joined for kw in ["sam", "security\\policy\\secrets", "samsrv"]),
        "ntds_hive": "ntds.dit" in _strs_joined,
        "reg_hive": any(kw in _strs_joined for kw in ["systemprofile", "sam\\sam", "hklm\\sam"]),
        "procdump": "procdump" in _strs_joined,
        "minidump": any(kw in _apis for kw in ["minidumpwritedump", "minidump"]),
    }

    _api_indicators = {
        "token_priv": "adjusttokenprivileges" in str(_apis),
        "open_process": "openprocess" in str(_apis) and "openprocesstoken" in str(_apis),
        "read_proc_mem": "readprocessmemory" in str(_apis),
    }

    _weight = sum(_indicators.values()) + sum(int(v) for v in _api_indicators.values())
    _detected = _weight >= 2
    _conf = min(0.30 + 0.10 * _weight, 1.0) if _weight > 0 else 0.0

    return {
        "technique": "credential_dumping",
        "detected": _detected,
        "confidence": _conf,
        "mitre_id": _LATERAL_TIDS["credential_dumping"],
        "indicators": _indicators,
        "api_indicators": _api_indicators,
        "match_count": _weight,
    }


_DETECTORS = {
    "wmi": detect_wmi, "psexec": detect_psexec,
    "schtasks": detect_schtasks, "winrm": detect_winrm,
    "dcom": detect_dcom, "rdp": detect_rdp,
    "smb": detect_smb, "ssh": detect_ssh,
    "passthehash": detect_passthehash,
}


def detect_all(imports: dict, strings: list, sections: list = None) -> dict:
    """全部横向移动检测器 + 凭据转储，汇总评分与风险等级。
    凭据转储命中的风险权重为 1.5 倍。
    """
    _results = {}
    _risk = 0.0
    _detected_count = 0

    for _name, _detector in _DETECTORS.items():
        _r = _detector(imports, strings)
        _results[_name] = _r
        if _r["detected"]:
            _detected_count += 1
            _risk += _r["confidence"]

    _cred = credential_dumping_detect(imports, strings, sections)
    if _cred["detected"]:
        _detected_count += 1
        _risk += _cred["confidence"] * 1.5

    _overall = min(_risk * 100.0 / max(len(_DETECTORS) + 1, 1), 100.0)

    if _cred["detected"] and _cred["confidence"] > 0.5:
        _summary = "CRITICAL"
    elif _detected_count >= 3:
        _summary = "HIGH_RISK"
    elif _detected_count >= 1:
        _summary = "SUSPICIOUS"
    else:
        _summary = "CLEAN"

    return {
        "findings": _results,
        "credential_dumping": _cred,
        "overall_risk": round(_overall, 1),
        "detected_count": _detected_count,
        "summary": _summary,
    }
