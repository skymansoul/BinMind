# capability_inference — 静态二进制能力推断引擎
# 从导入 API + 字符串 + 段特征推断二进制的高层功能能力，
# 无需执行、无需反汇编、无需 ML 训练。
#
# 区别于领域自适应 LLM 预测 stripped binary 单个函数名的方案,
# 本模块做的是整个二进制的
# 能力画像 (capability profile) — "它能做什么" 而非 "函数叫什么"。
# 粒度更粗但覆盖更全，且零外部依赖。
#
# 9 维能力空间:
#   network, file_io, process_manipulation, cryptography,
#   persistence, defense_evasion, data_collection, privilege_escalation,
#   user_interaction
#
# 每维由加权 API 匹配 + 字符串关键词匹配 + 段特征推断联合评分。

import math
from typing import Dict, List, Set, Tuple
from ._shared import extract_api_set as _extract_api_set, extract_string_set as _extract_string_set


# 能力定义: (API关键词列表, 字符串关键词列表, 权重元组)
_CAPABILITY_DEFINITIONS: Dict[str, Tuple[List[str], List[str], Tuple[float, float]]] = {
    "network": (
        # API 关键词 (导入表中匹配)
        ["recv", "send", "connect", "socket", "bind", "listen", "accept",
         "WSASocket", "WSARecv", "WSASend", "InternetOpen", "InternetConnect",
         "HttpOpenRequest", "HttpSendRequest", "URLDownloadToFile",
         "getaddrinfo", "gethostbyname", "curl", "ssh_connect", "WinHttp",
         "select", "poll", "epoll", "DnsQuery"],
        # 字符串关键词
        ["http://", "https://", "www.", ".com", ".org", ".net",
         "socket", "connect", "c2", "beacon", "listener", "bind port",
         "user-agent", "cookie", "referer", "api.", "rest/"],
        (0.65, 0.35),
    ),
    "file_io": (
        ["fopen", "fclose", "fread", "fwrite", "open", "close", "read", "write",
         "CreateFile", "ReadFile", "WriteFile", "SetFilePointer", "DeleteFile",
         "FindFirstFile", "FindNextFile", "CopyFile", "MoveFile",
         "fputs", "fgets", "fprintf", "fscanf", "stat", "lseek",
         "NtCreateFile", "NtReadFile", "NtWriteFile", "ZwCreateFile"],
        ["/etc/", "/tmp/", "/var/", "C:\\", "%APPDATA%", "%TEMP%",
         "file", "path", "directory", "folder", "config", ".dat", ".log",
         ".xml", ".json", ".ini", ".cfg", "homedir", "document"],
        (0.55, 0.45),
    ),
    "process_manipulation": (
        ["CreateProcess", "OpenProcess", "TerminateProcess", "CreateRemoteThread",
         "WriteProcessMemory", "ReadProcessMemory", "VirtualAllocEx",
         "QueueUserAPC", "NtCreateThreadEx", "RtlCreateUserThread",
         "fork", "execve", "execvp", "execl", "execle", "execv",
         "kill", "waitpid", "ptrace", "NtQuerySystemInformation",
         "CreateToolhelp32Snapshot", "Process32First", "Process32Next"],
        ["process", "inject", "hollow", "CreateProcess", "OpenProcess",
         "cmd.exe", "powershell", "/bin/sh", "shell", "execute",
         "pid", "thread", "mutex", "semaphore"],
        (0.70, 0.30),
    ),
    "cryptography": (
        ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey",
         "EVP_EncryptInit", "EVP_DecryptInit", "AES_", "RSA_", "SHA", "MD5",
         "bcrypt", "CryptoAPI", "CertOpenStore", "CryptStringToBinary",
         "gcry_", "gnutls_", "mbedtls_", "wolfSSL_", "sodium_",
         "RC4", "DES_", "HMAC", "PBKDF", "BCrypt", "NCrypt"],
        ["encrypt", "decrypt", "cipher", "AES", "RSA", "SHA", "key",
         "certificate", "public key", "private key", "BEGIN RSA",
         "BEGIN CERTIFICATE", "hash", "md5", "sha256", "base64",
         "salt", "iv", "nonce", "padding"],
        (0.60, 0.40),
    ),
    "persistence": (
        ["RegCreateKey", "RegSetValue", "RegOpenKey", "RegQueryValue",
         "CreateService", "StartService", "OpenSCManager",
         "RegisterTaskDefinition", "ITaskScheduler", "SetFileAttributes",
         "crontab", "systemd", "launchd", "install", "schtasks"],
        ["Run", "RunOnce", "CurrentVersion\\Run", "Startup",
         "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "service",
         "cron", "systemd", "launchd", "autostart", "boot",
         "login", "init.d", "rc.local", ".bashrc", ".profile"],
        (0.55, 0.45),
    ),
    "defense_evasion": (
        ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
         "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
         "NtSetInformationThread", "VirtualProtect", "mprotect",
         "SetErrorMode", "Wow64DisableWow64FsRedirection",
         "NtQuerySystemInformation", "BlockInput", "SwitchDesktop",
         "RtlGetVersion", "GetSystemInfo"],
        ["debug", "vmware", "virtualbox", "qemu", "xen", "sandbox",
         "ollydbg", "ida", "x64dbg", "windbg", "detect", "anti",
         "evasion", "stealth", "hidden", "bypass", "hook",
         "injection", "pack", "obfuscat", "encode"],
        (0.60, 0.40),
    ),
    "data_collection": (
        ["FindFirstFile", "FindNextFile", "GetClipboardData", "SetClipboardData",
         "GetKeyState", "GetAsyncKeyState", "SetWindowsHookEx", "GetForegroundWindow",
         "PrintWindow", "BitBlt", "CreateCompatibleDC", "capCreateCaptureWindow",
         "ReadDirectoryChanges", "RegEnumKey", "RegEnumValue",
         "NtQueryDirectoryFile", "keylogger", "screenshot"],
        ["keylog", "screenshot", "clipboard", "keyboard", "mouse",
         "camera", "microphone", "screen capture", "record",
         "monitor", "log keystroke", "account", "password",
         "credential", "cookie", "history", "bookmark"],
        (0.55, 0.45),
    ),
    "privilege_escalation": (
        ["OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValue",
         "DuplicateTokenEx", "ImpersonateLoggedOnUser", "CreateProcessAsUser",
         "SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege",
         "setuid", "setgid", "seteuid", "setegid", "chmod", "chown",
         "capset", "prctl", "sudo", "NtRaiseHardError"],
        ["root", "admin", "administrator", "privilege", "escalat",
         "SeDebug", "SeImpersonate", "token", "impersonat",
         "sudo", "su ", "setuid", "elevate", "bypass uac",
         "NT AUTHORITY\\SYSTEM", "LOCAL SYSTEM"],
        (0.60, 0.40),
    ),
    "user_interaction": (
        ["MessageBox", "DialogBox", "CreateWindow", "ShowWindow",
         "GetMessage", "DispatchMessage", "SetWindowText", "GetDlgItem",
         "SendMessage", "PostMessage", "GetCursorPos", "SetCursorPos",
         "mouse_event", "keybd_event", "SendInput"],
        ["dialog", "window", "button", "click", "message", "input",
         "user", "prompt", "confirm", "alert", "msgbox", "gui",
         "form", "menu", "toolbar", "status bar"],
        (0.50, 0.50),
    ),
}


def _extract_api_set(imports: Dict) -> Set[str]:
    """导入表 → 归一化 API 名称集合。"""
    _apis = set()
    _src = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if not isinstance(_src, dict):
        return _apis
    for _funcs in _src.values():
        if isinstance(_funcs, list):
            for _f in _funcs:
                _clean = _f.lower().rstrip('aw')
                _apis.add(_clean)
    return _apis


def _extract_string_set(strings: List) -> Set[str]:
    _ss = set()
    for _s in (strings or []):
        _t = _s[1] if isinstance(_s, tuple) else str(_s)
        _ss.add(_t.lower())
    return _ss


def _score_capability(
    cap_api_keywords: List[str],
    cap_str_keywords: List[str],
    api_set: Set[str],
    str_set: Set[str],
    weights: Tuple[float, float],
) -> Tuple[float, int, int]:
    """对单个能力评分: API 关键词命中率 + 字符串关键词命中率，加权。"""
    _api_hits = sum(1 for kw in cap_api_keywords
                    if any(kw.lower() in a for a in api_set))
    _str_hits = sum(1 for kw in cap_str_keywords
                    if kw.lower() in " ".join(str_set))

    _api_score = _api_hits / max(len(cap_api_keywords), 1)
    _str_score = _str_hits / max(len(cap_str_keywords), 1)

    _w_api, _w_str = weights
    _total = _api_score * _w_api + _str_score * _w_str

    # logistic 平滑压制弱信号噪声
    _boosted = 1.0 / (1.0 + math.exp(-10 * (_total - 0.08)))
    return (round(_boosted, 4), _api_hits, _str_hits)


def infer_capabilities(
    imports: Dict = None,
    strings: List = None,
    sections: List = None,
) -> Dict:
    """二进制能力推断主入口。

    返回:
    - capabilities: {capability_name: {score, api_hits, str_hits, level}}
    - primary_capabilities: 主要能力 (score > 0.5)
    - capability_vector: 9 维能力向量 (用于相似度比较)
    - binary_role: 推断的二进制角色标签
    """
    _api_set = _extract_api_set(imports or {})
    _str_set = _extract_string_set(strings or [])
    _sections = sections or []

    _caps = {}
    _vector = []

    for _cap_name, (_api_kws, _str_kws, _weights) in _CAPABILITY_DEFINITIONS.items():
        _score, _api_h, _str_h = _score_capability(
            _api_kws, _str_kws, _api_set, _str_set, _weights)

        _level = ("PRIMARY" if _score > 0.50 else
                  "SECONDARY" if _score > 0.25 else
                  "WEAK" if _score > 0.10 else "NONE")

        _caps[_cap_name] = {
            "score": _score,
            "api_hits": _api_h,
            "str_hits": _str_h,
            "level": _level,
        }
        _vector.append(_score)

    _primary = {k: v for k, v in _caps.items() if v["level"] == "PRIMARY"}

    # 角色推断: 从能力组合推断二进制的高层角色
    _role = _infer_role(_caps, _api_set, _str_set)

    return {
        "capabilities": _caps,
        "primary_capabilities": list(_primary.keys()),
        "capability_vector": _vector,
        "binary_role": _role["role"],
        "role_confidence": _role["confidence"],
        "role_description": _role["description"],
    }


def _infer_role(caps: Dict, api_set: Set[str], str_set: Set[str]) -> Dict:
    """从能力组合推断二进制角色。"""
    _roles = []

    if caps.get("network", {}).get("score", 0) > 0.5:
        if caps.get("process_manipulation", {}).get("score", 0) > 0.3:
            _roles.append(("C2_IMPLANT", 0.70, "C2 远控植入物"))
        elif caps.get("data_collection", {}).get("score", 0) > 0.3:
            _roles.append(("DATA_EXFILTRATOR", 0.65, "数据窃取工具"))
        else:
            _roles.append(("NETWORK_TOOL", 0.60, "网络通信工具"))

    if caps.get("file_io", {}).get("score", 0) > 0.4:
        if caps.get("cryptography", {}).get("score", 0) > 0.4:
            _roles.append(("RANSOMWARE", 0.75, "勒索软件 (文件操作+加密)"))
        elif caps.get("persistence", {}).get("score", 0) > 0.3:
            _roles.append(("PERSISTENT_DROPPER", 0.65, "持久化投放器"))

    if caps.get("defense_evasion", {}).get("score", 0) > 0.5:
        _roles.append(("EVASIVE_TOOL", 0.60, "高度规避性工具"))

    if caps.get("user_interaction", {}).get("score", 0) > 0.4:
        if caps.get("defense_evasion", {}).get("score", 0) > 0.3:
            _roles.append(("TROJAN_APPLICATION", 0.70, "伪装为正常应用的木马"))
        else:
            _roles.append(("GUI_APPLICATION", 0.55, "图形界面应用"))

    if caps.get("privilege_escalation", {}).get("score", 0) > 0.3:
        _roles.append(("PRIVILEGE_ESCALATION_TOOL", 0.65, "提权工具"))

    if not _roles:
        _max_cap = max(caps.items(), key=lambda x: x[1]["score"])
        if _max_cap[1]["score"] > 0.25:
            return {"role": f"PRIMARILY_{_max_cap[0].upper()}",
                    "confidence": _max_cap[1]["score"],
                    "description": f"主要具备{_max_cap[0]}能力"}
        return {"role": "GENERIC_BINARY", "confidence": 0.30,
                "description": "未识别到显著能力特征"}

    _best = max(_roles, key=lambda x: x[1])
    return {"role": _best[0], "confidence": _best[1], "description": _best[2]}
