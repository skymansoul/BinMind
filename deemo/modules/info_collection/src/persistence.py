# 2026-07-22
# persistence — 跨平台持久化检测：Windows / Linux / Mac
# 每个平台按具体技术细分，用字符串 + API 双通道匹配
# Windows 侧重注册表和服务，Linux 侧重 cron/systemd/rc

import re
from typing import List, Dict, Set

# ===== Windows 持久化模式 =====
_WIN_REGISTRY_KEYS = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppInit_DLLs",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppInit_DLLs",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
]

_WIN_SERVICE_APIS = [
    "CreateService", "OpenSCManager", "StartService", "ChangeServiceConfig",
    "SetServiceObjectSecurity", "QueryServiceConfig",
]
_WIN_SERVICE_STRINGS = [
    "SERVICE_AUTO_START", "SERVICE_DEMAND_START", "NT SERVICE",
    "SERVICE_BOOT_START", "SERVICE_SYSTEM_START",
]

_WIN_SCHEDULED_TASK_APIS = [
    "ITaskScheduler", "RegisterTaskDefinition", "NewWorkItem",
    "SetTargetComputer", "CreateFolder", "ITaskFolder",
]
_WIN_SCHEDULED_TASK_STRINGS = [
    "schtasks /create", "Task Scheduler", "/sc onlogon",
    "/sc onstart", "/sc onidle", "/sc daily",
]

_WIN_STARTUP_FOLDER = [
    r"Start Menu\Programs\Startup",
    r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
]

_WIN_WMI_PERSIST = [
    "__EventFilter", "__FilterToConsumerBinding",
    "__TimerInstruction", "__AbsoluteTimerInstruction",
    "ActiveScriptEventConsumer", "CommandLineEventConsumer",
    "__IntervalTimerInstruction",
]

_WIN_COM_HIJACK = [
    "CLSID", "InprocServer32", "LocalServer32",
    "TreatAs", "ProgID",
]

# ===== Linux 持久化模式 =====
_LINUX_CRON_PATHS = [
    "/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs",
    "/var/spool/cron", "/etc/cron.hourly", "/etc/cron.daily",
    "/etc/cron.weekly", "/etc/cron.monthly",
]

_LINUX_SYSTEMD_PATHS = [
    "/etc/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system", "~/.config/systemd/user",
]

_LINUX_RC_PATHS = [
    "/etc/rc.local", "/etc/init.d", "/etc/rc.d",
    "/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d",
    "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d",
]

_LINUX_SHELL_MODS = [
    "~/.bashrc", "~/.bash_profile", "~/.profile",
    "~/.zshrc", "~/.bash_login", "~/.bash_logout",
    "/etc/profile", "/etc/bash.bashrc",
]

_LINUX_LD_PRELOAD = ["LD_PRELOAD", "ld.so.preload", "/etc/ld.so.preload"]

_LINUX_PAM_MODS = [
    "/etc/pam.d", "/lib/security", "/lib64/security",
    "pam_unix.so", "pam_permit.so", "pam_exec.so",
]

_LINUX_XDG_AUTOSTART = [
    "~/.config/autostart", "/etc/xdg/autostart",
    ".desktop", "X-GNOME-Autostart",
]

# ===== Mac 持久化模式 =====
_MAC_LAUNCHD_PATHS = [
    "~/Library/LaunchAgents", "/Library/LaunchAgents",
    "/Library/LaunchDaemons", "/System/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
]

_MAC_LOGIN_ITEMS = [
    "loginwindow", "Login Items", "LSSharedFileList",
    "osascript add login item", "System Events",
]

_MAC_CRON = [
    "crontab", "launchctl submit", "com.apple.periodic",
]


def _norm(s: str) -> str:
    return s.lower().replace('\\', '\\\\')


# //// 各平台检测函数 ////

def detect_windows_persistence(imports: dict, strings: list) -> dict:
    _results = []
    _joined = " ".join(
        (s[1] if isinstance(s, tuple) else s).lower()
        for s in strings
    )
    _api_set = set()
    for _dll, _funcs in imports.items():
        for _f in _funcs:
            _api_set.add(_f.lower())

    # 注册表 Run key 检测
    _reg_hits = []
    for _key in _WIN_REGISTRY_KEYS:
        if _norm(_key) in _joined:
            _reg_hits.append(_key)
    if _reg_hits:
        _results.append({
            "type": "registry_run_key",
            "description": f"Registry Run key persistence ({len(_reg_hits)} keys)",
            "risk": "HIGH",
        })

    # 服务
    _svc_api = sum(1 for a in _WIN_SERVICE_APIS if a.lower() in str(_api_set))
    _svc_str = sum(1 for s in _WIN_SERVICE_STRINGS if s.lower() in _joined)
    if _svc_api >= 2 or _svc_str >= 2:
        _results.append({
            "type": "service_persistence",
            "description": "Windows service creation/configuration detected",
            "risk": "MEDIUM",
        })

    # Scheduled Tasks
    _task_api = sum(1 for a in _WIN_SCHEDULED_TASK_APIS if a.lower() in str(_api_set))
    _task_str = sum(1 for s in _WIN_SCHEDULED_TASK_STRINGS if s.lower() in _joined)
    if _task_api >= 1 or _task_str >= 1:
        _results.append({
            "type": "scheduled_task",
            "description": "Scheduled task persistence detected",
            "risk": "MEDIUM",
        })

    # WMI 事件订阅
    _wmi_hits = [w for w in _WIN_WMI_PERSIST if w.lower() in _joined]
    if len(_wmi_hits) >= 2:
        _results.append({
            "type": "wmi_event_subscription",
            "description": f"WMI event subscription persistence ({len(_wmi_hits)} indicators)",
            "risk": "HIGH",
        })

    # Startup 文件夹
    if any(p.lower() in _joined for p in _WIN_STARTUP_FOLDER):
        _results.append({
            "type": "startup_folder",
            "description": "Startup folder persistence",
            "risk": "MEDIUM",
        })

    # COM 劫持
    _com_hits = sum(1 for c in _WIN_COM_HIJACK if c.lower() in _joined)
    if _com_hits >= 2:
        _results.append({
            "type": "com_hijacking",
            "description": "COM object hijacking indicators",
            "risk": "HIGH",
        })

    # BITS 作业
    if "bits" in _joined and any(k in _joined for k in ["transfer", "job", "background"]):
        _results.append({
            "type": "bits_job",
            "description": "BITS job persistence detected",
            "risk": "MEDIUM",
        })

    # AppInit_DLLs / Winlogon
    _appinit = any("appinit_dlls" in _joined for k in [""]) or "appinit" in _joined
    _winlogon = any("winlogon" in _joined and ("shell" in _joined or "userinit" in _joined))
    if _appinit or _winlogon:
        _results.append({
            "type": "winlogon_appinit",
            "description": "Winlogon/AppInit DLL persistence",
            "risk": "HIGH",
        })

    _risk_score = sum({"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(r["risk"], 0) for r in _results)
    return {
        "platform": "windows",
        "findings": _results,
        "risk_score": _risk_score,
        "detected": len(_results) > 0,
    }


def detect_linux_persistence(imports: dict, strings: list) -> dict:
    _results = []
    _joined = " ".join(
        (s[1] if isinstance(s, tuple) else s).lower()
        for s in strings
    )

    # Cron 检测
    _cron_paths = sum(1 for p in _LINUX_CRON_PATHS if p.lower() in _joined)
    _cron_keywords = sum(1 for k in ["@reboot", "crontab", "cron job"] if k.lower() in _joined)
    if _cron_paths >= 1 or _cron_keywords >= 1:
        _results.append({
            "type": "cron_persistence",
            "description": "Cron-based persistence detected",
            "risk": "MEDIUM" if _cron_keywords >= 2 else "LOW",
        })

    # systemd
    _sysd = sum(1 for p in _LINUX_SYSTEMD_PATHS if p.lower() in _joined)
    if _sysd >= 1:
        _results.append({
            "type": "systemd_persistence",
            "description": "systemd service persistence",
            "risk": "MEDIUM",
        })

    # rc.local / init.d
    _rc_hits = sum(1 for p in _LINUX_RC_PATHS if p.lower() in _joined)
    if _rc_hits >= 1:
        _results.append({
            "type": "rc_script_persistence",
            "description": "rc.local / init.d script persistence",
            "risk": "MEDIUM",
        })

    # Shell 配置修改
    _shell_hits = sum(1 for p in _LINUX_SHELL_MODS if p.lower().replace('~', '') in _joined)
    if _shell_hits >= 1:
        _results.append({
            "type": "shell_rc_modification",
            "description": "Shell configuration file modification",
            "risk": "LOW",
        })

    # LD_PRELOAD
    if any(p.lower() in _joined for p in _LINUX_LD_PRELOAD):
        _results.append({
            "type": "ld_preload",
            "description": "LD_PRELOAD-based persistence",
            "risk": "HIGH",
        })

    # PAM 模块
    _pam_hits = sum(1 for p in _LINUX_PAM_MODS if p.lower() in _joined)
    if _pam_hits >= 2:
        _results.append({
            "type": "pam_module",
            "description": "PAM module persistence",
            "risk": "HIGH",
        })

    # XDG autostart
    if any(p.lower() in _joined for p in _LINUX_XDG_AUTOSTART):
        _results.append({
            "type": "xdg_autostart",
            "description": "XDG autostart desktop entry persistence",
            "risk": "LOW",
        })

    _risk_score = sum({"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(r["risk"], 0) for r in _results)
    return {
        "platform": "linux",
        "findings": _results,
        "risk_score": _risk_score,
        "detected": len(_results) > 0,
    }


def detect_mac_persistence(imports: dict, strings: list) -> dict:
    _results = []
    _joined = " ".join(
        (s[1] if isinstance(s, tuple) else s).lower()
        for s in strings
    )

    # launchd plists
    _launch = sum(1 for p in _MAC_LAUNCHD_PATHS if p.lower() in _joined)
    if _launch >= 1:
        _results.append({
            "type": "launchd_persistence",
            "description": "LaunchAgent/LaunchDaemon persistence",
            "risk": "MEDIUM",
        })

    # Login Items
    _login = sum(1 for p in _MAC_LOGIN_ITEMS if p.lower() in _joined)
    if _login >= 1:
        _results.append({
            "type": "login_item",
            "description": "Login item persistence",
            "risk": "LOW",
        })

    # cron (Mac)
    _mcron = sum(1 for p in _MAC_CRON if p.lower() in _joined)
    if _mcron >= 1:
        _results.append({
            "type": "cron_mac",
            "description": "Mac cron persistence",
            "risk": "LOW",
        })

    _risk_score = sum({"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(r["risk"], 0) for r in _results)
    return {
        "platform": "mac",
        "findings": _results,
        "risk_score": _risk_score,
        "detected": len(_results) > 0,
    }


# //// 统一入口 ////
def detect_all(imports: dict, strings: list, sections: list = None) -> dict:
    """跨平台持久化检测统一入口。

    返回: { "windows": {...}, "linux": {...}, "mac": {...}, "overall_risk": str, "total_findings": int }
    """
    _windows = detect_windows_persistence(imports, strings)
    _linux = detect_linux_persistence(imports, strings)
    _mac = detect_mac_persistence(imports, strings)

    _tot = len(_windows["findings"]) + len(_linux["findings"]) + len(_mac["findings"])
    _max_score = max(_windows["risk_score"], _linux["risk_score"], _mac["risk_score"])

    if _max_score >= 6:
        _overall = "CRITICAL"
    elif _max_score >= 3:
        _overall = "HIGH"
    elif _max_score >= 1:
        _overall = "MEDIUM"
    else:
        _overall = "CLEAN"

    return {
        "windows": _windows,
        "linux": _linux,
        "mac": _mac,
        "overall_risk": _overall,
        "total_findings": _tot,
    }
