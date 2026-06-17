"""
高级持久化威胁检测: 内核回调注册分析模块

功能:
    1. 扫描驱动或内核模块中注册的 PsSetCreateProcessNotifyRoutine 等回调
    2. 分析其是否可能被恶意利用
    3. 检测回调函数代码是否包含可疑操作

核心技术:
    - 已知恶意回调模式: 进程创建、线程创建、镜像加载、对象注册等
    - 可疑 API 序列检测: 权限提升 / 信息窃取 / 持久化
    - 风险评分: 基于行为特征加权
"""

import logging
import re
import json
import time
import threading
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class CallbackType(Enum):
    """回调类型"""
    CREATE_PROCESS = "PsSetCreateProcessNotifyRoutine"
    CREATE_THREAD = "PsSetCreateThreadNotifyRoutine"
    IMAGE_LOAD = "PsSetLoadImageNotifyRoutine"
    OBJECT_CALLBACK = "ObRegisterCallbacks"
    REGISTRY_CALLBACK = "CmRegisterCallback"
    SHUTDOWN = "IoRegisterShutdownNotification"
    POWER = "PoRegisterPowerSettingCallback"
    BUGCHECK = "KeRegisterBugCheckCallback"
    DPC = "KeRegisterBugCheckReasonCallback"
    FILE_SYSTEM = "IoRegisterFileSystem"
    FS_CHANGE = "IoRegisterFsRegistrationChange"
    DRIVER_FS = "IoRegisterDriverReinitialization"
    UNKNOWN = "unknown"


class SuspiciousAction(Enum):
    """可疑动作"""
    KILL_PROCESS = "kill_process"
    HIDE_PROCESS = "hide_process"
    INJECT_CODE = "inject_code"
    HOOK_SSDT = "hook_ssdt"
    MODIFY_TOKEN = "modify_token"
    DISABLE_DRIVER = "disable_driver"
    DISABLE_AV = "disable_av"
    DISABLE_FIREWALL = "disable_firewall"
    DISABLE_DEFENDER = "disable_defender"
    ELEVATE_PRIVILEGE = "elevate_privilege"
    READ_LSASS = "read_lsass"
    KEYLOG = "keylog"
    SCREEN_CAPTURE = "screen_capture"
    PERSIST_REGISTRY = "persist_registry"
    PERSIST_SERVICE = "persist_service"
    NETWORK_CONNECT = "network_connect"
    EXEC_SHELLCODE = "execute_shellcode"
    WRITE_DRIVER = "write_driver"
    WRITE_FILE = "write_file"
    ALLOC_MEMORY = "alloc_memory"
    HIDE_FILE = "hide_file"


@dataclass
class CallbackRoutine:
    """已注册回调例程"""
    callback_type: CallbackType
    address: int
    name: str
    driver_name: str = ""
    module_name: str = ""
    pre_operations: List[str] = field(default_factory=list)  # 应用于 OB 回调
    post_operations: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditFinding:
    """审计发现"""
    callback: CallbackRoutine
    suspicious_actions: List[SuspiciousAction] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    rationale: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class CallbackAuditReport:
    """回调审计报告"""
    driver_module: str
    callbacks: List[CallbackRoutine] = field(default_factory=list)
    findings: List[AuditFinding] = field(default_factory=list)
    overall_risk: float = 0.0
    risk_level: str = "low"
    timestamp: float = 0.0
    notes: str = ""


class SuspiciousPatternLibrary:
    """可疑模式库"""

    KILL_APIS = {
        "ZwTerminateProcess", "NtTerminateProcess",
        "PsTerminateSystemThread", "ZwKill",
    }
    HIDE_APIS = {
        "ZwQuerySystemInformation", "NtQuerySystemInformation",
        "PsLookupProcessByProcessId", "ZwQueryInformationProcess",
    }
    INJECT_APIS = {
        "KeStackAttachProcess", "ZwUnmapViewOfSection", "ZwMapViewOfSection",
        "ZwAllocateVirtualMemory", "NtCreateThreadEx",
    }
    HOOK_APIS = {
        "KeServiceDescriptorTable", "MmGetSystemRoutineAddress",
        "ZwQuerySystemInformation", "InterlockedExchange",
    }
    TOKEN_APIS = {
        "SeSinglePrivilegeCheck", "ZwAdjustPrivilegesToken",
        "PsAssignImpersonationToken", "PsImpersonateClient",
    }
    DISABLE_AV = {
        "OpenSCManagerW", "OpenServiceW", "ControlService",
        "ZwUnloadDriver", "ZwLoadDriver",
    }
    LSASS_APIS = {
        "MiniDumpWriteDump", "DbgHelp.dll",
        "RtlAdjustPrivilege", "SeDebugPrivilege",
    }
    KEYLOG_APIS = {
        "SetWindowsHookExW", "SetWindowsHookExA", "GetAsyncKeyState",
        "GetKeyboardState", "AttachThreadInput",
    }
    PERSIST_REG = {
        "RegSetValueExW", "RegCreateKeyExW", "NtSetValueKey",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    }
    PERSIST_SVC = {
        "CreateServiceW", "OpenSCManagerW", "ChangeServiceConfigW",
        "NtLoadDriver", "ZwLoadDriver", "IoCreateDriver",
    }
    DISABLE_APIS = {
        "OpenSCManagerW", "OpenServiceW", "ControlService",
        "ZwUnloadDriver", "ZwLoadDriver",
    }
    NETWORK_APIS = {
        "WSAStartup", "socket", "connect", "send", "recv",
        "HttpSendRequestW", "InternetOpenW", "InternetConnectW",
        "WdfSend", "TcpTcbInsert",
    }
    SHELLCODE_APIS = {
        "VirtualAlloc", "VirtualProtect", "CreateThread",
        "ZwAllocateVirtualMemory", "ZwProtectVirtualMemory",
    }
    DRIVER_LOAD = {
        "ZwLoadDriver", "NtLoadDriver", "IoCreateDriver",
        "IoCreateSymbolicLink", "IoCreateDevice",
    }
    ALLOC_APIS = {
        "ExAllocatePoolWithTag", "ExAllocatePool", "VirtualAlloc",
        "ZwAllocateVirtualMemory", "malloc", "calloc",
    }
    HIDE_FILE = {
        "ZwSetInformationFile", "NtSetInformationFile",
        "SetFileAttributesW", "SetFileTime",
    }

    SUSPICIOUS_GROUPS: Dict[SuspiciousAction, Set[str]] = {
        SuspiciousAction.KILL_PROCESS: KILL_APIS,
        SuspiciousAction.HIDE_PROCESS: HIDE_APIS,
        SuspiciousAction.INJECT_CODE: INJECT_APIS,
        SuspiciousAction.HOOK_SSDT: HOOK_APIS,
        SuspiciousAction.MODIFY_TOKEN: TOKEN_APIS,
        SuspiciousAction.DISABLE_AV: DISABLE_AV,
        SuspiciousAction.DISABLE_FIREWALL: DISABLE_APIS,
        SuspiciousAction.DISABLE_DRIVER: DISABLE_APIS,
        SuspiciousAction.DISABLE_DEFENDER: DISABLE_APIS,
        SuspiciousAction.ELEVATE_PRIVILEGE: TOKEN_APIS,
        SuspiciousAction.READ_LSASS: LSASS_APIS,
        SuspiciousAction.KEYLOG: KEYLOG_APIS,
        SuspiciousAction.SCREEN_CAPTURE: {"BitBlt", "CreateCompatibleDC", "GetDC"},
        SuspiciousAction.PERSIST_REGISTRY: PERSIST_REG,
        SuspiciousAction.PERSIST_SERVICE: PERSIST_SVC,
        SuspiciousAction.NETWORK_CONNECT: NETWORK_APIS,
        SuspiciousAction.EXEC_SHELLCODE: SHELLCODE_APIS,
        SuspiciousAction.WRITE_DRIVER: DRIVER_LOAD,
        SuspiciousAction.WRITE_FILE: {"ZwWriteFile", "NtWriteFile", "WriteFile"},
        SuspiciousAction.ALLOC_MEMORY: ALLOC_APIS,
        SuspiciousAction.HIDE_FILE: HIDE_FILE,
    }


class CallbackRegistryExtractor:
    """回调注册表提取器"""

    def __init__(self):
        self._lock = threading.Lock()

    def extract_from_iat(self, imports: List[str]) -> List[CallbackRoutine]:
        """从导入表提取"""
        routines: List[CallbackRoutine] = []
        for imp in imports:
            for cb_type in CallbackType:
                if cb_type.value in imp:
                    routines.append(CallbackRoutine(
                        callback_type=cb_type,
                        address=0,
                        name=imp,
                    ))
                    break
        return routines

    def extract_from_strings(self, strings: List[str]) -> List[CallbackRoutine]:
        """从字符串提取"""
        routines: List[CallbackRoutine] = []
        for s in strings:
            for cb_type in CallbackType:
                if cb_type.value in s:
                    routines.append(CallbackRoutine(
                        callback_type=cb_type,
                        address=0,
                        name=s,
                    ))
                    break
        return routines

    def extract_from_callgraph(
        self,
        func_name: str,
        callees: List[str]
    ) -> Optional[CallbackRoutine]:
        """从调用图提取"""
        for cb_type in CallbackType:
            if cb_type.value in func_name:
                return CallbackRoutine(
                    callback_type=cb_type,
                    address=0,
                    name=func_name,
                    raw_data={"callees": callees},
                )
        return None


class CallbackRiskScorer:
    """回调风险评分器"""

    HIGH_RISK_ACTIONS = {
        SuspiciousAction.HIDE_PROCESS,
        SuspiciousAction.READ_LSASS,
        SuspiciousAction.INJECT_CODE,
        SuspiciousAction.HOOK_SSDT,
        SuspiciousAction.DISABLE_DEFENDER,
        SuspiciousAction.WRITE_DRIVER,
    }

    PERSISTENCE_ACTIONS = {
        SuspiciousAction.PERSIST_REGISTRY,
        SuspiciousAction.PERSIST_SERVICE,
    }

    def __init__(self):
        self._lock = threading.Lock()

    def score(self, actions: List[SuspiciousAction], callback_type: CallbackType) -> Tuple[float, str]:
        """返回(分数, 等级)"""
        with self._lock:
            score = 0.0
            for a in actions:
                if a in self.HIGH_RISK_ACTIONS:
                    score += 0.4
                elif a in self.PERSISTENCE_ACTIONS:
                    score += 0.2
                else:
                    score += 0.1

            # 回调类型加权
            if callback_type in (CallbackType.OBJECT_CALLBACK, CallbackType.CREATE_PROCESS):
                score *= 1.2
            elif callback_type in (CallbackType.IMAGE_LOAD,):
                score *= 1.1

            score = min(1.0, score)
            if score >= 0.7:
                level = "critical"
            elif score >= 0.5:
                level = "high"
            elif score >= 0.3:
                level = "medium"
            else:
                level = "low"
            return score, level


class CallbackAuditor:
    """回调审计器 (主入口)"""

    def __init__(self):
        self.patterns = SuspiciousPatternLibrary()
        self.extractor = CallbackRegistryExtractor()
        self.scorer = CallbackRiskScorer()
        self._lock = threading.Lock()

    def _scan_callback_function(
        self,
        callback: CallbackRoutine,
        callees: List[str],
        strings: List[str]
    ) -> List[SuspiciousAction]:
        """扫描回调函数中的可疑动作"""
        actions: List[SuspiciousAction] = []
        for action, apis in self.patterns.SUSPICIOUS_GROUPS.items():
            for c in callees:
                for api in apis:
                    if api in c:
                        actions.append(action)
                        break
            for s in strings:
                for api in apis:
                    if api in s:
                        actions.append(action)
                        break
        return list(set(actions))

    def audit(
        self,
        driver_module: str,
        imports: List[str],
        strings: List[str],
        callgraph: Optional[Dict[str, List[str]]] = None
    ) -> CallbackAuditReport:
        """审计驱动模块"""
        with self._lock:
            report = CallbackAuditReport(driver_module=driver_module)
            # 提取回调
            callbacks = self.extractor.extract_from_iat(imports)
            callbacks += self.extractor.extract_from_strings(strings)
            if callgraph:
                for func, callees in callgraph.items():
                    cb = self.extractor.extract_from_callgraph(func, callees)
                    if cb:
                        callbacks.append(cb)

            # 去重
            seen: Set[Tuple[CallbackType, str]] = set()
            unique_cbs: List[CallbackRoutine] = []
            for cb in callbacks:
                key = (cb.callback_type, cb.name)
                if key not in seen:
                    seen.add(key)
                    unique_cbs.append(cb)
            report.callbacks = unique_cbs

            # 审计每个回调
            for cb in unique_cbs:
                callees = callgraph.get(cb.name, []) if callgraph else []
                actions = self._scan_callback_function(cb, callees, strings)
                if not actions:
                    continue
                score, level = self.scorer.score(actions, cb.callback_type)
                rationale: List[str] = []
                recs: List[str] = []
                for a in actions:
                    rationale.append(f"检测到可疑动作: {a.value}")
                    if a in CallbackRiskScorer.HIGH_RISK_ACTIONS:
                        recs.append(f"立即调查 {a.value}, 可能是恶意行为")
                if level in ("high", "critical"):
                    recs.append("建议在沙箱中隔离并深度分析")
                report.findings.append(AuditFinding(
                    callback=cb,
                    suspicious_actions=actions,
                    risk_score=score,
                    risk_level=level,
                    rationale=rationale,
                    recommendations=recs,
                ))

            # 整体风险
            if report.findings:
                avg = sum(f.risk_score for f in report.findings) / len(report.findings)
                report.overall_risk = avg
                if avg >= 0.7:
                    report.risk_level = "critical"
                elif avg >= 0.5:
                    report.risk_level = "high"
                elif avg >= 0.3:
                    report.risk_level = "medium"
                else:
                    report.risk_level = "low"
            report.timestamp = time.time()
            report.notes = f"审计了 {len(unique_cbs)} 个回调, 发现 {len(report.findings)} 个可疑"
            return report

    def audit_driver(
        self,
        driver_path: str,
        imports: Optional[List[str]] = None,
        strings: Optional[List[str]] = None,
        callgraph: Optional[Dict[str, List[str]]] = None
    ) -> CallbackAuditReport:
        """审计驱动文件"""
        if imports is None:
            imports = []
        if strings is None:
            strings = []
        if callgraph is None:
            callgraph = {}
        return self.audit(driver_path, imports, strings, callgraph)


# 便捷入口
def audit_driver_callbacks(
    driver_module: str,
    imports: List[str],
    strings: List[str],
    callgraph: Optional[Dict[str, List[str]]] = None
) -> CallbackAuditReport:
    auditor = CallbackAuditor()
    return auditor.audit(driver_module, imports, strings, callgraph)
