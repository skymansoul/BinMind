import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import pathlib

logger = logging.getLogger(__name__)


class CallbackType:
    """内核回调类型枚举。"""
    PROCESS_NOTIFY = "process_notify"
    THREAD_NOTIFY = "thread_notify"
    IMAGE_LOAD_NOTIFY = "image_load_notify"
    REGISTRY_CALLBACK = "registry_callback"
    OB_CALLBACK = "object_manager_callback"
    BUGCHECK_CALLBACK = "bugcheck_callback"
    POWER_CALLBACK = "power_callback"
    SHUTDOWN_CALLBACK = "shutdown_callback"
    IRP_MJ_CREATE = "irp_mj_create"
    IRP_MJ_DEVICE_CONTROL = "irp_mj_device_control"
    IRP_MJ_INTERNAL_DEVICE_CONTROL = "irp_mj_internal_device_control"
    ETW_TAMPER = "etw_tamper"
    MINIFILTER_ALTITUDE = "minifilter_altitude"
    WFP_CALLOUT = "wfp_callout"
    SSDT_HOOK = "ssdt_hook"
    DKOM_INDICATOR = "dkom_indicator"
    PATCHGUARD_TAMPER = "patchguard_tamper"
    HYPERVISOR_PRESENCE = "hypervisor_presence"
    MSR_SYSCALL_HOOK = "msr_syscall_hook"
    APC_INJECTION = "apc_injection"
    OBJECT_TYPE_CALLBACK = "object_type_callback"
    DSE_DISABLE = "dse_disable"
    HWBP_BYPASS = "hwbp_bypass"
    INDIRECT_SYSCALL = "indirect_syscall"
    CALLBACK_ZERO_OUT = "callback_zero_out"
    AMSI_PATCH = "amsi_patch"
    EDR_POLICY_SILENCE = "edr_policy_silence"
    WNF_CALLBACK = "wnf_callback"
    DMA_GUARD = "dma_guard"
    DMA_ATTACK = "dma_attack_indicator"

# MITRE ATT&CK 技术映射
# 每个回调类型对应的 ATT&CK (sub-)technique ID(s)
CALLBACK_ATTACK_MAPPING = {
    "process_notify": ["T1057", "T1543.003"],
    "thread_notify": ["T1055", "T1055.001"],
    "image_load_notify": ["T1574", "T1574.002"],
    "registry_callback": ["T1112", "T1547.001"],
    "object_manager_callback": ["T1014", "T1562.001"],
    "etw_tamper": ["T1562.001", "T1562.006"],
    "minifilter_altitude": ["T1562.001", "T1014"],
    "wfp_callout": ["T1562.004", "T1014"],
    "ssdt_hook": ["T1014", "T1562.001"],
    "dkom_indicator": ["T1014", "T1562"],
    "patchguard_tamper": ["T1562.001", "T1014"],
    "hypervisor_presence": ["T1014", "T1562"],
    "msr_syscall_hook": ["T1562.001", "T1014"],
    "apc_injection": ["T1055", "T1055.004"],
    "object_type_callback": ["T1562.001", "T1014"],
    "dse_disable": ["T1562.001", "T1543.003"],
    "hwbp_bypass": ["T1562.001", "T1055"],
    "indirect_syscall": ["T1562.001", "T1055"],
    "callback_zero_out": ["T1562.001", "T1014"],
    "amsi_patch": ["T1562.001"],
    "edr_policy_silence": ["T1562.001", "T1562"],
    "wnf_callback": ["T1547", "T1546"],
    "dma_guard": ["T1562"],
    "dma_attack_indicator": ["T1014", "T1068"],
}


# IRP 主功能码映射
_IRP_MJ_NAMES: Dict[int, str] = {
    0x00: "IRP_MJ_CREATE", 0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE", 0x03: "IRP_MJ_READ", 0x04: "IRP_MJ_WRITE",
    0x05: "IRP_MJ_QUERY_INFORMATION", 0x06: "IRP_MJ_SET_INFORMATION",
    0x07: "IRP_MJ_QUERY_EA", 0x08: "IRP_MJ_SET_EA",
    0x09: "IRP_MJ_FLUSH_BUFFERS", 0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    0x0B: "IRP_MJ_SET_VOLUME_INFORMATION", 0x0C: "IRP_MJ_DIRECTORY_CONTROL",
    0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL", 0x0E: "IRP_MJ_DEVICE_CONTROL",
    0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN", 0x12: "IRP_MJ_CLEANUP",
    0x13: "IRP_MJ_CREATE_MAILSLOT", 0x14: "IRP_MJ_QUERY_SECURITY",
    0x15: "IRP_MJ_SET_SECURITY", 0x16: "IRP_MJ_POWER",
    0x17: "IRP_MJ_SYSTEM_CONTROL", 0x18: "IRP_MJ_DEVICE_CHANGE",
    0x19: "IRP_MJ_QUERY_QUOTA", 0x1A: "IRP_MJ_SET_QUOTA",
    0x1B: "IRP_MJ_PNP",
}

# ETW 篡改指示器
_ETW_TAMPER_INDICATORS = [
    "EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteTransfer",
    "EtwNotificationRegister", "EtwTraceMessage",
    "NtTraceEvent", "EtwRegisterGuids",
]

# WFP 标注 API
_WFP_CALLOUT_APIS = [
    "FwpsCalloutRegister", "FwpsCalloutRegister0", "FwpsCalloutRegister1",
    "FwpsCalloutRegister2", "FwpsCalloutRegister3",
    "FwpmSubLayerAdd", "FwpmFilterAdd",
]

# 微过滤器高度可疑范围
_MINIFILTER_SUSPICIOUS_RANGES: list[tuple[int, int, str]] = [
    (0, 10000, "低于标准 AV 高度范围 — 可能是隐蔽注入"),
    (300000, 329999, "预留区域 — 仅内核组件应在此范围"),
    (400000, 429999, "接近顶部 — 可截获所有文件操作"),
]

# SSDT hook 特征
_SSDT_HOOK_INDICATORS = [
    "NtQuerySystemInformation", "NtQueryDirectoryFile",
    "NtEnumerateKey", "NtEnumerateValueKey",
    "NtOpenProcess", "NtCreateThread", "NtTerminateProcess",
    "NtDeviceIoControlFile", "NtQueryInformationProcess",
    "NtSetInformationProcess", "NtDuplicateObject",
    "ZwQuerySystemInformation", "ZwQueryDirectoryFile",
]

# DKOM 检测 — 利用 ActiveProcessLinks 以外枚举路径的 API
# DKOM 仅断开进程链表，无法同时从 PspCidTable 或 csrss 句柄表中移除条目。
# 交叉视图不一致即为 DKOM 证据。
_DKOM_CROSS_VIEW_APIS = [
    "NtQuerySystemInformation",  # SystemProcessInformation — 链表遍历
    "PspCidTable",                # 句柄表遍历（Volatility psxview 原理）
    "CsrGetProcessId",            # csrss 句柄表
    "ZwQueryInformationProcess",  # 独立于 ActiveProcessLinks
]

# PatchGuard 篡改检测 — 若程序引用了 PG 上下文初始化或
# KeBugCheckEx 的钩子，可能正在尝试绕过 Kernel Patch Protection
_PATCHGUARD_TAMPER_INDICATORS = [
    "KiInitializePatchGuard", "KeBugCheckEx", "KeBugCheck2",
    "KdpTrap", "KiSystemServiceCopyEnd", "ExpTimeRefreshDpc",
    "KiFilterFiberContext",   # PatchGuard DPC 上下文
    "HalpMcaLogArbiterLock",  # MCA 处理（PG 触发路径）
]

# 虚拟化检测 — VMX/SVM 指令或 MSR 访问模式
_HYPERVISOR_INDICATORS = [
    "vmxon", "vmxoff", "vmcall", "vmclear", "vmptrld", "vmptrst",
    "vmread", "vmwrite", "vmlaunch", "vmresume",
    "svm_vmrun", "skinit", "clgi", "stgi",
    "MSR_IA32_FEATURE_CONTROL", "MSR_IA32_VMX_BASIC",
    "MSR_VM_HSAVE_PA", "EPT", "VPID",
]

# MSR_LSTAR / IA32_SYSENTER_EIP — 系统调用入口点
# 若被修改指向非 ntoskrnl 地址，即为 syscall hook
_MSR_SYSCALL_HOOK_TARGETS = [
    "MSR_LSTAR", "MSR_CSTAR", "MSR_SFMASK",
    "IA32_SYSENTER_EIP", "IA32_SYSENTER_ESP",
    "KiSystemCall64", "KiSystemCall32",
    "HalpApic1EndOfInterrupt",
]

# APC 注入检测 — 用户态 APC 可被 rootkit 用于向
# 用户态进程注入 shellcode（如 Equation Group 的 DoublePulsar）
_APC_INJECTION_APIS = [
    "KeInsertQueueApc", "KiInsertQueueApc",
    "NtQueueApcThread", "NtQueueApcThreadEx",
    "KeInitializeApc", "ZwAlertThread",
    "PsGetContextThread", "PsSetContextThread",
]

# 对象类型回调 — PsProcessType/PsThreadType 的回调注册
# 比 ObRegisterCallbacks 更底层的拦截点
_OBJECT_TYPE_CALLBACK_APIS = [
    "ObCreateObjectType", "ObRegisterCallbacks",
    "PsProcessType", "PsThreadType", "PsJobType",
    "IoFileObjectType", "ExDesktopObjectType",
    "ObpCreateHandle", "ObpIncrementHandleCount",
]

# DSE 禁用 — 引导配置或注册表篡改以禁用驱动签名强制
_DSE_DISABLE_INDICATORS = [
    "g_CiEnabled",          # CI.dll 的全局开关
    "CiInitialize",         # 代码完整性初始化
    "SeCiValidateImageData", # 签名验证路径
    "BCDE_LIBRARY_TYPE",    # BCD 禁用 DSE 的标志
    "TESTSIGNING", "DISABLE_INTEGRITY_CHECKS",
]

# HWBP (Hardware Breakpoint) patchless bypass — Praetorian 2025
# 使用 NtContinue 设置 DR0-DR7 寄存器以劫持 ETW/AMSI 函数
# 而不修改内存字节，也不触发 SetThreadContext 的 ETW-TI 事件
_HWBP_BYPASS_INDICATORS = [
    "NtContinue", "RtlRestoreContext", "NtSetContextThread",
    "Dr0", "Dr1", "Dr6", "Dr7",
    "SetThreadContext",  # 传统方法 — HWBP 绕过是对此的升级
    "CONTEXT_DEBUG_REGISTERS",
]

# 间接系统调用 + 栈欺骗 — EDR 规避的高级形式
# 从 ntdll.dll 的合法地址执行 syscall 指令，同时伪造调用栈
_INDIRECT_SYSCALL_INDICATORS = [
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
    "NtProtectVirtualMemory", "NtCreateThreadEx",
    "syscall", "sysenter",
    "ntdll.dll", "Wow64Transition",
    "RtlUserThreadStart",
]

# 内核回调数组归零 — 直接在内核内存中清除 EDR 注册的回调
# 极其危险：触发 PatchGuard BSOD 0x109 (CRITICAL_STRUCTURE_CORRUPTION)
_CALLBACK_ZERO_OUT_INDICATORS = [
    "PspCreateProcessNotifyRoutine", "PspCreateThreadNotifyRoutine",
    "PspLoadImageNotifyRoutine", "CallbackListDelete",
    "ExCompareExchangeCallBack", "CmUnRegisterCallback",
    "ObUnRegisterCallbacks",
    # PatchGuard 绕过尝试
    "MmMapIoSpaceEx", "HalReturnToFirmware",
    "KiBugCheckDispatch", "KeBugCheckEx",
]

# AMSI 补丁 — EDR bypass 的第一步通常禁用 AMSI
_AMSI_PATCH_INDICATORS = [
    "AmsiInitialize", "AmsiScanBuffer", "AmsiScanString",
    "AmsiOpenSession", "AmsiCloseSession",
    # 修补者的常用手法：补丁为 0xC3 (ret) 或修改 DllCanUnloadNow
    "NtProtectVirtualMemory", "VirtualProtect",
    "DllCanUnloadNow",
]

# EDR 策略静默 — 通过 WDAC/AppLocker 策略禁用 EDR 组件
_EDR_POLICY_SILENCE_INDICATORS = [
    "WldpSetDynamicCodeTrust", "WldpQueryDynamicCodeTrust",
    "CiSetTrustedOriginClaimId", "ZwSetSystemInformation",
    "SystemPolicyInformation", "AppLocker",
    "WDAC", "DeviceGuard",
    "NtSetSystemInformation",
]

# 扩展的线程池定时器 ETW 规避
# 使用 TpAllocTimer → TpSetTimer 创建用户态定时器，
# 在回调中执行 ETW 补丁，绕过 ETW-TI 的 syscall 监控
_THREADPOOL_ETW_EVASION = [
    "TpAllocTimer", "TpSetTimer", "TpWaitForTimer",
    "CreateThreadpoolTimer", "SetThreadpoolTimer",
    "WaitForThreadpoolTimerCallbacks",
]

# WNF (Windows Notification Facility) 回调 — 极少被 EDR 监控的持久化路径
_WNF_CALLBACK_INDICATORS = [
    "NtUpdateWnfStateData", "NtQueryWnfStateData",
    "NtSubscribeWnfStateChange", "RtlSubscribeWnfStateChangeNotification",
    "WNF_SHEL_EXECUTE", "WNF_EXTANT",
]

# DMA 攻击指示器 — PCIe MITM (Heino 2.0) / Thunderbolt DMA / M.2 固件篡改
_DMA_ATTACK_INDICATORS = [
    "PCIE_ATS", "PRI_ENABLE", "PASID_ENABLE",
    "MSR_IA32_VMX_PROCBASED_CTLS2",  # EPT 子页级 DMA 绕过
    "DMAR", "DMA_REMAPPING_STRUCTURE",
    "IntelRtd3Vrc", "ThunderboltNHI",
    "PCIBusDriver", "pci.sys",
    "HalpDmaSyncMapBuffer", "HalpDmaAllocateAdapter",
    "MmMapIoSpaceEx",  # 物理内存映射 → DMA 读写
    "HalGetBusDataByOffset",  # PCI 配置空间读取 — MITM 设备枚举
]

# DMA Guard 策略检测
_DMA_GUARD_INDICATORS = [
    "DmaGuard", "KernelDmaProtection",
    "DMA_REMAPPING_POLICY",
    "IoMmu", "HalpIommu",
    "DmaRemappingEnabled",
]


class KernelCallback:
    __slots__ = ('callback_id', 'callback_type', 'driver_name',
                 'registration_api', 'altitude', 'is_suspicious', 'reason',
                 'extra_evidence',)

    def __init__(self, callback_id="", callback_type="", driver_name="",
                 registration_api="", altitude="", is_suspicious=False,
                 reason="", extra_evidence=None):
        self.callback_id = callback_id
        self.callback_type = callback_type
        self.driver_name = driver_name
        self.registration_api = registration_api
        self.altitude = altitude
        self.is_suspicious = is_suspicious
        self.reason = reason
        self.extra_evidence: list[str] = extra_evidence or []

    def to_dict(self) -> Dict[str, Any]:
        cb_type = self.callback_type
        type_val = cb_type.value if hasattr(cb_type, 'value') else str(cb_type)
        return {
            'callback_id': self.callback_id,
            'type': type_val,
            'driver': self.driver_name,
            'api': self.registration_api,
            'altitude': self.altitude,
            'is_suspicious': self.is_suspicious,
            'reason': self.reason,
            'extra_evidence': self.extra_evidence,
        }


class WindowsKernelCallbackDetector:

    CALLBACK_APIS = {
        CallbackType.PROCESS_NOTIFY: [
            'PsSetCreateProcessNotifyRoutine',
            'PsSetCreateProcessNotifyRoutineEx',
            'PsSetCreateProcessNotifyRoutineEx2'],
        CallbackType.THREAD_NOTIFY: [
            'PsSetCreateThreadNotifyRoutine',
            'PsSetCreateThreadNotifyRoutineEx'],
        CallbackType.IMAGE_LOAD_NOTIFY: [
            'PsSetLoadImageNotifyRoutine',
            'PsSetLoadImageNotifyRoutineEx'],
        CallbackType.REGISTRY_CALLBACK: [
            'CmRegisterCallback', 'CmRegisterCallbackEx'],
        CallbackType.OB_CALLBACK: [
            'ObRegisterCallbacks'],
        CallbackType.BUGCHECK_CALLBACK: [
            'KeRegisterBugCheckCallback',
            'KeRegisterBugCheckReasonCallback'],
        CallbackType.POWER_CALLBACK: [
            'PoRegisterPowerSettingCallback',
            'IoRegisterShutdownNotification'],
        CallbackType.IRP_MJ_DEVICE_CONTROL: [
            'IRP_MJ_DEVICE_CONTROL', 'DriverObject->MajorFunction'],
        CallbackType.MINIFILTER_ALTITUDE: [
            'FltRegisterFilter', 'FltStartFiltering'],
        CallbackType.WFP_CALLOUT: [
            'FwpsCalloutRegister', 'FwpsCalloutRegister0',
            'FwpsCalloutRegister1', 'FwpsCalloutRegister2',
            'FwpsCalloutRegister3'],
        CallbackType.OBJECT_TYPE_CALLBACK: [
            'PsProcessType', 'PsThreadType', 'ObCreateObjectType'],
        CallbackType.APC_INJECTION: [
            'KeInsertQueueApc', 'NtQueueApcThread', 'KeInitializeApc'],
        CallbackType.WNF_CALLBACK: [
            'NtUpdateWnfStateData', 'RtlSubscribeWnfStateChangeNotification'],
    }

    SUSPICIOUS_COMBOS = [
        (CallbackType.PROCESS_NOTIFY, CallbackType.OB_CALLBACK),
        (CallbackType.PROCESS_NOTIFY, CallbackType.IMAGE_LOAD_NOTIFY),
        (CallbackType.OB_CALLBACK, CallbackType.REGISTRY_CALLBACK),
        (CallbackType.PROCESS_NOTIFY, CallbackType.IRP_MJ_DEVICE_CONTROL),
        (CallbackType.OB_CALLBACK, CallbackType.MINIFILTER_ALTITUDE),
        (CallbackType.ETW_TAMPER, CallbackType.PROCESS_NOTIFY),
        (CallbackType.DKOM_INDICATOR, CallbackType.PROCESS_NOTIFY),
        (CallbackType.DSE_DISABLE, CallbackType.PROCESS_NOTIFY),
        (CallbackType.MSR_SYSCALL_HOOK, CallbackType.PATCHGUARD_TAMPER),
        (CallbackType.HWBP_BYPASS, CallbackType.ETW_TAMPER),
        (CallbackType.INDIRECT_SYSCALL, CallbackType.AMSI_PATCH),
        (CallbackType.CALLBACK_ZERO_OUT, CallbackType.PROCESS_NOTIFY),
        (CallbackType.EDR_POLICY_SILENCE, CallbackType.DSE_DISABLE),
        (CallbackType.DMA_ATTACK, CallbackType.HYPERVISOR_PRESENCE),
    ]

    def __init__(self):
        self._findings: List[KernelCallback] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"CALLBACK-{self._counter:04d}"

    def detect_from_apis(self, api_calls: List[str]) -> List[KernelCallback]:
        findings = []
        api_lower = [c.lower() for c in api_calls]
        for cb_type, apis in self.CALLBACK_APIS.items():
            for api in apis:
                if api.lower() in api_lower:
                    findings.append(KernelCallback(
                        callback_id=self._next_id(),
                        callback_type=cb_type,
                        registration_api=api,
                        is_suspicious=cb_type in (
                            CallbackType.OB_CALLBACK,
                            CallbackType.PROCESS_NOTIFY,
                            CallbackType.MINIFILTER_ALTITUDE,
                            CallbackType.WFP_CALLOUT,
                            CallbackType.APC_INJECTION),
                        reason=('内核回调例程' if cb_type not in (
                            CallbackType.OB_CALLBACK,) else
                            '对象管理器回调')))
        return findings

    def detect_from_strings(self, strings_data: List[str]) -> List[KernelCallback]:
        findings = []
        strings_combined = ' '.join(strings_data)

        # 主回调 API 扫描
        for cb_type, apis in self.CALLBACK_APIS.items():
            for api in apis:
                if api in strings_combined:
                    findings.append(KernelCallback(
                        callback_id=self._next_id(),
                        callback_type=cb_type,
                        registration_api=api,
                        is_suspicious=True,
                        reason=f'{api} 字符串引用 — 内核驱动组件'))

        # ETW 篡改
        for indicator in _ETW_TAMPER_INDICATORS:
            if indicator in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.ETW_TAMPER,
                    registration_api=indicator,
                    is_suspicious=True,
                    reason=f'ETW 篡改指示器: {indicator} — EDR/Rootkit 常用 ETW 劫持'))

        # WFP 标注驱动
        for wfp_api in _WFP_CALLOUT_APIS:
            if wfp_api in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.WFP_CALLOUT,
                    registration_api=wfp_api,
                    is_suspicious=True,
                    reason=f'WFP 标注注册: {wfp_api} — 网络栈过滤'))

        # SSDT hook
        for ssdt_sym in _SSDT_HOOK_INDICATORS:
            if ssdt_sym in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.SSDT_HOOK,
                    registration_api=ssdt_sym,
                    is_suspicious=True,
                    reason=f'SSDT 敏感函数引用: {ssdt_sym} — 可能为 SSDT hook 目标'))

        # DKOM 交叉视图检测
        for cross_api in _DKOM_CROSS_VIEW_APIS:
            if cross_api in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.DKOM_INDICATOR,
                    registration_api=cross_api,
                    is_suspicious=True,
                    reason=f'DKOM 检测指示器: {cross_api} — 交叉视图枚举'))

        # PatchGuard 篡改
        for pg_indicator in _PATCHGUARD_TAMPER_INDICATORS:
            if pg_indicator in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.PATCHGUARD_TAMPER,
                    registration_api=pg_indicator,
                    is_suspicious=True,
                    reason=f'PatchGuard 篡改指示器: {pg_indicator}'))

        # 虚拟化检测
        for hyper_indicator in _HYPERVISOR_INDICATORS:
            if hyper_indicator in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.HYPERVISOR_PRESENCE,
                    registration_api=hyper_indicator,
                    is_suspicious=True,
                    reason=f'虚拟化指示器: {hyper_indicator} — VMX/SVM 指令或 MSR'))

        # MSR 系统调用 hook
        for msr_target in _MSR_SYSCALL_HOOK_TARGETS:
            if msr_target in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.MSR_SYSCALL_HOOK,
                    registration_api=msr_target,
                    is_suspicious=True,
                    reason=f'MSR 系统调用入口: {msr_target} — 可能的 syscall hook 目标'))

        # APC 注入
        for apc_api in _APC_INJECTION_APIS:
            if apc_api in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.APC_INJECTION,
                    registration_api=apc_api,
                    is_suspicious=True,
                    reason=f'APC 注入 API: {apc_api} — 用户态代码注入路径'))

        # 对象类型回调
        for obj_api in _OBJECT_TYPE_CALLBACK_APIS:
            if obj_api in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.OBJECT_TYPE_CALLBACK,
                    registration_api=obj_api,
                    is_suspicious=True,
                    reason=f'对象类型回调: {obj_api} — 底层对象拦截'))

        # DSE 禁用
        for dse_indicator in _DSE_DISABLE_INDICATORS:
            if dse_indicator in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.DSE_DISABLE,
                    registration_api=dse_indicator,
                    is_suspicious=True,
                    reason=f'DSE 禁用指示器: {dse_indicator} — 驱动签名强制绕过'))

        # HWBP patchless bypass (Praetorian 2025)
        for hwbp_ind in _HWBP_BYPASS_INDICATORS:
            if hwbp_ind in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.HWBP_BYPASS,
                    registration_api=hwbp_ind,
                    is_suspicious=True,
                    reason=f'HWBP 绕过指示器: {hwbp_ind} — NtContinue+DR 寄存器劫持'))

        # 间接系统调用 + 栈欺骗
        for ind_sys in _INDIRECT_SYSCALL_INDICATORS:
            if ind_sys in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.INDIRECT_SYSCALL,
                    registration_api=ind_sys,
                    is_suspicious=True,
                    reason=f'间接 syscall 指示器: {ind_sys} — EDR 用户态 hook 绕过'))

        # 内核回调归零
        for czo in _CALLBACK_ZERO_OUT_INDICATORS:
            if czo in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.CALLBACK_ZERO_OUT,
                    registration_api=czo,
                    is_suspicious=True,
                    reason=f'回调归零指示器: {czo} — 内核回调数组篡改 (触发 PG: 0x109)'))

        # AMSI 补丁
        for amsi_api in _AMSI_PATCH_INDICATORS:
            if amsi_api in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.AMSI_PATCH,
                    registration_api=amsi_api,
                    is_suspicious=True,
                    reason=f'AMSI 补丁指示器: {amsi_api} — 反恶意软件扫描接口禁用'))

        # EDR 策略静默
        for edr_pol in _EDR_POLICY_SILENCE_INDICATORS:
            if edr_pol in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.EDR_POLICY_SILENCE,
                    registration_api=edr_pol,
                    is_suspicious=True,
                    reason=f'EDR 策略静默: {edr_pol} — WDAC/AppLocker 策略操控'))

        # 线程池 ETW 规避
        for tp_evasion in _THREADPOOL_ETW_EVASION:
            if tp_evasion in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.ETW_TAMPER,
                    registration_api=tp_evasion,
                    is_suspicious=True,
                    reason=f'线程池 ETW 规避: {tp_evasion} — 异步定时器绕过 syscall 监控'))

        # WNF 回调 — 隐蔽持久化路径
        for wnf_ind in _WNF_CALLBACK_INDICATORS:
            if wnf_ind in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.WNF_CALLBACK,
                    registration_api=wnf_ind,
                    is_suspicious=True,
                    reason=f'WNF 回调指示器: {wnf_ind} — Windows 通知设施持久化'))

        # DMA 攻击检测
        for dma_ind in _DMA_ATTACK_INDICATORS:
            if dma_ind in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.DMA_ATTACK,
                    registration_api=dma_ind,
                    is_suspicious=True,
                    reason=f'DMA 攻击指示器: {dma_ind} — PCIe MITM/Thunderbolt DMA'))

        # DMA Guard 策略
        for guard_ind in _DMA_GUARD_INDICATORS:
            if guard_ind in strings_combined:
                findings.append(KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.DMA_GUARD,
                    registration_api=guard_ind,
                    is_suspicious=False,
                    reason=f'DMA Guard 策略引用: {guard_ind}'))

        return findings

    def detect_irp_hooks(self, driver_irp_table: Dict[int, str]) -> List[KernelCallback]:
        findings = []
        for mj_code, handler in driver_irp_table.items():
            mj_name = _IRP_MJ_NAMES.get(mj_code, f"IRP_MJ_{mj_code:02x}")
            suspicious = (
                handler.startswith("0x") and
                not handler.startswith("0xfffff800")
            )
            findings.append(KernelCallback(
                callback_id=self._next_id(),
                callback_type=CallbackType.IRP_MJ_DEVICE_CONTROL,
                registration_api=mj_name,
                is_suspicious=suspicious,
                reason=f'{mj_name} → {handler}' +
                       (' [非内核模块地址]' if suspicious else ''),
                extra_evidence=[f"mj_code=0x{mj_code:02x}"],
            ))
        return findings

    def check_minifilter_altitude(self, altitude_str: str) -> Optional[KernelCallback]:
        try:
            altitude = int(altitude_str.strip())
        except (ValueError, AttributeError):
            return None

        for lo, hi, desc in _MINIFILTER_SUSPICIOUS_RANGES:
            if lo <= altitude <= hi:
                return KernelCallback(
                    callback_id=self._next_id(),
                    callback_type=CallbackType.MINIFILTER_ALTITUDE,
                    altitude=altitude_str,
                    is_suspicious=True,
                    reason=f'微过滤器高度 {altitude} 落入可疑区间 [{lo}, {hi}]: {desc}')

        return None

    def check_callback_abuse(self, callbacks: List[KernelCallback]) -> List[Dict[str, Any]]:
        abuses = []
        cb_types = {c.callback_type for c in callbacks}
        for combo in self.SUSPICIOUS_COMBOS:
            if all(c in cb_types for c in combo):
                abuses.append({
                    'pattern': 'multiple_callback_types',
                    'types': list(combo),
                    'severity': 'critical',
                    'description': '多类型内核回调共存 — rootkit/EDR 规避特征'
                })

        # ETW 篡改 + 进程回调
        if CallbackType.ETW_TAMPER in cb_types and (
            CallbackType.PROCESS_NOTIFY in cb_types or
            CallbackType.OB_CALLBACK in cb_types):
            abuses.append({
                'pattern': 'etw_tamper_with_process_hooks',
                'types': [CallbackType.ETW_TAMPER],
                'severity': 'critical',
                'description': 'ETW 篡改配合进程回调 — 典型的 EDR 规避 + 持久化组合'
            })

        # WFP + Minifilter
        if CallbackType.WFP_CALLOUT in cb_types and CallbackType.MINIFILTER_ALTITUDE in cb_types:
            abuses.append({
                'pattern': 'wfp_minifilter_combo',
                'types': [CallbackType.WFP_CALLOUT, CallbackType.MINIFILTER_ALTITUDE],
                'severity': 'high',
                'description': 'WFP 网络过滤 + 微过滤器文件过滤 — 全栈监控'
            })

        # DKOM + DSE disable = 正在加载未签名 rootkit
        if CallbackType.DKOM_INDICATOR in cb_types and CallbackType.DSE_DISABLE in cb_types:
            abuses.append({
                'pattern': 'dkom_with_dse_bypass',
                'types': [CallbackType.DKOM_INDICATOR, CallbackType.DSE_DISABLE],
                'severity': 'critical',
                'description': 'DKOM 配合 DSE 禁用 — 未签名 rootkit 加载后隐藏痕迹'
            })

        # 虚拟化 + MSR syscall hook = Type-1/2 HV rootkit
        if CallbackType.HYPERVISOR_PRESENCE in cb_types and CallbackType.MSR_SYSCALL_HOOK in cb_types:
            abuses.append({
                'pattern': 'hypervisor_syscall_hijack',
                'types': [CallbackType.HYPERVISOR_PRESENCE, CallbackType.MSR_SYSCALL_HOOK],
                'severity': 'critical',
                'description': '虚拟化 + 系统调用劫持 — HV rootkit (Matrix/Illusion 族)'
            })

        # HWBP + ETW 篡改 = patchless ETW bypass
        if CallbackType.HWBP_BYPASS in cb_types and CallbackType.ETW_TAMPER in cb_types:
            abuses.append({
                'pattern': 'hwbp_etw_bypass',
                'types': [CallbackType.HWBP_BYPASS, CallbackType.ETW_TAMPER],
                'severity': 'high',
                'description': 'HWBP 绕过 + ETW 篡改 — patchless EDR 规避 (Praetorian 2025)'
            })

        # 间接 syscall + AMSI 补丁 = 完整的用户态 EDR 绕过链
        if CallbackType.INDIRECT_SYSCALL in cb_types and CallbackType.AMSI_PATCH in cb_types:
            abuses.append({
                'pattern': 'indirect_syscall_amsi_chain',
                'types': [CallbackType.INDIRECT_SYSCALL, CallbackType.AMSI_PATCH],
                'severity': 'high',
                'description': '间接 syscall + AMSI 补丁 — 完整用户态 EDR 绕过链'
            })

        # 回调归零 + 进程回调 = 有目标地移除特定 EDR 回调
        if CallbackType.CALLBACK_ZERO_OUT in cb_types and CallbackType.PROCESS_NOTIFY in cb_types:
            abuses.append({
                'pattern': 'targeted_callback_removal',
                'types': [CallbackType.CALLBACK_ZERO_OUT, CallbackType.PROCESS_NOTIFY],
                'severity': 'critical',
                'description': '内核回调归零 + 进程通知 — 定向移除 EDR 注册回调 (触发 PG)'
            })

        # EDR 策略静默 + DSE 禁用 = 完全禁用 Windows 安全基础设施
        if CallbackType.EDR_POLICY_SILENCE in cb_types and CallbackType.DSE_DISABLE in cb_types:
            abuses.append({
                'pattern': 'full_security_disarm',
                'types': [CallbackType.EDR_POLICY_SILENCE, CallbackType.DSE_DISABLE],
                'severity': 'critical',
                'description': 'EDR 策略静默 + DSE 禁用 — 完全解除 Windows 安全防护'
            })

        return abuses

    def detect_token_manipulation_patterns(self, imports: List[str]) -> Dict[str, Any]:
        # 检测令牌操纵模式 — DKOM 的前置步骤。
        patterns = {
            'token_theft': [
                'PsReferencePrimaryToken', 'SeCreateAccessState',
                'PsDereferencePrimaryToken', 'ZwOpenProcessToken',
                'NtOpenProcessToken', 'ZwDuplicateToken',
            ],
            'privilege_enablement': [
                'SeSinglePrivilegeCheck', 'SePrivilegeCheck',
                'ZwAdjustPrivilegesToken', 'NtAdjustPrivilegesToken',
                'RtlAdjustPrivilege',
            ],
            'process_manipulation': [
                'PsLookupProcessByProcessId', 'KeStackAttachProcess',
                'KeUnstackDetachProcess', 'ZwOpenProcess', 'NtOpenProcess',
                'PsGetNextProcess',   # 遍历 EPROCESS 链 — DKOM 前兆
                'ObOpenObjectByName', # 通过对象名获取 EPROCESS
            ],
        }
        imports_lower = {i.lower() for i in imports}
        detected = {}
        for category, indicators in patterns.items():
            hits = [i for i in indicators if i.lower() in imports_lower]
            if hits:
                detected[category] = hits
        return {
            'token_manipulation_detected': bool(detected),
            'patterns': detected,
            'risk_level': 'critical' if len(detected) >= 2 else
                         'high' if detected else 'none',
        }

    def analyze(self, api_calls: Optional[List[str]] = None,
                strings_data: Optional[List[str]] = None,
                driver_irp_table: Optional[Dict[int, str]] = None,
                minifilter_altitudes: Optional[List[str]] = None,
                imports: Optional[List[str]] = None,
                **kwargs) -> Dict[str, Any]:
        api_calls = api_calls or []
        strings_data = strings_data or []
        imports = imports or []

        findings = self.detect_from_apis(api_calls)
        findings += self.detect_from_strings(strings_data)

        if driver_irp_table:
            findings += self.detect_irp_hooks(driver_irp_table)

        if minifilter_altitudes:
            for alt in minifilter_altitudes:
                finding = self.check_minifilter_altitude(alt)
                if finding:
                    findings.append(finding)

        abuses = self.check_callback_abuse(findings)
        token_info = self.detect_token_manipulation_patterns(imports)
        self._findings = findings

        # 风险评分
        risk_score = len(findings) * 10
        risk_score += len(abuses) * 30
        if token_info['risk_level'] == 'critical':
            risk_score += 50
        elif token_info['risk_level'] == 'high':
            risk_score += 25

        risk_level = ('critical' if risk_score >= 100 or abuses else
                      'high' if risk_score >= 60 else
                      'medium' if risk_score >= 30 else 'low')

        return {
            'success': True,
            'total_callbacks': len(findings),
            'callbacks': [c.to_dict() for c in findings],
            'callback_types': list(set(str(c.callback_type) for c in findings)),
            'callback_abuse': abuses,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'token_manipulation': token_info,
            # MITRE ATT&CK 技术映射
            'attack_techniques': sorted(set(
                t for c in findings
                for t in CALLBACK_ATTACK_MAPPING.get(
                    c.callback_type if isinstance(c.callback_type, str)
                    else str(c.callback_type), [])
            )),
        }


def detect_windows_kernel_callbacks(
    api_calls: Optional[List[str]] = None,
    strings_data: Optional[List[str]] = None,
    **kwargs) -> Dict[str, Any]:
    detector = WindowsKernelCallbackDetector()
    return detector.analyze(api_calls=api_calls, strings_data=strings_data, **kwargs)


__all__ = ["WindowsKernelCallbackDetector", "KernelCallback", "CallbackType",
           "detect_windows_kernel_callbacks"]

def _debug_print(*args, **kwargs):
    """环境变量 BINMIND_DEBUG 置位时输出调试信息。预留的排障入口。"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
