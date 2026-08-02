"""进程伪装检测 — API 调用模式匹配 + 多信号置信度融合。"""
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional

__log = logging.getLogger(__name__)


class SpoofingTechnique(Enum):
    PROCESS_HOLLOWING = "process_hollowing"
    PROCESS_DOPPELGANGING = "process_doppelganging"
    PPID_SPOOFING = "ppid_spoofing"
    TOKEN_MANIPULATION = "token_manipulation"
    PARENT_PID_SPOOFING = "parent_pid_spoofing"
    RUNPE = "runpe"
    PROCESS_HERPADERPING = "process_herpaderping"
    DLL_SIDE_LOADING = "dll_side_loading"
    # 反分析技术
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    ANTI_SANDBOX = "anti_sandbox"
    # 线程劫持
    THREAD_HIJACK = "thread_execution_hijack"
    APC_INJECTION = "apc_injection"


class SpoofingFinding:
    __slots__ = ('finding_id', 'technique', 'severity', 'description',
                 'api_evidence', 'confidence', 'mitre_technique', 'evidence_chain')

    def __init__(self, finding_id, technique, severity, description,
                 api_evidence=None, confidence=0.0, mitre_technique="",
                 evidence_chain=None):
        self.finding_id = finding_id
        self.technique = technique
        self.severity = severity
        self.description = description
        self.api_evidence = api_evidence or []
        self.confidence = confidence
        self.mitre_technique = mitre_technique
        self.evidence_chain = evidence_chain or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'technique': self.technique.value if hasattr(self.technique, 'value') else str(self.technique),
            'severity': self.severity,
            'description': self.description,
            'api_evidence': self.api_evidence[:5],
            'confidence': self.confidence,
            'mitre': self.mitre_technique,
            'evidence_chain': self.evidence_chain[:8],
        }


class ProcessSpoofingDetector:
    """基于 API 调用模式匹配检测进程伪装技术。

    增强：引入多信号置信度融合 — 对每个检测维度独立计算置信度后
    取加权几何平均，避免单一 API 偶然命中导致的误报。
    """

    HOLLOWING_PATTERN = [
        'CreateProcess', 'CREATE_SUSPENDED', 'NtUnmapViewOfSection',
        'VirtualAllocEx', 'WriteProcessMemory', 'SetThreadContext', 'ResumeThread']

    DOPPELGANGING_PATTERN = [
        'NtCreateTransaction', 'CreateFileTransacted', 'NtCreateProcessEx',
        'NtCreateThreadEx', 'RollbackTransaction']

    TOKEN_MANIPULATION_APIS = [
        'OpenProcessToken', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser',
        'SetThreadToken', 'AdjustTokenPrivileges', 'CreateProcessAsUser',
        'CreateProcessWithTokenW', 'NtSetInformationProcess']

    PPID_SPOOFING_APIS = [
        'InitializeProcThreadAttributeList', 'UpdateProcThreadAttribute',
        'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS', 'CreateProcess']

    # 新增：Herpaderping 模式 — 与 Hollowing 高度相似但在 NtCreateProcessEx
    # 之后立即替换文件映射
    HERPADERPING_PATTERN = [
        'NtCreateProcessEx', 'NtCreateThreadEx', 'NtQueryInformationProcess',
        'NtWriteVirtualMemory', 'NtResumeThread']

    DLL_SIDE_LOADING_APIS = [
        'LoadLibrary', 'GetProcAddress', 'CreateRemoteThread',
        'WriteProcessMemory', 'SetWindowsHookEx']

    # ── 反分析检测：参照 @wshobson/anti-reversing-techniques (35K★) ──
    # 按检测类别分三组：反调试、反虚拟机、反沙箱。

    # 反调试 API / 技术指标
    ANTI_DEBUG_APIS = [
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'NtSetInformationThread',
        'OutputDebugString', 'DbgBreakPoint', 'DbgUiRemoteBreakin',
        'NtGlobalFlag', 'CloseHandle', 'OpenProcess',
        'DebugActiveProcess', 'ContinueDebugEvent',
    ]
    # 反调试字符串特征（PEB/标志位）
    ANTI_DEBUG_STRINGS = [
        'BeingDebugged', 'NtGlobalFlag', 'HeapFlags',
        'ForceFlags', 'Debugger', 'ProcessHeap',
    ]

    # 反虚拟机检测 — CPUID/Red Pill/bios/dmi 指纹
    ANTI_VM_APIS = [
        'CreateFile', 'DeviceIoControl', 'GetSystemFirmwareTable',
        'EnumServicesStatus', 'SetupDiGetDeviceRegistryProperty',
    ]
    ANTI_VM_STRINGS = [
        'vmtools', 'VMware', 'VirtualBox', 'VBOX', 'QEMU',
        'Hyper-V', 'Microsoft Hv', 'Parallels', 'Xen',
        'Q35', 'Bochs', 'KVM', 'VMWARE', 'VIRTUAL',
        'cpuid', 'hypervisor', 'Red Pill',
        # 虚拟机注册表/文件/进程指纹
        'vmwareuser', 'vboxservice', 'vboxtray',
        'vmsrvc', 'vmacthlp', 'VMTools',
    ]

    # 反沙箱 — 检测沙箱环境的典型指标
    ANTI_SANDBOX_APIS = [
        'GetTickCount', 'QueryPerformanceCounter', 'NtQueryPerformanceCounter',
        'Sleep', 'NtDelayExecution', 'WaitForSingleObject',
        'GlobalMemoryStatus', 'GetDiskFreeSpace', 'GetCursorPos',
    ]
    ANTI_SANDBOX_STRINGS = [
        'sandbox', 'cuckoo', 'malwr', 'JoeSandbox',
        'Any.Run', 'Triage', 'CAPE', 'DRAKVUF',
    ]

    def __init__(self):
        self._findings: List[SpoofingFinding] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"SPOOF-{self._counter:04d}"

    @staticmethod
    def _fuse_confidence(signal_confidences: List[float]) -> float:
        """多信号 Bayesian 融合，与 LateralMovementDetector 方法一致。"""
        prod = 1.0
        for c in signal_confidences:
            if c > 0:
                prod *= (1.0 - min(c, 1.0))
        return round(1.0 - prod, 3)

    def detect_hollowing(self, api_calls: List[str]) -> Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        matches = [a for a in self.HOLLOWING_PATTERN if a.lower() in api_lower]
        if len(matches) >= 3:
            # 阶段置信度：前缀阶段（CreateProcess + SUSPENDED）权重更高
            early = sum(1 for m in matches if m.lower() in
                       {'createprocess', 'create_suspended', 'ntunmapviewofsection'})
            late = len(matches) - early
            early_conf = min(early / 3, 1.0) * 0.9
            late_conf = min(late / 4, 1.0) * 0.6
            fused = self._fuse_confidence([early_conf, late_conf])

            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.PROCESS_HOLLOWING,
                severity='critical',
                description='Process Hollowing: CreateProcess(SUSPENDED) + Unmap + SetThreadContext + Resume',
                api_evidence=matches,
                confidence=fused,
                mitre_technique='T1055.012',
                evidence_chain=[f"{'→'.join(matches[:5])}"])
        return None

    def detect_herpaderping(self, api_calls: List[str]) -> Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        matches = [a for a in self.HERPADERPING_PATTERN if a.lower() in api_lower]
        if len(matches) >= 3:
            conf = min(len(matches) / len(self.HERPADERPING_PATTERN) * 1.2, 1.0)
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.PROCESS_HERPADERPING,
                severity='critical',
                description='Process Herpaderping: NtCreateProcessEx + 文件替换',
                api_evidence=matches,
                confidence=conf,
                mitre_technique='T1055.012',
                evidence_chain=[f"{'→'.join(matches[:5])}"])
        return None

    def detect_token_manipulation(self, api_calls: List[str]) -> Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        matches = [a for a in self.TOKEN_MANIPULATION_APIS if a.lower() in api_lower]
        if len(matches) >= 2:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.TOKEN_MANIPULATION,
                severity='high',
                description=f'Token 操纵: {matches[:3]}',
                api_evidence=matches,
                confidence=min(len(matches) / 5, 1.0),
                mitre_technique='T1134',
                evidence_chain=[f"API 命中: {', '.join(matches[:5])}"])
        return None

    def detect_ppid_spoofing(self, api_calls: List[str],
                             strings_data: List[str]) -> Optional[SpoofingFinding]:
        combined = {s.lower() for s in (api_calls + strings_data)}
        matches = [a for a in self.PPID_SPOOFING_APIS if a.lower() in combined]
        if len(matches) >= 3:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.PPID_SPOOFING,
                severity='high',
                description='父进程 PID 伪装: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS',
                api_evidence=matches,
                confidence=min(len(matches) / 4, 1.0),
                mitre_technique='T1134.004',
                evidence_chain=[f"API+Str 命中: {', '.join(matches[:5])}"])
        return None

    def detect_dll_side_loading(self, api_calls: List[str],
                                strings_data: List[str]) -> Optional[SpoofingFinding]:
        combined = {s.lower() for s in (api_calls + strings_data)}
        matches = [a for a in self.DLL_SIDE_LOADING_APIS if a.lower() in combined]
        # DLL 侧加载需要至少 3 个指标 + 路径字符串中包含可疑 DLL 名
        suspicious_dll = any('.dll' in s or 'ws2_32' in s or 'version' in s
                           for s in combined)
        if len(matches) >= 3 and suspicious_dll:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.DLL_SIDE_LOADING,
                severity='high',
                description='DLL 侧加载/劫持：LoadLibrary + 远程线程注入组合',
                api_evidence=matches,
                confidence=0.75,
                mitre_technique='T1574.002',
                evidence_chain=[f"API + DLL 引用: {', '.join(matches[:5])}"])
        return None

    def detect_anti_debug(self, api_calls: List[str],
                          strings_data: List[str]) -> Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        str_lower = {s.lower() for s in strings_data}
        api_hits = [a for a in self.ANTI_DEBUG_APIS if a.lower() in api_lower]
        str_hits = [s for s in self.ANTI_DEBUG_STRINGS if s.lower() in str_lower]
        total = len(api_hits) + len(str_hits)
        if total >= 2:
            conf = min(total / 8, 1.0)
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.ANTI_DEBUG,
                severity='medium',
                description=f'反调试检测: API {len(api_hits)} 个, 字符串 {len(str_hits)} 个',
                api_evidence=api_hits + str_hits,
                confidence=conf,
                mitre_technique='T1622',
                evidence_chain=[f'API: {", ".join(api_hits[:4])}' if api_hits else '',
                                f'Str: {", ".join(str_hits[:4])}' if str_hits else ''])
        return None

    def detect_anti_vm(self, api_calls: List[str],
                       strings_data: List[str]) -> Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        str_lower = {s.lower() for s in strings_data}
        api_hits = [a for a in self.ANTI_VM_APIS if a.lower() in api_lower]
        str_hits = [s for s in self.ANTI_VM_STRINGS if s.lower() in str_lower]
        # 虚拟机字符串命中权重远高于 API 命中 — 前者几乎确定 VM 检测意图
        score = len(str_hits) * 0.3 + len(api_hits) * 0.1
        if str_hits:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.ANTI_VM,
                severity='high',
                description=f'反虚拟机检测: 命中 {len(str_hits)} 个 VM 指纹',
                api_evidence=str_hits[:5], confidence=min(score, 1.0),
                mitre_technique='T1497',
                evidence_chain=[f'VM指纹: {", ".join(str_hits[:5])}'])
        return None

    # 线程劫持：SuspendThread + SetThreadContext + ResumeThread 模式
    # 区别于 CreateRemoteThread — 劫持已有线程而非创建新线程
    THREAD_HIJACK_APIS = [
        'SuspendThread', 'SetThreadContext', 'ResumeThread',
        'OpenThread', 'GetThreadContext', 'NtSuspendThread',
    ]

    def detect_thread_hijack(self, api_calls: List[str]) -> Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        matches = [a for a in self.THREAD_HIJACK_APIS if a.lower() in api_lower]
        # 需要 Suspend + SetContext + Resume 三阶段至少 2 项 +
        if len(matches) >= 2:
            has_set_context = 'setthreadcontext' in api_lower
            has_suspend = 'suspendthread' in api_lower or 'ntsuspendthread' in api_lower
            if has_set_context and has_suspend:
                return SpoofingFinding(
                    finding_id=self._next_id(),
                    technique=SpoofingTechnique.THREAD_HIJACK,
                    severity='high',
                    description='线程执行劫持: SuspendThread + SetThreadContext + ResumeThread',
                    api_evidence=matches,
                    confidence=0.85,
                    mitre_technique='T1055.005',
                    evidence_chain=[f'线程劫持链: {"→".join(matches[:4])}'])
        return None

    # APC 注入：QueueUserAPC / NtQueueApcThread + alertable 状态线程
    APC_INJECTION_APIS = [
        'QueueUserAPC', 'NtQueueApcThread', 'NtQueueApcThreadEx',
        'SleepEx', 'WaitForSingleObjectEx', 'WaitForMultipleObjectsEx',
    ]

    def detect_apc_injection(self, api_calls: List[str]) -> Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        matches = [a for a in self.APC_INJECTION_APIS if a.lower() in api_lower]
        has_queue_apc = 'queueuserapc' in api_lower or 'ntqueueapcthread' in api_lower
        has_alertable = 'sleepex' in api_lower or 'waitforsingleobjectex' in api_lower
        if has_queue_apc and has_alertable:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.APC_INJECTION,
                severity='critical',
                description='APC 注入: QueueUserAPC + Alertable 等待状态',
                api_evidence=matches,
                confidence=0.9,
                mitre_technique='T1055.004',
                evidence_chain=[f'APC链: {", ".join(matches[:4])}'])
        if has_queue_apc and len(matches) >= 1:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.APC_INJECTION,
                severity='medium',
                description='QueueUserAPC 存在但缺少明确的 Alertable 状态指示',
                api_evidence=matches, confidence=0.45,
                mitre_technique='T1055.004')
        return None
        api_lower = {c.lower() for c in api_calls}
        str_lower = {s.lower() for s in strings_data}
        api_hits = [a for a in self.ANTI_SANDBOX_APIS if a.lower() in api_lower]
        str_hits = [s for s in self.ANTI_SANDBOX_STRINGS if s.lower() in str_lower]
        # 需要 API (延时/查询) + 字符串 (沙箱名) 双重命中才算
        if api_hits and str_hits:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.ANTI_SANDBOX,
                severity='high',
                description=f'反沙箱检测: 延时API+沙箱指纹组合',
                api_evidence=api_hits[:3] + str_hits[:3],
                confidence=0.85,
                mitre_technique='T1497.001',
                evidence_chain=[f'延时: {", ".join(api_hits[:3])}, '
                                f'沙箱: {", ".join(str_hits[:3])}'])
        return None

    def analyze(self, api_calls: Optional[List[str]] = None,
                strings_data: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        api_calls = api_calls or []
        strings_data = strings_data or []
        findings: List[SpoofingFinding] = []

        detectors = [
            self.detect_hollowing,
            self.detect_herpaderping,
            self.detect_token_manipulation,
            lambda ac: self.detect_ppid_spoofing(ac, strings_data),
            lambda ac: self.detect_dll_side_loading(ac, strings_data),
            lambda ac: self.detect_anti_debug(ac, strings_data),
            lambda ac: self.detect_anti_vm(ac, strings_data),
            lambda ac: self.detect_anti_sandbox(ac, strings_data),
            self.detect_thread_hijack,
            self.detect_apc_injection,
        ]
        for d in detectors:
            result = d(api_calls)
            if result:
                findings.append(result)

        # Doppelganging — 需要事务 API + 字符串上下文双重确认
        if any('doppelgang' in s.lower() or 'transacted' in s.lower()
               for s in strings_data):
            api_lower = {c.lower() for c in api_calls}
            tx_matches = [a for a in self.DOPPELGANGING_PATTERN if a.lower() in api_lower]
            if len(tx_matches) >= 2:
                findings.append(SpoofingFinding(
                    finding_id=self._next_id(),
                    technique=SpoofingTechnique.PROCESS_DOPPELGANGING,
                    severity='critical',
                    description='检测到 Process Doppelganging 模式（事务 API + 字符串确认）',
                    api_evidence=tx_matches,
                    confidence=min(0.5 + len(tx_matches) * 0.15, 1.0),
                    mitre_technique='T1055.012',
                    evidence_chain=[f"事务 API: {', '.join(tx_matches[:5])}"]))

        self._findings = findings
        result = {
            'success': True,
            'total_findings': len(findings),
            'findings': [f.to_dict() for f in findings],
            'risk_level': 'critical' if any(f.severity == 'critical' for f in findings)
                         else 'high' if findings else 'low'
        }
        # 防御规避战术映射 — 所有进程伪装均归类于 TA0005
        defense_evasion_techniques = [
            {'technique': f.technique.value,
             'mitre': f.mitre_technique,
             'confidence': f.confidence}
            for f in findings
        ]
        result['defense_evasion'] = {
            'tactic': 'Defense Evasion (TA0005)',
            'techniques': defense_evasion_techniques,
            'combined_confidence': round(
                1.0 - (1.0 - min(f.confidence for f in findings))**len(findings)
                if findings else 0, 3
            ),
        }
        return result


def detect_process_spoofing(api_calls: List[str],
                            strings_data: Optional[List[str]] = None,
                            **kwargs) -> Dict[str, Any]:
    """便捷入口：实例化检测器并执行全量分析。"""
    detector = ProcessSpoofingDetector()
    return detector.analyze(api_calls=api_calls, strings_data=strings_data)


__all__ = ["ProcessSpoofingDetector", "SpoofingFinding", "SpoofingTechnique",
           "detect_process_spoofing"]
