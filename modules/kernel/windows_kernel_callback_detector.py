from enum import Enum
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)



class CallbackType(Enum):
    PROCESS_NOTIFY = "process_notify"
    THREAD_NOTIFY = "thread_notify"
    IMAGE_LOAD_NOTIFY = "image_load_notify"
    REGISTRY_CALLBACK = "registry_callback"
    OB_CALLBACK = "object_manager_callback"
    BUGCHECK_CALLBACK = "bugcheck_callback"
    POWER_CALLBACK = "power_callback"
    SHUTDOWN_CALLBACK = "shutdown_callback"

class KernelCallback:
    __slots__ = ('callback_id', 'callback_type', 'driver_name', 'registration_api', 'altitude', 'is_suspicious', 'reason',)

    def __init__(self, callback_id, callback_type, driver_name="", registration_api="", altitude="", is_suspicious=False, reason=""):
        self.callback_id = callback_id
        self.callback_type = callback_type
        self.driver_name = driver_name
        self.registration_api = registration_api
        self.altitude = altitude
        self.is_suspicious = is_suspicious
        self.reason = reason


    def to_dict(self) -> Dict[str, Any]:
        return {
            'callback_id': self.callback_id,
            'type': self.callback_type.value,
            'driver': self.driver_name,
            'api': self.registration_api,
            'altitude': self.altitude,
            'is_suspicious': self.is_suspicious,
            'reason': self.reason
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
    }

    SUSPICIOUS_COMBOS = [
        (CallbackType.PROCESS_NOTIFY, CallbackType.OB_CALLBACK),
        (CallbackType.PROCESS_NOTIFY, CallbackType.IMAGE_LOAD_NOTIFY),
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
                            CallbackType.PROCESS_NOTIFY),
                        reason='内核回调例程' if cb_type not in (
                            CallbackType.OB_CALLBACK,) else
                               '对象管理器回调 — 可截获进程/线程/句柄操作'))
        return findings

    def detect_from_strings(self, strings_data: List[str]) -> List[KernelCallback]:
        findings = []
        strings_combined = ' '.join(strings_data)
        for cb_type, apis in self.CALLBACK_APIS.items():
            for api in apis:
                if api in strings_combined:
                    findings.append(KernelCallback(
                        callback_id=self._next_id(),
                        callback_type=cb_type,
                        registration_api=api,
                        is_suspicious=True,
                        reason=f'{api} 字符串引用 — 疑似内核驱动组件'))
        return findings

    def check_callback_abuse(self, callbacks: List[KernelCallback]) -> List[Dict[str, Any]]:
        """Cross-reference callback registrations against known abuse patterns."""
        abuses = []
        cb_types = {c.callback_type for c in callbacks}
        for combo in self.SUSPICIOUS_COMBOS:
            if all(c in cb_types for c in combo):
                abuses.append({
                    'pattern': 'multiple_callback_types',
                    'types': [c.value for c in combo],
                    'severity': 'critical',
                    'description': '多类型内核回调共存 — rootkit/EDR 规避特征'
                })
        return abuses

    def analyze(self, api_calls: Optional[List[str]] = None,
                strings_data: Optional[List[str]] = None,
                **kwargs) -> Dict[str, Any]:
        api_calls = api_calls or []
        strings_data = strings_data or []

        findings = self.detect_from_apis(api_calls)
        findings += self.detect_from_strings(strings_data)
        abuses = self.check_callback_abuse(findings)
        self._findings = findings

        return {
            'success': True,
            'total_callbacks': len(findings),
            'callbacks': [c.to_dict() for c in findings],
            'callback_types': list(set(c.callback_type.value for c in findings)),
            'callback_abuse': abuses,
            'risk_level': 'critical' if abuses else
                         'high' if len(findings) >= 3 else
                         'medium' if findings else 'low'
        }


def detect_windows_kernel_callbacks(
    api_calls: Optional[List[str]] = None,
    strings_data: Optional[List[str]] = None,
    **kwargs) -> Dict[str, Any]:
    detector = WindowsKernelCallbackDetector()
    return detector.analyze(api_calls=api_calls, strings_data=strings_data)


__all__ = ["WindowsKernelCallbackDetector", "KernelCallback", "CallbackType",
           "detect_windows_kernel_callbacks"]
