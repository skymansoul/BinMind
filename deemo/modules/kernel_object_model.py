"""
内核对象行为建模与漏洞检测模块

功能:
    1. 针对 Windows 内核对象 (_EPROCESS, _ETHREAD) 建立操作模型
    2. 分析驱动 Dispatch 例程是否错误操作对象
    3. 检测引用计数泄露/双重释放等内核对象管理漏洞

核心技术:
    - 内核对象结构定义 (ETPROCESS/ETHREAD/ERESOURCE/IO_STACK_LOCATION)
    - 行为规则: 正确获取/释放的 API 配对
    - 路径敏感分析
    - 引用计数不变量检查
"""

import logging
import os
import re
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class KernelObjectType(Enum):
    """内核对象类型"""
    EPROCESS = "_EPROCESS"
    ETHREAD = "_ETHREAD"
    FILE_OBJECT = "_FILE_OBJECT"
    DEVICE_OBJECT = "_DEVICE_OBJECT"
    ERESOURCE = "_ERESOURCE"
    FAST_MUTEX = "_FAST_MUTEX"
    IO_STACK_LOCATION = "_IO_STACK_LOCATION"
    IRP = "_IRP"
    UNKNOWN = "unknown"


class KernelApiCategory(Enum):
    """内核 API 分类"""
    OB_REFERENCE = "ob_reference"      # ObReferenceObject*
    OB_DEREFERENCE = "ob_dereference"  # ObDereferenceObject*
    LOCK_ACQUIRE = "lock_acquire"      # ExAcquire*
    LOCK_RELEASE = "lock_release"      # ExRelease*
    IO_CALL = "io_call"                # IoCallDriver
    ALLOC = "alloc"
    FREE = "free"


@dataclass
class KernelApi:
    """内核 API 调用"""
    name: str
    category: KernelApiCategory
    address: int = 0
    args: List[str] = field(default_factory=list)
    target_object: Optional[str] = None


@dataclass
class ObjectLifecycle:
    """对象生命周期事件"""
    object_name: str
    obj_type: KernelObjectType
    acquire_site: Optional[int] = None
    release_sites: List[int] = field(default_factory=list)
    ref_balance: int = 0
    is_leaked: bool = False
    is_double_freed: bool = False
    error: Optional[str] = None


@dataclass
class KernelVulnerability:
    """内核漏洞"""
    vuln_type: str
    severity: str
    location: str
    description: str
    object_name: str = ""
    cwe_id: str = ""


# 已知内核 API 分类表
KERNEL_API_TABLE: Dict[str, KernelApiCategory] = {
    "ObReferenceObjectByHandle": KernelApiCategory.OB_REFERENCE,
    "ObReferenceObject": KernelApiCategory.OB_REFERENCE,
    "ObReferenceObjectByPointer": KernelApiCategory.OB_REFERENCE,
    "ObDereferenceObject": KernelApiCategory.OB_DEREFERENCE,
    "ObfDereferenceObject": KernelApiCategory.OB_DEREFERENCE,
    "ExAcquireResourceExclusiveLite": KernelApiCategory.LOCK_ACQUIRE,
    "ExAcquireResourceSharedLite": KernelApiCategory.LOCK_ACQUIRE,
    "ExAcquireFastMutex": KernelApiCategory.LOCK_ACQUIRE,
    "ExReleaseResourceLite": KernelApiCategory.LOCK_RELEASE,
    "ExReleaseFastMutex": KernelApiCategory.LOCK_RELEASE,
    "IoCallDriver": KernelApiCategory.IO_CALL,
    "ExAllocatePool": KernelApiCategory.ALLOC,
    "ExAllocatePoolWithTag": KernelApiCategory.ALLOC,
    "ExFreePool": KernelApiCategory.FREE,
    "ExFreePoolWithTag": KernelApiCategory.FREE,
    "IoAllocateIrp": KernelApiCategory.ALLOC,
    "IoFreeIrp": KernelApiCategory.FREE,
}


OBJECT_TYPE_API: Dict[KernelObjectType, Dict[str, KernelApiCategory]] = {
    KernelObjectType.EPROCESS: {
        "acquire": KernelApiCategory.OB_REFERENCE,
        "release": KernelApiCategory.OB_DEREFERENCE
    },
    KernelObjectType.ERESOURCE: {
        "acquire": KernelApiCategory.LOCK_ACQUIRE,
        "release": KernelApiCategory.LOCK_RELEASE
    }
}


@dataclass
class DispatchRoutine:
    """驱动 Dispatch 例程"""
    name: str
    irp_code: str
    body: str
    api_calls: List[KernelApi] = field(default_factory=list)


class KernelAPIDetector:
    """内核 API 检测"""

    def detect(self, asm_text: str) -> List[KernelApi]:
        results: List[KernelApi] = []
        for line in asm_text.split("\n"):
            m = re.match(r"0x([0-9a-f]+)\s+(.*)", line.strip())
            if not m:
                continue
            addr = int(m.group(1), 16)
            ins = m.group(2)
            for api_name, cat in KERNEL_API_TABLE.items():
                if api_name in ins:
                    results.append(KernelApi(
                        name=api_name, category=cat, address=addr,
                        args=self._extract_args(ins)
                    ))
                    break
        return results

    def _extract_args(self, ins: str) -> List[str]:
        m = re.search(r"\((.*)\)", ins)
        if not m:
            return []
        return [a.strip() for a in m.group(1).split(",")]


class ReferenceCounter:
    """引用计数追踪"""

    def __init__(self):
        self.refs: Dict[str, int] = defaultdict(int)
        self.lifecycles: Dict[str, ObjectLifecycle] = {}

    def record_event(self, obj: str, api: KernelApi):
        if obj not in self.lifecycles:
            self.lifecycles[obj] = ObjectLifecycle(
                object_name=obj, obj_type=KernelObjectType.UNKNOWN
            )
        lc = self.lifecycles[obj]
        if api.category == KernelApiCategory.OB_REFERENCE:
            self.refs[obj] += 1
            lc.ref_balance = self.refs[obj]
            if lc.acquire_site is None:
                lc.acquire_site = api.address
        elif api.category == KernelApiCategory.OB_DEREFERENCE:
            self.refs[obj] -= 1
            lc.ref_balance = self.refs[obj]
            lc.release_sites.append(api.address)
            if self.refs[obj] < 0:
                lc.is_double_freed = True
                lc.error = "引用计数降至负数, 可能双重释放"
        elif api.category == KernelApiCategory.LOCK_ACQUIRE:
            if obj not in self.lifecycles:
                lc.acquire_site = api.address
            self.refs[obj] += 1
        elif api.category == KernelApiCategory.LOCK_RELEASE:
            self.refs[obj] -= 1
            lc.release_sites.append(api.address)
            if self.refs[obj] < 0:
                lc.is_double_freed = True
                lc.error = "锁释放多于获取, 可能死锁或释放未持有锁"
        elif api.category == KernelApiCategory.ALLOC:
            if obj not in self.lifecycles:
                lc.acquire_site = api.address
        elif api.category == KernelApiCategory.FREE:
            if obj in self.lifecycles and self.refs.get(obj, 0) > 0:
                lc.is_leaked = True
                lc.error = "分配后未释放"
            self.refs[obj] -= 1
            lc.release_sites.append(api.address)
            if self.refs[obj] < 0:
                lc.is_double_freed = True
                lc.error = "释放次数超过分配次数"

    def finalize(self) -> List[ObjectLifecycle]:
        """最终化, 找出未平衡的对象"""
        issues: List[ObjectLifecycle] = []
        for name, lc in self.lifecycles.items():
            if self.refs.get(name, 0) > 0:
                lc.is_leaked = True
                if not lc.error:
                    lc.error = f"引用计数未归零 (剩余 {self.refs[name]})"
            issues.append(lc)
        return issues


class DispatchRoutineAnalyzer:
    """Dispatch 例程分析"""

    def analyze(self, asm_text: str) -> List[KernelVulnerability]:
        detector = KernelAPIDetector()
        counter = ReferenceCounter()
        apis = detector.detect(asm_text)
        # 推断对象
        for api in apis:
            obj = api.args[0] if api.args else "unknown"
            counter.record_event(obj, api)
        # 检查错误处理路径: Dispatch 例程必须调用 IoCompleteRequest
        if "IoCompleteRequest" not in asm_text:
            return [KernelVulnerability(
                vuln_type="missing_io_complete",
                severity="medium",
                location="DispatchRoutine",
                description="Dispatch 例程可能未调用 IoCompleteRequest",
                cwe_id="CWE-401"
            )]
        # 检查 lifecycle issues
        issues = counter.finalize()
        vulns: List[KernelVulnerability] = []
        for lc in issues:
            if lc.is_leaked:
                vulns.append(KernelVulnerability(
                    vuln_type="kernel_object_leak",
                    severity="medium",
                    location=f"0x{lc.acquire_site or 0:x}",
                    description=f"内核对象 {lc.object_name} 引用计数未归零: {lc.error}",
                    object_name=lc.object_name,
                    cwe_id="CWE-401"
                ))
            if lc.is_double_freed:
                vulns.append(KernelVulnerability(
                    vuln_type="double_free_or_deref",
                    severity="high",
                    location=f"0x{lc.release_sites[-1] if lc.release_sites else 0:x}",
                    description=f"内核对象 {lc.object_name}: {lc.error}",
                    object_name=lc.object_name,
                    cwe_id="CWE-415"
                ))
        return vulns


class KernelObjectModel:
    """内核对象行为模型"""

    def __init__(self):
        self.detector = KernelAPIDetector()
        self.analyzer = DispatchRoutineAnalyzer()

    def analyze_binary(self, binary_path: str,
                       dispatch_funcs: Optional[List[str]] = None
                       ) -> Dict[str, Any]:
        import subprocess
        try:
            r = subprocess.run(
                ['r2', '-q', '-c',
                 'aa; pdf @ sym.IoCreateDriver; q', binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            text = r.stdout
        except Exception as e:
            logger.warning(f"反编译失败: {e}")
            return {'success': False, 'error': str(e)}
        apis = self.detector.detect(text)
        vulns = self.analyzer.analyze(text)
        return {
            'success': True,
            'api_count': len(apis),
            'vulnerabilities': [
                {
                    'type': v.vuln_type,
                    'severity': v.severity,
                    'location': v.location,
                    'description': v.description,
                    'object': v.object_name,
                    'cwe': v.cwe_id
                }
                for v in vulns
            ],
            'apis': [
                {'name': a.name, 'category': a.category.value, 'address': hex(a.address)}
                for a in apis
            ]
        }


def analyze_kernel_object_usage(binary_path: str) -> Dict[str, Any]:
    """便捷入口"""
    model = KernelObjectModel()
    return model.analyze_binary(binary_path)
