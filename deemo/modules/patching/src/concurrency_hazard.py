# 修改记录:
# 2025-08-16 10:33 — 初始实现：锁序变更 + 原子性违反 + 屏障缺失检测
# 2025-08-17 15:19 — 增加内存访问模式变更检测（共享→非共享的重分类）

"""Patch Concurrency Hazard Detector — 补丁引入的并发风险静态检测。

现有并发检测工具（ThreadSanitizer, Helgrind）操作在完整程序上，
不做补丁级别的差分分析。本模块对比补丁前后的汇编指令，
检测补丁引入的并发安全风险。

检测维度：
  1. 锁序变更：补丁是否改变了 lock/unlock 的配对或嵌套顺序
  2. 原子性违反：补丁是否将原子操作替换为非原子操作
  3. 内存屏障缺失：补丁是否移除了 mfence/lfence/sfence 或带 lock 前缀的指令
  4. 共享变量访问：补丁是否新增了对共享内存的写入
  5. 调用约定变更：补丁是否将线程安全的函数替换为非线程安全的版本

与 Linux kernel Clang thread-safety annotations [2025 RFC] 的差异：
  那些是源码级编译时检查。本模块在二进制补丁级操作，
  不依赖源码注解——直接分析汇编指令模式。

限制：
  静态分析无法捕获所有并发 bug（需要动态执行 + 时序模型）。
  本模块作为第一道过滤：标记高风险补丁进行更深入的审查。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class HazardSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ConcurrencyHazard:
    """单条并发风险发现。"""
    hazard_type: str             # lock_order | atomicity | barrier | shared_access | call_conv
    severity: HazardSeverity = HazardSeverity.LOW
    description: str = ""
    # 关联指令
    original_instruction: str = ""
    patched_instruction: str = ""
    instruction_offset: int = 0
    # 缓解建议
    mitigation: str = ""


@dataclass
class HazardReport:
    """并发风险检测报告。"""
    patch_id: str = ""
    hazards: List[ConcurrencyHazard] = field(default_factory=list)
    # 统计
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    # 补丁修改的指令集合分析
    lock_instructions_modified: bool = False
    atomic_instructions_modified: bool = False
    barrier_instructions_modified: bool = False
    # 建议
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'hazard_count': len(self.hazards),
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
            'lock_modified': self.lock_instructions_modified,
            'atomic_modified': self.atomic_instructions_modified,
            'barrier_modified': self.barrier_instructions_modified,
            'recommendation': self.recommendation,
            'top_hazards': [
                {'type': h.hazard_type, 'severity': h.severity.value,
                 'desc': h.description, 'mitigation': h.mitigation}
                for h in self.hazards[:8]
            ],
        }


# ── 汇编级并发模式数据库 ─────────────────────────────────────────

# 锁获取指令模式
_LOCK_ACQUIRE_PATTERNS = [
    re.compile(r'\b(lock\s+)?(cmpxchg|xchg)\b.*\b1\b', re.I),  # spinlock acquire
    re.compile(r'\bcall\s+.*(lock|acquire|enter|mutex_lock)\b', re.I),
    re.compile(r'\b(mov|test)\s+.*\b(lock|mutex)\b', re.I),
    re.compile(r'\bfutex\b.*\b(FUTEX_LOCK|FUTEX_WAIT)\b', re.I),
]

# 锁释放指令模式
_LOCK_RELEASE_PATTERNS = [
    re.compile(r'\b(mov|and|xor)\s+.*\b0\b', re.I),  # spinlock release
    re.compile(r'\bcall\s+.*(unlock|release|exit|mutex_unlock)\b', re.I),
    re.compile(r'\bfutex\b.*\b(FUTEX_UNLOCK|FUTEX_WAKE)\b', re.I),
]

# 原子操作指令
_ATOMIC_INSTRUCTIONS = {
    'lock cmpxchg', 'lock xchg', 'lock add', 'lock sub',
    'lock inc', 'lock dec', 'lock and', 'lock or', 'lock xor',
    'xadd', 'cmpxchg16b', 'mfence', 'lfence', 'sfence',
    # ARM64 原子操作
    'ldaxr', 'stlxr', 'ldxr', 'stxr', 'dmb', 'dsb', 'isb',
    'ldaddal', 'ldsetal', 'caspal', 'swpal',
}

# 内存屏障指令
_BARRIER_INSTRUCTIONS = {
    'mfence', 'lfence', 'sfence',       # x86
    'dmb', 'dsb', 'isb',                 # ARM
    'fence',                             # RISC-V
    'sync',                              # PowerPC
    'lock',                              # x86 lock prefix
}

# 线程安全函数名模式
_THREAD_SAFE_FUNCTIONS = re.compile(
    r'(strerror_r|localtime_r|gmtime_r|asctime_r|'
    r'ctime_r|rand_r|readdir_r|getpwnam_r)', re.I)

# 已知非线程安全函数
_UNSAFE_FUNCTIONS = {
    'strerror', 'strtok', 'localtime', 'gmtime', 'asctime',
    'ctime', 'rand', 'gethostbyname', 'readdir', 'getpwnam',
}


# ── 并发风险检测器 ────────────────────────────────────────────────

class ConcurrencyHazardDetector:
    """补丁级并发风险静态检测。

    用法:
        detector = ConcurrencyHazardDetector()
        report = detector.analyze(original_asm, patched_asm, patch_id='CVE-2024-0001')
        for h in report.hazards:
            if h.severity in (HazardSeverity.CRITICAL, HazardSeverity.HIGH):
                print(f'{h.hazard_type}: {h.description}')
    """

    def analyze(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "") -> HazardReport:
        """对比补丁前后汇编，检测并发风险。"""
        report = HazardReport(patch_id=patch_id)

        # 计算指令差异
        orig_set = set(original_asm)
        patch_set = set(patched_asm)
        added = patch_set - orig_set
        removed = orig_set - patch_set

        # 1. 锁序变更检测
        lock_hazards = self._check_lock_ordering(original_asm, patched_asm, added, removed)
        report.hazards.extend(lock_hazards)
        report.lock_instructions_modified = len(lock_hazards) > 0

        # 2. 原子性违反检测
        atomic_hazards = self._check_atomicity(added, removed)
        report.hazards.extend(atomic_hazards)
        report.atomic_instructions_modified = len(atomic_hazards) > 0

        # 3. 屏障缺失检测
        barrier_hazards = self._check_barriers(added, removed)
        report.hazards.extend(barrier_hazards)
        report.barrier_instructions_modified = len(barrier_hazards) > 0

        # 4. 共享变量访问检测
        shared_hazards = self._check_shared_access(added, original_asm)
        report.hazards.extend(shared_hazards)

        # 5. 调用约定变更
        call_hazards = self._check_call_convention(added, removed)
        report.hazards.extend(call_hazards)

        # 统计
        sev_counts = {s: 0 for s in HazardSeverity}
        for h in report.hazards:
            sev_counts[h.severity] += 1
        report.critical_count = sev_counts[HazardSeverity.CRITICAL]
        report.high_count = sev_counts[HazardSeverity.HIGH]
        report.medium_count = sev_counts[HazardSeverity.MEDIUM]
        report.low_count = sev_counts[HazardSeverity.LOW]

        # 综合建议
        total = len(report.hazards)
        if total == 0:
            report.recommendation = "未检测到并发风险——补丁的并发安全性表面良好"
        elif report.critical_count > 0:
            report.recommendation = ("发现 %d 个严重并发风险，"
                                     "部署前必须通过 ThreadSanitizer 动态验证" % report.critical_count)
        elif report.high_count > 0:
            report.recommendation = ("%d 个高风险项——建议对补丁区域做"
                                     "lockdep 式锁分析 + 动态测试" % report.high_count)
        else:
            report.recommendation = "%d 个低/中风险项——作为代码审查的辅助参考" % total

        return report

    # ── 锁序检查 ──────────────────────────────────────────────────

    def _check_lock_ordering(self, orig: List[str], patched: List[str],
                             added: Set[str], removed: Set[str]
                             ) -> List[ConcurrencyHazard]:
        """检测锁获取/释放顺序变更。"""
        hazards = []

        orig_acquires = [i for i, inst in enumerate(orig)
                        if any(p.search(inst) for p in _LOCK_ACQUIRE_PATTERNS)]
        orig_releases = [i for i, inst in enumerate(orig)
                        if any(p.search(inst) for p in _LOCK_RELEASE_PATTERNS)]
        patched_acquires = [i for i, inst in enumerate(patched)
                           if any(p.search(inst) for p in _LOCK_ACQUIRE_PATTERNS)]
        patched_releases = [i for i, inst in enumerate(patched)
                           if any(p.search(inst) for p in _LOCK_RELEASE_PATTERNS)]

        # 锁获取被移除 → 可能扩大临界区或引入竞争
        if len(patched_acquires) < len(orig_acquires):
            hazards.append(ConcurrencyHazard(
                hazard_type='lock_order',
                severity=HazardSeverity.HIGH,
                description="锁获取指令被移除 (%d → %d)，临界区可能被消除或扩大" % (
                    len(orig_acquires), len(patched_acquires)),
                mitigation="确认移除的锁获取对应的临界区逻辑是否已过时",
            ))

        # 锁释放被移除 → 可能导致死锁
        if len(patched_releases) < len(orig_releases):
            hazards.append(ConcurrencyHazard(
                hazard_type='lock_order',
                severity=HazardSeverity.CRITICAL,
                description="锁释放指令被移除 (%d → %d)，存在死锁风险" % (
                    len(orig_releases), len(patched_releases)),
                mitigation="立即审查：缺少 unlock 的代码路径会永久持有锁",
            ))

        # 锁顺序改变（同一个函数内有多锁时）
        if len(orig_acquires) >= 2 and len(patched_acquires) >= 2:
            if orig_acquires != patched_acquires:
                hazards.append(ConcurrencyHazard(
                    hazard_type='lock_order',
                    severity=HazardSeverity.MEDIUM,
                    description="多锁的获取顺序可能已改变",
                    mitigation="验证新顺序是否与其他代码路径的锁序一致",
                ))

        return hazards

    # ── 原子性检查 ────────────────────────────────────────────────

    def _check_atomicity(self, added: Set[str], removed: Set[str]
                         ) -> List[ConcurrencyHazard]:
        """检测原子操作变更。"""
        hazards = []

        atoms_removed = {inst for inst in removed
                        if any(a in inst.lower() for a in _ATOMIC_INSTRUCTIONS)}
        atoms_added = {inst for inst in added
                      if any(a in inst.lower() for a in _ATOMIC_INSTRUCTIONS)}

        if atoms_removed:
            hazards.append(ConcurrencyHazard(
                hazard_type='atomicity',
                severity=HazardSeverity.CRITICAL,
                description="原子操作被移除: %s" % ', '.join(
                    list(atoms_removed)[:3]),
                mitigation="若此操作保护共享数据，移除后必然引入 data race",
            ))

        # 检测原子→非原子的替换模式
        for rm_inst in atoms_removed:
            rm_norm = rm_inst.lower().replace('lock ', '').strip()
            for add_inst in added:
                add_norm = add_inst.lower().strip()
                # 同操作码但缺少 lock 前缀
                if rm_norm.split()[0] == add_norm.split()[0]:
                    if 'lock' in rm_inst.lower() and 'lock' not in add_inst.lower():
                        hazards.append(ConcurrencyHazard(
                            hazard_type='atomicity',
                            severity=HazardSeverity.CRITICAL,
                            description="原子指令退化为非原子: '%s' → '%s'" % (
                                rm_inst.strip()[:40], add_inst.strip()[:40]),
                            mitigation="此替换破坏原子性——所有并发访问此变量的线程不再安全",
                        ))

        return hazards

    # ── 屏障检查 ──────────────────────────────────────────────────

    def _check_barriers(self, added: Set[str], removed: Set[str]
                        ) -> List[ConcurrencyHazard]:
        """检测内存屏障变更。"""
        hazards = []

        barriers_removed = {inst for inst in removed
                           if any(b in inst.lower().split()
                                 for b in _BARRIER_INSTRUCTIONS)}
        if barriers_removed:
            hazards.append(ConcurrencyHazard(
                hazard_type='barrier',
                severity=HazardSeverity.HIGH,
                description="内存屏障被移除: %s" % ', '.join(
                    list(barriers_removed)[:3]),
                mitigation="在弱内存序架构（ARM/PowerPC/RISC-V）上，"
                          "缺少屏障会导致其他核心看到不一致的内存状态",
            ))

        return hazards

    # ── 共享变量访问检查 ──────────────────────────────────────────

    def _check_shared_access(self, added: Set[str],
                             orig_asm: List[str]) -> List[ConcurrencyHazard]:
        """检测新增的共享内存写入。"""
        hazards = []

        # 检测新增的内存写入指令
        write_patterns = [
            re.compile(r'\bmov\s+\[(\w+)\+?(0x[0-9a-f]+)?\],', re.I),
            re.compile(r'\bstr\s+', re.I),
            re.compile(r'\bstp\s+', re.I),
            re.compile(r'\bxchg\s+', re.I),
            re.compile(r'\b(cmov|fst|fstp)\b', re.I),
        ]
        new_writes = set()
        for inst in added:
            for pat in write_patterns:
                if pat.search(inst):
                    new_writes.add(inst)
                    break

        if new_writes and not self._has_surrounding_lock(added, orig_asm):
            hazards.append(ConcurrencyHazard(
                hazard_type='shared_access',
                severity=HazardSeverity.MEDIUM,
                description="新增 %d 条内存写入指令，未检测到对应的锁保护" % len(new_writes),
                mitigation="确认写入目标是否为线程独占内存；"
                          "若是共享内存，需增加锁或使用原子写入",
            ))

        return hazards

    @staticmethod
    def _has_surrounding_lock(added: Set[str], orig_asm: List[str]) -> bool:
        """检查新增指令周围是否有锁操作。"""
        for inst in added:
            if any(p.search(inst) for p in _LOCK_ACQUIRE_PATTERNS):
                return True
        # 也检查原始指令中是否存在锁
        for inst in orig_asm:
            if any(p.search(inst) for p in _LOCK_ACQUIRE_PATTERNS):
                return True
        return False

    # ── 调用约定检查 ──────────────────────────────────────────────

    def _check_call_convention(self, added: Set[str], removed: Set[str]
                               ) -> List[ConcurrencyHazard]:
        """检测线程安全→非线程安全的函数替换。"""
        hazards = []

        added_unsafe = {inst for inst in added
                       if any(uf in inst.lower() for uf in _UNSAFE_FUNCTIONS)}
        # 检查是否移除了对应的 _r 安全版本
        removed_safe = {inst for inst in removed
                       if _THREAD_SAFE_FUNCTIONS.search(inst)}

        if added_unsafe:
            hazards.append(ConcurrencyHazard(
                hazard_type='call_conv',
                severity=HazardSeverity.MEDIUM,
                description="引入了非线程安全函数调用: %s" % ', '.join(
                    list(added_unsafe)[:3]),
                mitigation="在多线程上下文中替换为 _r 后缀的安全版本",
            ))

        if removed_safe and added_unsafe:
            hazards.append(ConcurrencyHazard(
                hazard_type='call_conv',
                severity=HazardSeverity.HIGH,
                description="线程安全函数被替换为非线程安全版本",
                mitigation="撤销替换或使用安全版本",
            ))

        return hazards
