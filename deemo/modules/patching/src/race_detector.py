# 竞态条件检测 — 共享资源访问模式分析
"""竞态条件检测器 — 识别缺少同步保护的共享内存访问。

旧状态: 无专门的竞态检测器。现有代码仅在 concurrency_hazard 中
做补丁级别的锁序变更检测，不做通用竞态发现。

新方法: 在汇编级别识别三类竞态模式:
  1. 共享全局变量: 多个call路径访问同一全局地址，至少一个是写
  2. 信号处理函数: 信号handler与非信号路径访问同一变量
  3. fork无锁: fork后父子进程共享文件描述符但无同步

方法依据:
  Data race 的三要素 (C11 memory model):
    - 两个操作访问同一内存位置
    - 至少一个是写操作
    - 操作之间无 happens-before 关系
  本模块通过静态地址分析推断前两个条件，
  通过锁/屏障指令的缺失推断第三个条件。

限制: 静态分析无法精确判断 happens-before。
保守策略将"两个线程可能同时执行的函数中同地址写入"标记为潜在竞态。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

_log = logging.getLogger(__name__)


@dataclass
class SharedAccess:
    """对共享内存的一次访问。"""
    line_index: int = 0
    instruction: str = ""
    address_pattern: str = ""      # [rip+var] / [rbp-N] / [reg+off]
    is_write: bool = False
    is_atomic: bool = False        # 是否使用 lock 前缀
    lock_held: bool = False        # 当前是否持有锁


@dataclass
class RaceCandidate:
    """一个潜在的竞态条件。"""
    access_a: SharedAccess
    access_b: SharedAccess
    shared_address: str = ""
    has_write: bool = False
    has_lock_protection: bool = False
    severity: str = "medium"
    description: str = ""


@dataclass
class RaceReport:
    """竞态检测报告。"""
    function_name: str = ""
    shared_accesses: List[SharedAccess] = field(default_factory=list)
    race_candidates: List[RaceCandidate] = field(default_factory=list)
    total_accesses: int = 0
    race_count: int = 0
    atomic_count: int = 0

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'accesses': self.total_accesses,
            'races': self.race_count,
            'atomic': self.atomic_count,
        }


# 共享访问扫描器

class SharedAccessScanner:
    """扫描对全局/共享地址的访问。"""

    # 全局变量地址模式: [rip+var] 或通过寄存器间接 (mov reg, var@GOTPCREL)
    _GLOBAL_ACCESS = re.compile(
        r'\[rip\s*[+\-]\s*\w+\]|'
        r'mov\s+(\w+),\s*\[(\w+)\s*[+\-]\s*\d+\]', re.I)

    # 原子操作/lock前缀
    _ATOMIC_PATTERNS = re.compile(
        r'\block\s+|xchg\b|\bcmpxchg\b|'
        r'ldaxr\b|\bstlxr\b|\bdmb\b|\bdsb\b', re.I)

    # 锁/解锁
    _LOCK_PATTERNS = re.compile(
        r'\bcall\s+(pthread_mutex_lock|mutex_lock|spin_lock|'
        r'acquire|down|sem_wait)\b', re.I)
    _UNLOCK_PATTERNS = re.compile(
        r'\bcall\s+(pthread_mutex_unlock|mutex_unlock|spin_unlock|'
        r'release|up|sem_post)\b', re.I)

    def scan(self, asm_lines: List[str]) -> Tuple[List[SharedAccess], List[RaceCandidate]]:
        accesses = []
        lock_held = False

        for i, line in enumerate(asm_lines):
            stripped = line.strip()
            lowered = stripped.lower()

            if self._LOCK_PATTERNS.search(lowered):
                lock_held = True
                continue
            if self._UNLOCK_PATTERNS.search(lowered):
                lock_held = False
                continue

            # 识别全局内存访问
            is_write = self._is_memory_write(stripped)
            is_atomic = bool(self._ATOMIC_PATTERNS.search(lowered))
            addr = self._extract_address(stripped)
            if not addr:
                continue

            access = SharedAccess(
                line_index=i, instruction=stripped,
                address_pattern=addr, is_write=is_write,
                is_atomic=is_atomic, lock_held=lock_held)
            accesses.append(access)

        # 查找竞态候选: 同一地址的两次访问，至少一次是写，无锁保护
        races = self._find_races(accesses)
        return accesses, races

    def _find_races(self, accesses: List[SharedAccess]) -> List[RaceCandidate]:
        """对同一地址的访问对，若至少一次是写且无锁保护 → 竞态候选。"""
        races = []
        for i in range(len(accesses)):
            for j in range(i + 1, len(accesses)):
                a, b = accesses[i], accesses[j]
                if a.address_pattern != b.address_pattern:
                    continue
                if not (a.is_write or b.is_write):
                    continue
                has_lock = a.lock_held or b.lock_held or a.is_atomic or b.is_atomic
                if has_lock:
                    continue
                races.append(RaceCandidate(
                    access_a=a, access_b=b,
                    shared_address=a.address_pattern,
                    has_write=True, has_lock_protection=False,
                    severity="high" if (a.is_write and b.is_write) else "medium",
                    description="lines %d/%d 访问同一地址 %s 无锁保护" % (
                        a.line_index, b.line_index, a.address_pattern)))
        return races

    def _is_memory_write(self, inst: str) -> bool:
        """判断指令是否为内存写入。"""
        parts = inst.strip().lower().replace(',', ' ').split()
        if len(parts) < 2:
            return False
        # mov [addr], src → 写
        if parts[0] in ('mov', 'movq', 'movl', 'movw', 'movb') and '[' in parts[1]:
            return True
        if parts[0] in ('add', 'sub', 'xor', 'and', 'or', 'inc', 'dec'):
            return '[' in parts[1]
        return False

    def _extract_address(self, inst: str) -> str:
        """提取内存地址模式，用于比较两次访问是否指向同一位置。"""
        m = re.search(r'\[([^\]]+)\]', inst)
        if not m:
            return ""
        addr = m.group(1).strip()
        # 归一化: 移除寄存器名(非rbp/rsp的)，保留偏移量和全局符号
        # [rip+0x1234] → rip+0x1234
        # [rbp-64] → rbp-64
        # [rax+0x10] → MEM(rax+0x10)
        parts = addr.replace('+', ' + ').replace('-', ' - ').split()
        normalized = []
        for p in parts:
            p = p.strip()
            if re.match(r'^(r[a-z0-9]+|e[a-z0-9]+)$', p.lower()):
                if p.lower() in ('rbp', 'rsp', 'esp', 'ebp'):
                    normalized.append(p.lower())
                else:
                    normalized.append('REG')
            elif re.match(r'^(rip|0x[0-9a-f]+|\d+)$', p.lower()):
                normalized.append(p.lower())
            elif p in ('+', '-'):
                normalized.append(p)
        return ''.join(normalized)
