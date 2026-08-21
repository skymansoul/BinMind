#
# 同步原语提取 - 从二进制导入表和指令序列中识别线程同步操作
#
# 覆盖三类平台：
#   POSIX: pthread_mutex_lock/trylock/unlock, pthread_rwlock_*, pthread_spin_*
# Windows: EnterCriticalSec/LeaveCriticalSec, WaitForSingleObject
# AcquireSRWLockExclus/Shared, ReleaseSRWLockExclus/Shared
#    Darwin: os_unfair_lock_lock/unlock, dispatch_semaphore_wait/signal
#
# 输出 SyncSite 列表-每条记录标记了 (函数地址, 指令偏移, 原语类型, 锁标识符)

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class SyncType(Enum):
    MUTEX_LOCK = auto()
    MUTEX_TRYLOCK = auto()
    MUTEX_UNLOCK = auto()
    RWLOCK_RDLOCK = auto()
    RWLOCK_WRLOCK = auto()
    RWLOCK_UNLOCK = auto()
    SPIN_LOCK = auto()
    SPIN_UNLOCK = auto()
    SEMAPHORE_WAIT = auto()
    SEMAPHORE_POST = auto()
    COND_WAIT = auto()
    COND_SIGNAL = auto()
    COND_BROADCAST = auto()
    BARRIER_WAIT = auto()
    THREAD_CREATE = auto()
    THREAD_JOIN = auto()


@dataclass
class SyncPrimitive:
    """一个同步原语的定义-映射导入符号到 SyncType"""
    import_name: str
    sync_type: SyncType
    lock_arg_position: int = 0  # 锁指针在参数列表中的位置（0-indexed）
    is_shared: bool = False     # True 表示此原语操作共享资源而非命名锁


@dataclass
class SyncSite:
    """函数中的一个同步操作实例"""
    func_addr: int
    func_name: str
    insn_offset: int            # 函数内的指令偏移
    sync_type: SyncType
    lock_identifier: str        # 从调用参数推导的锁标识符（用于匹配 lock/unlock 对）
    called_symbol: str          # 被调用的导入符号名


# 多平台同步原语映射表

_SYNC_PRIMITIVE_MAP: Dict[str, SyncPrimitive] = {
# POSIX mutex
    'pthread_mutex_lock':    SyncPrimitive('pthread_mutex_lock',    SyncType.MUTEX_LOCK),
    'pthread_mutex_trylock': SyncPrimitive('pthread_mutex_trylock', SyncType.MUTEX_TRYLOCK),
    'pthread_mutex_unlock':  SyncPrimitive('pthread_mutex_unlock',  SyncType.MUTEX_UNLOCK),
# POSIX rwlock
    'pthread_rwlock_rdlock':  SyncPrimitive('pthread_rwlock_rdlock',  SyncType.RWLOCK_RDLOCK),
    'pthread_rwlock_wrlock':  SyncPrimitive('pthread_rwlock_wrlock',  SyncType.RWLOCK_WRLOCK),
    'pthread_rwlock_unlock':  SyncPrimitive('pthread_rwlock_unlock',  SyncType.RWLOCK_UNLOCK),
# POSIX spinlock - 与 mutex 在锁序分析中等价
    'pthread_spin_lock':     SyncPrimitive('pthread_spin_lock',     SyncType.SPIN_LOCK),
    'pthread_spin_trylock':  SyncPrimitive('pthread_spin_trylock',  SyncType.MUTEX_TRYLOCK),
    'pthread_spin_unlock':   SyncPrimitive('pthread_spin_unlock',   SyncType.SPIN_UNLOCK),
# POSIX condi vari
    'pthread_cond_wait':     SyncPrimitive('pthread_cond_wait',     SyncType.COND_WAIT),
    'pthread_cond_timedwait': SyncPrimitive('pthread_cond_timedwait', SyncType.COND_WAIT),
    'pthread_cond_signal':   SyncPrimitive('pthread_cond_signal',   SyncType.COND_SIGNAL),
    'pthread_cond_broadcast': SyncPrimitive('pthread_cond_broadcast', SyncType.COND_BROADCAST),
# POSIX barrier
    'pthread_barrier_wait':  SyncPrimitive('pthread_barrier_wait',  SyncType.BARRIER_WAIT),
# POSIX semaphore
    'sem_wait':   SyncPrimitive('sem_wait',   SyncType.SEMAPHORE_WAIT),
    'sem_trywait': SyncPrimitive('sem_trywait', SyncType.SEMAPHORE_WAIT),
    'sem_post':   SyncPrimitive('sem_post',   SyncType.SEMAPHORE_POST),
# POSIX thread lifecycle
    'pthread_create': SyncPrimitive('pthread_create', SyncType.THREAD_CREATE),
    'pthread_join':   SyncPrimitive('pthread_join',   SyncType.THREAD_JOIN),
# Windows Crit Sec
    'EnterCriticalSection':       SyncPrimitive('EnterCriticalSection',       SyncType.MUTEX_LOCK),
    'TryEnterCriticalSection':    SyncPrimitive('TryEnterCriticalSection',    SyncType.MUTEX_TRYLOCK),
    'LeaveCriticalSection':       SyncPrimitive('LeaveCriticalSection',       SyncType.MUTEX_UNLOCK),
    'InitializeCriticalSection':  SyncPrimitive('InitializeCriticalSection',  SyncType.MUTEX_LOCK),  # 不参与锁分析但记录
    'DeleteCriticalSection':      SyncPrimitive('DeleteCriticalSection',      SyncType.MUTEX_UNLOCK),
# Windows SRW Lock (Vista+)
    'AcquireSRWLockExclusive': SyncPrimitive('AcquireSRWLockExclusive', SyncType.MUTEX_LOCK),
    'AcquireSRWLockShared':    SyncPrimitive('AcquireSRWLockShared',    SyncType.RWLOCK_RDLOCK),
    'ReleaseSRWLockExclusive': SyncPrimitive('ReleaseSRWLockExclusive', SyncType.MUTEX_UNLOCK),
    'ReleaseSRWLockShared':    SyncPrimitive('ReleaseSRWLockShared',    SyncType.RWLOCK_UNLOCK),
# Windows thread lifecycle
    'CreateThread':  SyncPrimitive('CreateThread',  SyncType.THREAD_CREATE),
    '_beginthreadex': SyncPrimitive('_beginthreadex', SyncType.THREAD_CREATE),
# Darwin (macOS/iOS)
    'os_unfair_lock_lock':   SyncPrimitive('os_unfair_lock_lock',   SyncType.MUTEX_LOCK),
    'os_unfair_lock_unlock': SyncPrimitive('os_unfair_lock_unlock', SyncType.MUTEX_UNLOCK),
    'dispatch_semaphore_wait':    SyncPrimitive('dispatch_semaphore_wait',    SyncType.SEMAPHORE_WAIT),
    'dispatch_semaphore_signal':  SyncPrimitive('dispatch_semaphore_signal',  SyncType.SEMAPHORE_POST),
}


def extract_sync_primitives(imports: List[str]) -> Dict[str, SyncPrimitive]:
    """从导入符号列表中提取同步原语
    返回 {symbol_name: SyncPrimit}
    """
    found = {}
    for imp in imports:
        # 剥离模块前缀（如 KERNEL32.EnterCriticalSec → EnterCriticalSec）
        base_name = imp.split('.')[-1] if '.' in imp else imp
        # 剥离 @ 后缀（如 pthread_mutex_lock@GLIBC_2.0）
        clean_name = base_name.split('@')[0] if '@' in base_name else base_name
        if clean_name in _SYNC_PRIMITIVE_MAP:
            found[imp] = _SYNC_PRIMITIVE_MAP[clean_name]
    return found


def build_lock_pairs(sites: List[SyncSite]) -> List[Tuple[SyncSite, SyncSite]]:
    """匹配 lock→unlock 配对。同一函数内按指令偏移顺序配对

    lock 操作（MUTEX_LOCK, RWLOCK_WRLOCK, RWLOCK_RDLOCK, SPIN_LOCK）
    与后续最近的同一锁标识符的 unlock 操作配对
    未配对的操作（如提前 return 跳过了 unlock）标记为警告
    """
    pairs = []
    # 按函数分组
    by_func: Dict[int, List[SyncSite]] = {}
    for site in sites:
        by_func.setdefault(site.func_addr, []).append(site)

    for func_addr, func_sites in by_func.items():
        func_sites.sort(key=lambda s: s.insn_offset)

        # 对每个锁标识符维护一个栈
        lock_stack: Dict[str, List[SyncSite]] = {}

        for site in func_sites:
            is_lock = site.sync_type in (SyncType.MUTEX_LOCK, SyncType.MUTEX_TRYLOCK,
                                          SyncType.RWLOCK_WRLOCK, SyncType.RWLOCK_RDLOCK,
                                          SyncType.SPIN_LOCK)
            is_unlock = site.sync_type in (SyncType.MUTEX_UNLOCK, SyncType.RWLOCK_UNLOCK,
                                            SyncType.SPIN_UNLOCK)

            if is_lock:
                lock_stack.setdefault(site.lock_identifier, []).append(site)
            elif is_unlock:
                stack = lock_stack.get(site.lock_identifier, [])
                if stack:
                    lock_site = stack.pop()
                    pairs.append((lock_site, site))
                else:
                    logger.warning("unlock without lock: %s in %s (offset %d)",
                                   site.lock_identifier, site.func_name, site.insn_offset)
    return pairs
