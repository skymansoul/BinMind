#
# 并发分析管线 —— 编排静态并发缺陷分析的完整流程
#
# 输入: 反汇编后的函数指令数据 + 导入表
# 输出: ConcurrencyReport（死锁 + 数据竞争 + 同步误用）
#
# 设计约束：
# 纯静态，不执行目标程序
#   - 所有依赖为 Python 标准库（不引入 z3/claripy/angr 等重量依赖）
# - 可集成到 CI 流水线：报告.has_critical_issues → exit 1

import logging
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from .sync_primitive import (
    SyncPrimitive, SyncType, SyncSite,
    extract_sync_primitives, build_lock_pairs,
)
from .lock_graph import (
    build_lock_graph, detect_deadlock_cycles, LockGraph,
)
from .race_detector import (
    SharedAccess, AccessType,
    collect_thread_entries, find_shared_accesses,
    detect_potential_races, RaceReport,
)

logger = logging.getLogger(__name__)


@dataclass
class ConcurrencyReport:
    """二进制文件的完整并发安全性评估"""
    binary_path: str
    total_functions: int
    thread_entries: int
    total_sync_sites: int
    deadlock_cycles: List[Tuple[List[str], List]]  # [(lock_ids, edges)]
    potential_races: List[RaceReport]
    unpaired_locks: List[SyncSite]  # lock 后无 unlock
    has_critical_issues: bool

    def summary(self) -> str:
        """单行摘要供 CI 日志使用"""
        parts = []
        if self.deadlock_cycles:
            parts.append(f"{len(self.deadlock_cycles)} DEADLOCK")
        if self.potential_races:
            high = sum(1 for r in self.potential_races if r.severity == 'HIGH')
            parts.append(f"{high}/{len(self.potential_races)} RACES")
        if self.unpaired_locks:
            parts.append(f"{len(self.unpaired_locks)} UNPAIRED-LOCKS")
        if not parts:
            return "CLEAN"
        return " | ".join(parts)


def analyze_binary_concurrency(
    binary_path: str,
    imports: List[str],
    func_insns: Dict[str, Tuple[int, List[Tuple[str, List[str]]]]],
    global_vars: Optional[Dict[str, int]] = None,
) -> ConcurrencyReport:
    """对二进制文件做完整的静态并发分析
    
    参数:
    binary_path: 二进制文件路径（用于报告）
    imports: 导入符号列表（如 r2 的 iE 输出）
    func_insns: {name: (addr, [(mnemonic, [operands]),.])}
    global_vars: {name: addr} 全局变量映射（如 r2 的 输出）
    
    返回 并发Report
    """
    if global_vars is None:
        global_vars = {}

# 阶段 1: 同步原语提取
    sync_primitives = extract_sync_primitives(imports)
    logger.info("识别到 %d 个同步原语导入", len(sync_primitives))

    # 从指令中提取 SyncSite
    all_sites: List[SyncSite] = []
    func_addr_map: Dict[str, int] = {}

    for func_name, (func_addr, insns) in func_insns.items():
        func_addr_map[func_name] = func_addr
        for offset, (mn, ops) in enumerate(insns):
            if mn != 'call' or not ops:
                continue
            callee_raw = ops[0].strip('<>"')
            callee = callee_raw.split('.')[-1] if '.' in callee_raw else callee_raw
            callee = callee.split('@')[-1] if '@' in callee else callee

            # 在 sync_primitives 中查找
            matched = None
            for imp_name, prim in sync_primitives.items():
                imp_clean = imp_name.split('.')[-1].split('@')[-1]
                if imp_clean == callee:
                    matched = prim
                    break

            if matched:
                # 锁标识符推导——简化：使用被调用符号的第一个操作数作为 ID
                lock_id = ops[1] if len(ops) > 1 else f"anon_{func_name}_{offset}"
                site = SyncSite(
                    func_addr=func_addr,
                    func_name=func_name,
                    insn_offset=offset,
                    sync_type=matched.sync_type,
                    lock_identifier=lock_id,
                    called_symbol=callee,
                )
                all_sites.append(site)

    logger.info("提取到 %d 个同步操作位点", len(all_sites))

# 阶段 2: 锁配对
    lock_pairs = build_lock_pairs(all_sites)
    # 未配对的锁
    paired_locks = {p[0].lock_identifier for p in lock_pairs} | \
                   {p[1].lock_identifier for p in lock_pairs}
    unpaired = [s for s in all_sites
                 if s.lock_identifier not in paired_locks
                 and s.sync_type in (SyncType.MUTEX_LOCK, SyncType.MUTEX_UNLOCK,
                                     SyncType.RWLOCK_WRLOCK, SyncType.RWLOCK_RDLOCK)]

# 阶段 3: 锁图构建 + 死锁检测
    lock_graph = build_lock_graph(all_sites)
    deadlock_cycles = detect_deadlock_cycles(lock_graph)

# 阶段 4: 线程入口推断
    # 将 func_insns 转为简易格式
    simple_func_insns = {name: insns for name, (_, insns) in func_insns.items()}
    thread_entries = collect_thread_entries(simple_func_insns, func_addr_map)

    # 如果没有显式线程创建但存在同步原语，标记为"可能的并发"
    if not thread_entries:
        # 任何使用锁的函数都可能在线程上下文中运行
        for site in all_sites:
            if site.sync_type in (SyncType.MUTEX_LOCK, SyncType.MUTEX_UNLOCK):
                thread_entries[site.func_name] = {'<inferred_from_locks>'}

# 阶段 5: 共享访问收集
    all_shared: Dict[str, List[SharedAccess]] = {}
    for func_name, (func_addr, insns) in func_insns.items():
        accesses = find_shared_accesses(func_name, func_addr, insns, global_vars)
        if accesses:
            all_shared[func_name] = accesses

# 阶段 6: 数据竞争检测
    # 每个函数的锁集合
    func_locks: Dict[str, Set[str]] = defaultdict(set)
    for site in all_sites:
        func_locks[site.func_name].add(site.lock_identifier)

    races = detect_potential_races(thread_entries, all_shared, func_locks)

# 阶段 7: 汇总
    has_critical = bool(deadlock_cycles) or \
                   any(r.severity == 'HIGH' for r in races) or \
                   len(unpaired) > 5  # 超过 5 个未配对的锁视为严重

    report = ConcurrencyReport(
        binary_path=binary_path,
        total_functions=len(func_insns),
        thread_entries=len(thread_entries),
        total_sync_sites=len(all_sites),
        deadlock_cycles=deadlock_cycles,
        potential_races=races,
        unpaired_locks=unpaired,
        has_critical_issues=has_critical,
    )

    logger.info("并发分析完成: %s", report.summary())
    return report
