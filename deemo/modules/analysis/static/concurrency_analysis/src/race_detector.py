#
# 数据竞争检测 —— 静态分析两函数是否可能在不互斥的情况下并发访问共享数据
#
# 竞争条件：两个不同线程中的操作访问同一内存位置，至少一个是写操作
# 且没有共同的互斥锁保护
#
# 本模块是静态近似——不执行程序，因此：
# 真阳性率较低（会报告"可能"的竞争而非确认）
# 但假阴性率也较低（任何可能竞争都能捕获，适合 CI 安全门禁）
#
# 实现策略：
# 1. 从调用图（被 pthread_cre/CreateThread 使用的函数）推断线程入口
#   2. 收集每个函数读/写的全局变量和堆内存位置
# 3. 对每对可能的并发函数（在不同线程入口可达的函数）
#      检查是否满足：写 ∩ (其他读 ∪ 其他写) ≠ ∅ 且无共同锁保护
#
# ThreadSanitizer v3 的 happens- 模型
# 本项目将其从动态插桩转换为静态二进制分析

import logging
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict

logger = logging.getLogger(__name__)


class AccessType(Enum):
    READ = auto()
    WRITE = auto()
    READ_WRITE = auto()  # 无法静态确定


@dataclass
class SharedAccess:
    """一个函数对某内存位置的访问描述"""
    func_name: str
    func_addr: int
    data_label: str       # 全局变量名或堆对象的标识符
    data_addr: int        # 数据地址（如已知）
    access_type: AccessType


@dataclass
class RaceReport:
    """一个潜在数据竞争的详细报告"""
    func_a: str
    func_b: str
    shared_data: str
    access_a: AccessType
    access_b: AccessType
    common_locks: List[str]   # 如果为空 → 无共同锁保护 → 高置信度竞争
    severity: str             # HIGH/MEDIUM/LOW


def _is_thread_create_call(mnemonic: str, operands: List[str]) -> bool:
    """检测线程创建调用——检查 callee 是否为已知的线程创建函数"""
    if mnemonic != 'call':
        return False
    if not operands:
        return False
    callee = operands[0].strip('<>"').split('.')[-1]
    return callee in {'pthread_create', 'CreateThread', '_beginthreadex',
                       'std::thread::thread', 'boost::thread::thread'}


def collect_thread_entries(func_insns: Dict[str, List[Tuple[str, List[str]]]],
                           func_addr_map: Dict[str, int]) -> Dict[str, Set[str]]:
    """收集线程入口——通过线程创建调用的参数推断
    
    返回 {thread_func_name: {entry_func_names}}
    pthread_cre(func_ptr,.) 的第三个参数是线程函数指针
    此处用简化方法：收集所有被线程创建函数引用的函数名
    精确的参数提取需要完整的反汇编→IR→值流分析——这超出了静态扫描的范围
    """
    thread_entries: Dict[str, Set[str]] = defaultdict(set)

    for func_name, insns in func_insns.items():
        for mn, ops in insns:
            if _is_thread_create_call(mn, ops):
                # 在线程创建调用附近寻找被引用的函数名
                # 实际应用中这需要更精确的常数传播——这里是启发式
                for mn2, ops2 in insns:
                    if mn2 == 'lea' and ops2:
                        # lea rcx, [thread_func] → thread_func 是线程入口
                        target = ops2[-1]
                        if target in func_addr_map or target in func_insns:
                            thread_entries[target].add(func_name)
                            logger.debug("推断线程入口: %s (由 %s 创建)",
                                         target, func_name)

    return thread_entries


def find_shared_accesses(func_name: str, func_addr: int,
                         insns: List[Tuple[str, List[str]]],
                         global_vars: Dict[str, int],
                         ) -> List[SharedAccess]:
    """在一个函数的指令序列中查找对全局变量的访问
    
    启发式：mov 和算术指令的 mem 操作数如果引用了全局符号 → 共享访问
    """
    accesses = []
    seen = set()

    for mn, ops in insns:
        for op_str in ops:
            # 匹配全局变量引用（简化——假设全局符号被引用为 [rip+offset] 或绝对地址）
            for gvar_name, gvar_addr in global_vars.items():
                if gvar_name in op_str and gvar_name not in seen:
                    seen.add(gvar_name)
                    # 判断读/写
                    if mn in ('mov', 'lea', 'cmp', 'test', 'push'):
                        # mov reg, [global] 是读；但 mov [global], reg 是写
                        # 简化：第一个操作数是 mem 引用 = 写，否则 = 读
                        is_write = (ops[0] == op_str and mn == 'mov')
                        at = AccessType.WRITE if is_write else AccessType.READ
                    elif mn in ('add', 'sub', 'inc', 'dec', 'xor', 'and', 'or',
                               'xchg', 'xadd', 'lock'):
                        at = AccessType.READ_WRITE
                    else:
                        at = AccessType.READ

                    accesses.append(SharedAccess(
                        func_name=func_name,
                        func_addr=func_addr,
                        data_label=gvar_name,
                        data_addr=gvar_addr,
                        access_type=at,
                    ))

    return accesses


def detect_potential_races(
    thread_entries: Dict[str, Set[str]],
    shared_accesses: Dict[str, List[SharedAccess]],
    func_locks: Dict[str, Set[str]],
) -> List[RaceReport]:
    """检测潜在的数据竞争
    
    对每对在不同线程上下文中执行的函数，检查：
    (a) 两者是否访问同一全局变量
    (b) 至少一个是写或读写
    (c) 共同锁集为空
    
    参数:
    thread_entries: {thread_func: {creator_funcs}}
    shared_accesses: {func_name: [SharedAccess]}
    func_locks: {func_name: {lock_ids}} 每个函数获取的锁集合
    """
    # 收集所有线程相关函数（线程入口 + 被它们调用的函数）
    thread_related: Set[str] = set(thread_entries.keys())

    # 构建反向索引：data_label → [(func_name, access_type)]
    data_to_funcs: Dict[str, List[Tuple[str, AccessType]]] = defaultdict(list)
    for func_name, accesses in shared_accesses.items():
        for acc in accesses:
            data_to_funcs[acc.data_label].append((func_name, acc.access_type))

    reports = []

    # 对每个共享数据，检查所有访问者对
    for data_label, accessors in data_to_funcs.items():
        n = len(accessors)
        if n < 2:
            continue

        for i in range(n):
            for j in range(i + 1, n):
                fa, at_a = accessors[i]
                fb, at_b = accessors[j]

                # 两函数都在线程相关集合中才可能是并发
                if fa not in thread_related and fb not in thread_related:
                    continue

                # 至少一个是写
                if at_a == AccessType.READ and at_b == AccessType.READ:
                    continue

                # 检查共同锁
                locks_a = func_locks.get(fa, set())
                locks_b = func_locks.get(fb, set())
                common = locks_a & locks_b

                severity = 'HIGH' if not common else ('MEDIUM' if len(common) < 2 else 'LOW')

                reports.append(RaceReport(
                    func_a=fa, func_b=fb, shared_data=data_label,
                    access_a=at_a, access_b=at_b,
                    common_locks=list(common),
                    severity=severity,
                ))

    # 去重——按共享数据+函数对
    seen_pairs = set()
    unique = []
    for r in reports:
        pair = tuple(sorted([r.func_a, r.func_b])) + (r.shared_data,)
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique.append(r)

    # 按严重度排序
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    unique.sort(key=lambda r: severity_order.get(r.severity, 99))

    logger.info("数据竞争检测: %d 个潜在竞争 (HIGH=%d)",
                len(unique), sum(1 for r in unique if r.severity == 'HIGH'))

    return unique
