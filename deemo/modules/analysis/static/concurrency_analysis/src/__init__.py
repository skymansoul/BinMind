#
# 静态并发缺陷检测 —— 在二进制层面分析多线程同步原语和 happens- 关系
#
# 大多数并发缺陷检测器（ThreadSanitizer, Helgrind）依赖运行时插桩
# 本项目在反汇编输出上做静态分析——不需要执行目标程序。核心创新：
#
# 1. 同步原语重建 —— 通过导入表识别 pthread_mutex_lock / EnterCriticalSec 等
#      锁定/解锁操作，重建每个函数的锁获取-释放配对
# 2. 线程入口推断 —— 通过 pthread_cre / CreateThread 的调用点推断哪些函数
#      可能在不同线程中执行
#   3. 锁图构建 —— 构建 "先获取 A 再获取 B" 的偏序关系，检测传递闭包中的环
# （死锁条件: → B →. → A）
#   4. 数据竞争检测 —— 对每对在不同线程中执行且共享写访问的函数（通过全局变量
#      交叉引用识别），检查是否存在共同的锁保护
#
# 已知局限：
# - 间接调用（函数指针/vt）的目标解析不完全——这是二进制程序的固有问题
#   - 条件变量的 wait/signal 模式检测依赖启发式（pthread_cond_wait 附近找不到
#     mutex_lock 则报告为潜在误用）
#
# ref: arXiv:2305.08701 — ConcStatic 的锁图构建方法（源代码级）
# 本项目将其推广到二进制层面并增加了间接调用的 heuristic 回退策略

from .sync_primitive import (
    SyncPrimitive, SyncType, SyncSite,
    extract_sync_primitives, build_lock_pairs,
)
from .lock_graph import (
    LockGraph, LockNode, LockOrderEdge,
    build_lock_graph, detect_deadlock_cycles,
)
from .race_detector import (
    SharedAccess, AccessType,
    collect_thread_entries, find_shared_accesses,
    detect_potential_races, RaceReport,
)
from .concurrency_pipeline import analyze_binary_concurrency, ConcurrencyReport
