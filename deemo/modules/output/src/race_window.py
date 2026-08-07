"""
竞态条件利用窗口宽度估计 — 检查-使用指令间距→时间窗口。

问题定义:
  TOCTOU (Time-of-Check to Time-of-Use) 漏洞的利用可行性取决于
  check 和 use 之间有多少条指令 — 这决定了攻击者的竞态窗口宽度。
  现有工具报告 "存在 TOCTOU" 但不量化窗口宽度。

  本模块从三个维度估算竞态窗口:
    1. 指令间距 — check→use 路径上的指令数 (静态 CFG)
    2. 路径复杂度 — 条件分支/函数调用增加执行时间方差
    3. 系统调用屏障 — 路径上的 syscall 是天然的攻击点
       (syscall 导致内核切换 → 宽竞态窗口)

  窗口宽度 (μs) = instruction_count / IPC / clock_ghz
  IPC 假设: ~1.5 (现代乱序核的中等估计)
  转换为 exploitability 评分: 窗口越宽 → 越容易利用。

  Tsafrir et al.: TORTILLA — TOCTOU 利用框架
  CVE-2023-3269: Linux kernel TOCTOU (check→use: ~50 insns → 可利用)
  无现有量化工具 — 2026-08 检索确认.

修改记录:
  2026-08-02 13:18 - 初始版本，指令计数+CPU模型窗口估计
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# 默认 IPC 假设 (每周期指令数)
_DEFAULT_IPC = 1.5
# 默认时钟频率 (GHz)
_DEFAULT_CLOCK_GHZ = 2.5

class RaceType(Enum):
    TOCTOU_FS = "toctou_fs"        # 文件系统 TOCTOU
    TOCTOU_MEM = "toctou_mem"      # 共享内存/映射 TOCTOU
    SIGNAL_RACE = "signal_race"    # 信号处理器竞争
    THREAD_RACE = "thread_race"    # 多线程数据竞争
    UNKNOWN = "unknown"

@dataclass
class RaceWindow:
    """竞态窗口评估。"""
    race_type: RaceType
    instruction_count: int          # check→use 路径上的指令数
    branch_count: int               # 路径上的条件分支数
    syscall_count: int              # 路径上的系统调用数
    estimated_window_us: float      # 估算竞态窗口 (微秒)
    exploitability: float           # 0-10, 越高越容易利用
    window_quality: str = ''        # tiny/small/medium/large/huge

def _classify_race(
    function_context: str = '',
    vuln_description: str = '',
) -> RaceType:
    combined = (function_context + ' ' + vuln_description).lower()
    if any(kw in combined for kw in ('open', 'stat', 'access', 'chmod',
           'chown', 'unlink', 'rename', 'symlink', 'link', 'readlink',
           'fopen', 'fstat', 'lstat')):
        return RaceType.TOCTOU_FS
    if any(kw in combined for kw in ('mmap', 'shm', 'shmat', 'shared memory',
           'mprotect', 'msync')):
        return RaceType.TOCTOU_MEM
    if any(kw in combined for kw in ('signal', 'sigaction', 'sig_handler',
           'async', 'interrupt')):
        return RaceType.SIGNAL_RACE
    if any(kw in combined for kw in ('thread', 'pthread', 'mutex', 'lock',
           'atomic', 'concurrent', 'race')):
        return RaceType.THREAD_RACE
    return RaceType.UNKNOWN

def _estimate_window_us(
    instruction_count: int,
    branch_count: int = 0,
    syscall_count: int = 0,
    ipc: float = _DEFAULT_IPC,
    clock_ghz: float = _DEFAULT_CLOCK_GHZ,
) -> float:
    """
    指令数 → 时间窗口 (微秒)。

    window = (insns + branch_penalty + syscall_penalty) / (IPC × GHz)
    branch_penalty: 每条条件分支增加 3 个周期的方差
    syscall_penalty: 每个 syscall 增加 ~1000 cycles (用户→内核→用户)
    """
    cycles_per_ins = 1.0 / ipc if ipc > 0 else 0.67
    base_cycles = instruction_count * cycles_per_ins
    branch_cycles = branch_count * 3.0    # 分支误预测惩罚
    syscall_cycles = syscall_count * 1000.0  # 系统调用开销

    total_cycles = base_cycles + branch_cycles + syscall_cycles
    # GHz → cycles/sec
    window_seconds = total_cycles / (clock_ghz * 1e9)
    return window_seconds * 1e6  # 转微秒

def _window_to_exploitability(window_us: float, race_type: RaceType) -> float:
    """
    竞态窗口 → exploitability 映射。

    窗口 > 100μs → 几乎确定可利用 (在用户态竞态中很大)。
    窗口 < 0.1μs → 几乎不可利用 (需要精确到数十个 CPU 周期)。
    """
    # 不同类型有不同"可利用"基线
    baseline = {
        RaceType.TOCTOU_FS: 1.0,    # 文件系统 — 窗口最宽 (ms级IO)
        RaceType.TOCTOU_MEM: 0.3,   # 内存映射 — 窗口窄 (μs级)
        RaceType.SIGNAL_RACE: 0.5,
        RaceType.THREAD_RACE: 0.2,  # 线程竞争 — 最窄 (ns级)
        RaceType.UNKNOWN: 0.5,
    }.get(race_type, 0.5)

    # sigmoid: log10(window_us) 在 [-1, 2] 范围内映射到 [0, 10]
    log_w = math.log10(max(window_us, 1e-6))
    score = 10.0 / (1.0 + math.exp(-2.0 * (log_w - 1.0)))
    return round(score * baseline, 1)

def estimate_race_window(
    function_context: str = '',
    vuln_description: str = '',
    check_to_use_insns: int = 10,
    branch_count: int = 0,
    syscall_count: int = 0,
    ipc: float = _DEFAULT_IPC,
    clock_ghz: float = _DEFAULT_CLOCK_GHZ,
) -> RaceWindow:
    """
    估算竞态条件的利用窗口。

    check_to_use_insns: check 和 use 之间的指令数 (CFG 最短路径)。
    """
    rtype = _classify_race(function_context, vuln_description)
    window = _estimate_window_us(check_to_use_insns, branch_count,
                                  syscall_count, ipc, clock_ghz)
    exploit = _window_to_exploitability(window, rtype)

    if window >= 100:
        quality = 'huge'
    elif window >= 10:
        quality = 'large'
    elif window >= 1.0:
        quality = 'medium'
    elif window >= 0.1:
        quality = 'small'
    else:
        quality = 'tiny'

    return RaceWindow(
        race_type=rtype,
        instruction_count=check_to_use_insns,
        branch_count=branch_count,
        syscall_count=syscall_count,
        estimated_window_us=round(window, 3),
        exploitability=exploit,
        window_quality=quality,
    )

def race_summary(rw: RaceWindow) -> Dict[str, Any]:
    """竞态窗口评估摘要。"""
    if rw.window_quality in ('large', 'huge'):
        verdict = ('宽竞态窗口 — 利用可行性高。'
                   '考虑: 1) 原子操作替代; 2) 文件描述符重打开检查')
    elif rw.window_quality == 'medium':
        verdict = '中等窗口 — 需要精确时机控制。使用 filesystem stress + inotify 辅助'
    else:
        verdict = '窄窗口 — 利用难度高。考虑多核并发 + CPU pinning 提高成功率'

    rw_type = rw.race_type
    if rw_type == RaceType.TOCTOU_FS and rw.syscall_count == 0:
        verdict += ' (提示: 若路径上存在 open/stat 调用则为 syscall 屏障)'

    return {
        'race_type': rw.race_type.value,
        'instruction_count': rw.instruction_count,
        'estimated_window_us': rw.estimated_window_us,
        'window_quality': rw.window_quality,
        'exploitability': rw.exploitability,
        'syscall_barriers': rw.syscall_count,
        'verdict': verdict,
    }
