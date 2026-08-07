"""
硬件断点 监控 for x86-64 debug 寄存器 (DR0-DR7) management

提供 low-level control over Intel/AMD debug 寄存器s for hardware
breakpoint (HWBP) installation, monitoring, DR6 status 解码
支持 multi-thread attachment LEN/RW condition 编码
"""

import os
import sys
import struct
import ctypes
import logging
import platform
import threading
from enum import IntEnum, IntFlag, auto
from typing import Optional, List, Dict, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
__log = logging.getLogger(__name__)

_CURRENT_PLATFORM = platform.system().lower()
_IS_WINDOWS = _CURRENT_PLATFORM == "windows"
_IS_LINUX = _CURRENT_PLATFORM == "linux"


# DR7 编码 constants
#
# DR7 寄存器布局（x86-64）：
# Bits 0,2,4,6: L0-L3（局部断点使能）—— 任务切换时自动清除
# Bits 1,3,5,7: G0-G3（全局断点使能）—— 所有任务均有效
# Bits 16-17: RW0（断点 0 的触发条件）
# Bits 18-19: LEN0（断点 0 的长度）
# Bits 20-21: RW1, 22-23: LEN1
# Bit 13: GD（通用检测，用于调试寄存器访问拦截）
#   Bits 8-12,14-15: 保留（必须为 0）
#
# 设计权衡：RW 和 LEN 字段的 bit 偏移不是规律的 4*slot
# 而是 16+4*slot(RW) 和 18+4*slot(LEN)

DR7_L0 = 1 << 0
DR7_G0 = 1 << 1
DR7_L1 = 1 << 2
DR7_G1 = 1 << 3
DR7_L2 = 1 << 4
DR7_G2 = 1 << 5
DR7_L3 = 1 << 6
DR7_G3 = 1 << 7

# LE/GE (local/global exact breakpoint) — P6 家族后已弃用，置为 1 用于兼容性
DR7_LE = 1 << 8
DR7_GE = 1 << 9

DR7_GD = 1 << 13                              # 调试寄存器访问检测

# 每个断点槽位的 enable bits
_DR7_LOCAL_ENABLE = [DR7_L0, DR7_L1, DR7_L2, DR7_L3]
_DR7_GLOBAL_ENABLE = [DR7_G0, DR7_G1, DR7_G2, DR7_G3]

# RW 和 LEN 的 bit 偏移（相对 DR7）
_DR7_RW_SHIFT = [16, 20, 24, 28]
_DR7_LEN_SHIFT = [18, 22, 26, 30]


class BreakpointCondition(IntEnum):
    """DR7 RW field -- 硬件断点 trigger condition"""
    EXECUTE = 0                                  # 00: 指令执行断点
    WRITE = 1                                    # 01: 数据写入断点
    IO_READ_WRITE = 2                            # 10: /O 读写（需 CR4.DE=1，不常用）
    READ_WRITE = 3                               # 11: 数据读写断点


class BreakpointLength(IntEnum):
    """DR7 LEN field -- monitored byte range"""
    BYTE_1 = 0                                   # 00: 1 字节
    BYTE_2 = 1                                   # 01: 2 字节
    BYTE_8 = 2                                   # 10: 8 字节（x86-64 下也可能是 4 字节模式）
    BYTE_4 = 3                                   # 11: 4 字节

    @classmethod
    def from_byte_count(cls, count: int) -> "BreakpointLength":
        mapping = {1: cls.BYTE_1, 2: cls.BYTE_2, 4: cls.BYTE_4, 8: cls.BYTE_8}
        return mapping.get(count, cls.BYTE_1)


@dataclass
class HardwareBreakpoint:
    """Descriptor for a single hardware debug 寄存器 breakpoint slot"""
    slot: int                                    # 0-3
    address: int
    condition: BreakpointCondition
    length: BreakpointLength
    enabled: bool = True
    global_scope: bool = False                   # 全局断点（跨任务切换保持）
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot": self.slot,
            "address": hex(self.address),
            "condition": self.condition.name,
            "length": self.length.name,
            "enabled": self.enabled,
            "global_scope": self.global_scope,
            "label": self.label,
        }


@dataclass
class DR6Status:
    """Decoded DR6 debug status 寄存器 a breakpoint hit
    
    DR6 寄存器布局：
    Bit 0-3: B0-B3（对应断点槽位 0-3 触发标志）
    Bit 13: BD（调试寄存器访问检测）
    Bit 14: BS（单步执行 / Trap Flag 触发）
    Bit 15: BT（任务切换时 TSS 的 T 位触发）
    Bit 16: RTM（Intel TSX 事务中止）
    """
    raw_value: int
    breakpoint_hit: bool = False
    triggered_slot: Optional[int] = None         # 哪个槽位触发了断点（0-3）
    bs_flag: bool = False                         # 单步执行
    bd_flag: bool = False                         # 调试寄存器访问
    bt_flag: bool = False                         # 任务切换
    rtm_flag: bool = False                        # TSX 事务中止
    multiple_hits: bool = False                   # 多个槽位同时触发

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw": hex(self.raw_value),
            "breakpoint_hit": self.breakpoint_hit,
            "triggered_slot": self.triggered_slot,
            "bs_flag": self.bs_flag,             # Trap Flag
            "bd_flag": self.bd_flag,             # Debug 寄存器 Access
            "bt_flag": self.bt_flag,             # Task Switch
            "rtm_flag": self.rtm_flag,           # TSX Abort
            "multiple_hits": self.multiple_hits,
        }


class ThreadContext:
    """快照 thread 寄存器s needed for breakpoint management"""

    __slots__ = ("thread_id", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
                 "eflags", "rip", "accessible")

    def __init__(self, thread_id: int):
        self.thread_id = thread_id
        self.dr0 = self.dr1 = self.dr2 = self.dr3 = 0
        self.dr6 = 0
        self.dr7 = 0
        self.eflags = 0
        self.rip = 0
        self.accessible = False


class HWBreakpointMonitor:
    """硬件断点 lifecycle manager for x86-64 处理
    
    管理 DR0-DR7 寄存器 state across threads, 计算 DR7 masks
    解码 DR6 status hit, 支持 thread-scoped global
    breakpoint scopes
    
    架构决策：
    - DR7 按 slot 独立编码，使用 _compute_dr7_for_slot 为每个槽位
    计算其贡献位，然后 OR 合并。这避免了全局状态变量误用的问题
    - 每个线程维护独立的上下文快照，支持多线程断点安装
    - DR6 解码区分单槽位触发和多槽位同时触发两种场景
    """

    MAX_BREAKPOINTS = 4

    def __init__(self, target_pid: Optional[int] = None):
        self._target_pid = target_pid
        self._breakpoints: Dict[int, HardwareBreakpoint] = {}
        # 已安装断点的槽位位图
        self._active_slots: int = 0
        # 按线程跟踪上下文: thread_id -> ThreadContext
        self._thread_contexts: Dict[int, ThreadContext] = {}
        # 断点命中日志
        self._hit_log: List[Tuple[int, DR6Status, float]] = []

    # Thread enumeration

    def enumerate_threads(self) -> List[int]:
        """Enumerate thread IDs target process
        
        Linux: /proc/PID/task/
        Windows: CreateToolhelp32快照
        """
        thread_ids: List[int] = []
        if self._target_pid is None:
            return thread_ids

        if _IS_LINUX:
            task_dir = f"/proc/{self._target_pid}/task"
            if os.path.isdir(task_dir):
                for entry in os.listdir(task_dir):
                    try:
                        tid = int(entry)
                        thread_ids.append(tid)
                    except ValueError:
                        pass
        elif _IS_WINDOWS:
            # 使用 ctypes 调用 Windows API
            thread_ids = self._enumerate_windows_threads()

        return thread_ids

    def _enumerate_windows_threads(self) -> List[int]:
        """Windows thread enumeration via ctypes"""
        if not hasattr(ctypes, "windll"):
            return []
        try:
            kernel32 = ctypes.windll.kernel32
            TH32CS_SNAPTHREAD = 0x00000004
            THREADENTRY32 = ctypes.c_void_p
            # Stub: 完整实现需 THREADENTRY32 结构体和 Thread32First/Next 循环
            __log.debug("Windows thread enumeration stub.")
        except Exception:
            pass
        return []

    # Breakpoint CRUD

    def add_breakpoint(
        self,
        address: int,
        condition: BreakpointCondition,
        length: BreakpointLength,
        slot: Optional[int] = None,
        global_scope: bool = False,
        label: str = "",
    ) -> Optional[HardwareBreakpoint]:
        """Allocate a 硬件断点 address
        
        'slot' None, auto-assign first available slot (0-3)
        返回 created breakpoint or None slot available
        """
        if slot is not None and slot >= self.MAX_BREAKPOINTS:
            __log.error("Invalid slot %d (max %d).", slot, self.MAX_BREAKPOINTS)
            return None

        if slot is not None and slot in self._breakpoints:
            __log.warning("Slot %d already occupied. Overwriting.", slot)
            self.remove_breakpoint(slot)

        if slot is None:
            slot = self._find_free_slot()
            if slot is None:
                __log.error("No free hardware breakpoint slots (0-3 all used).")
                return None

        bp = HardwareBreakpoint(
            slot=slot,
            address=address,
            condition=condition,
            length=length,
            enabled=True,
            global_scope=global_scope,
            label=label,
        )
        self._breakpoints[slot] = bp
        self._active_slots |= (1 << slot)
        __log.info(
            "Breakpoint %d set at 0x%x (%s, %s) [%s].",
            slot, address, condition.name, length.name, label
        )
        return bp

    def remove_breakpoint(self, slot: int) -> bool:
        """Remove a 硬件断点 slot index"""
        if slot not in self._breakpoints:
            return False
        del self._breakpoints[slot]
        self._active_slots &= ~(1 << slot)
        return True

    def list_breakpoints(self) -> List[HardwareBreakpoint]:
        """返回 currently 配置ured breakpoints"""
        return list(self._breakpoints.values())

    def _find_free_slot(self) -> Optional[int]:
        """查找 first unused slot (0-3)"""
        for slot in range(self.MAX_BREAKPOINTS):
            if slot not in self._breakpoints:
                return slot
        return None

    # DR7 computation
    #
    # 修复说明：_compute_dr7 不再引用模块级 dwIdx 变量
    # 每个槽位的 enable/condition/length 位由局部变量 idx 直接计算
    # 避免了全局变量泄露导致的位掩码错误

    def _compute_dr7_for_slot(self, idx: int) -> int:
        """计算 DR7 contribution for a single breakpoint slot
        
        Args:
        idx: Slot index (0-3)
        
        返回:
        Bitmask OR DR7 for slot
        """
        bp = self._breakpoints.get(idx)
        if bp is None or not bp.enabled:
            return 0

        dr7_value = 0

        # 局部/全局使能
        if bp.global_scope:
            dr7_value |= _DR7_GLOBAL_ENABLE[idx]
        else:
            dr7_value |= _DR7_LOCAL_ENABLE[idx]

        # RW 条件
        rw_bits = int(bp.condition) & 0x3
        dr7_value |= (rw_bits << _DR7_RW_SHIFT[idx])

        # LEN 长度
        len_bits = int(bp.length) & 0x3
        dr7_value |= (len_bits << _DR7_LEN_SHIFT[idx])

        return dr7_value

    def compute_dr7(self) -> int:
        """计算 full DR7 寄存器 value for active breakpoints
        
        合并所有槽位的贡献 + LE/GE 兼容位 + GD 检测位
        """
        dr7 = DR7_LE | DR7_GE           # 兼容位（P6 前处理器需要置 1）

        for slot in range(self.MAX_BREAKPOINTS):
            dr7 |= self._compute_dr7_for_slot(slot)

        return dr7

    def compute_dr7_mask(self) -> int:
        """计算 a 写入 mask for DR7 touches active slots
        
        用于 SetThreadContext 时的保护——避免覆盖其他调试器的设置
        只修改当前活跃槽位对应的 bit，其余保持原值
        """
        mask = 0
        for slot in range(self.MAX_BREAKPOINTS):
            bp = self._breakpoints.get(slot)
            if bp is None or not bp.enabled:
                continue
            # 启用 bits
            mask |= _DR7_LOCAL_ENABLE[slot]
            mask |= _DR7_GLOBAL_ENABLE[slot]
            # RW bits
            mask |= (0x3 << _DR7_RW_SHIFT[slot])
            # LEN bits
            mask |= (0x3 << _DR7_LEN_SHIFT[slot])
        # 总是包含 LE/GE
        mask |= (DR7_LE | DR7_GE)
        return mask

    # DR6 status 解码

    def decode_dr6(self, dr6_raw: int) -> DR6Status:
        """解码 DR6 debug status 寄存器 a breakpoint hit
        
        DR6 是"粘性"寄存器——处理器在检测到断点条件时置位
        但不会自动清除。软件必须在处理完断点后清除对应的 bit
        
        解码流程：
        1. 读取 DR6 原始值
        2. 识别哪个 B0-B3 位被置位（一次可能多个）
        3. 检查 BS/BD/BT/RTM 辅助标志
        4. 格式化返回 DR6Status
        """
        b0 = (dr6_raw & (1 << 0)) != 0
        b1 = (dr6_raw & (1 << 1)) != 0
        b2 = (dr6_raw & (1 << 2)) != 0
        b3 = (dr6_raw & (1 << 3)) != 0
        bs_flag = (dr6_raw & (1 << 14)) != 0      # 单步
        bd_flag = (dr6_raw & (1 << 13)) != 0      # 调试寄存器访问
        bt_flag = (dr6_raw & (1 << 15)) != 0      # 任务切换
        rtm_flag = (dr6_raw & (1 << 16)) != 0     # TSX 中止

        hit_slots = [i for i, hit in enumerate([b0, b1, b2, b3]) if hit]
        triggered_slot = hit_slots[0] if len(hit_slots) == 1 else None
        multiple_hits = len(hit_slots) > 1
        breakpoint_hit = len(hit_slots) > 0

        status = DR6Status(
            raw_value=dr6_raw,
            breakpoint_hit=breakpoint_hit,
            triggered_slot=triggered_slot,
            bs_flag=bs_flag,
            bd_flag=bd_flag,
            bt_flag=bt_flag,
            rtm_flag=rtm_flag,
            multiple_hits=multiple_hits,
        )
        return status

    def clear_dr6(self) -> int:
        """构造 value 写入 back DR6 清除 hit flags
        
        Intel manual: 写入 DR6 时，设置 B0-B3 为 1 反而会清除这些 bit
        这是因为 DR6 的 B0-B3 位是写-1-清除（写入-1--清除）的
        其他 bit（BS, BD, BT）应保持为 0 在写入值中
        
        返回应写入 DR6 的值
        """
        # 对所有活跃槽位设置对应的 B 位为 1（清除操作）
        clear_mask = 0
        for slot in range(self.MAX_BREAKPOINTS):
            if slot in self._breakpoints:
                clear_mask |= (1 << slot)
        return clear_mask

    # Thread context manipulation

    def attach_to_thread(self, thread_id: int) -> bool:
        """Attach capture debug 寄存器 state a thread"""
        ctx = ThreadContext(thread_id)
        # Stub: 实际实现需要 ptrace(PTRACE_GETREGSET, NT_X86_XSTATE)
        # 或 Windows 的 GetThreadContext
        if _IS_LINUX:
            ctx.accessible = self._linux_get_thread_regs(thread_id, ctx)
        elif _IS_WINDOWS:
            ctx.accessible = self._windows_get_thread_context(thread_id, ctx)

        if ctx.accessible:
            self._thread_contexts[thread_id] = ctx
            return True
        return False

    def _linux_get_thread_regs(self, tid: int, ctx: ThreadContext) -> bool:
        """读取 debug 寄存器s a Linux thread via ptrace"""
        # 需要 ptrace attach 权限；stub 返回 False 表示未实现
        __log.debug("Linux ptrace regs read stub for TID %d.", tid)
        return False

    def _windows_get_thread_context(self, tid: int, ctx: ThreadContext) -> bool:
        """读取 debug 寄存器s a Windows thread via GetThreadContext"""
        __log.debug("Windows GetThreadContext stub for TID %d.", tid)
        return False

    def install_breakpoints_on_thread(self, thread_id: int) -> bool:
        """写入 debug 寄存器s for thread
        
        写入 DR0-DR3 (breakpoint addresses) DR7 (control)
        thread's debug 寄存器 set
        """
        if thread_id not in self._thread_contexts:
            if not self.attach_to_thread(thread_id):
                __log.error(
                    "Cannot access thread %d context -- "
                    "breakpoint installation failed.", thread_id
                )
                return False

        ctx = self._thread_contexts[thread_id]

        # 写入断点地址
        for slot in range(self.MAX_BREAKPOINTS):
            bp = self._breakpoints.get(slot)
            if bp and bp.enabled:
                if slot == 0:
                    ctx.dr0 = bp.address
                elif slot == 1:
                    ctx.dr1 = bp.address
                elif slot == 2:
                    ctx.dr2 = bp.address
                elif slot == 3:
                    ctx.dr3 = bp.address

        ctx.dr7 = self.compute_dr7()
        __log.info(
            "Installed %d breakpoints on thread %d (DR7=0x%x).",
            sum(1 for bp in self._breakpoints.values() if bp.enabled),
            thread_id, ctx.dr7
        )
        return True

    # Multi-thread breakpoint attachment

    def monitor_all_threads(self) -> Dict[int, bool]:
        """Attach 硬件断点s thread target process
        
        遍历目标进程的所有线程，为每个线程安装当前配置的硬件断点
        返回 {thread_id: success} 映射，用于诊断部分安装失败的情况
        
        设计考量：SetThreadContext 在 x86-64 上操作的是每个线程独立
        的调试寄存器副本。线程创建时不继承父线程的 DR 值（Intel 规范）
        因此必须为每个现有线程单独设置。这也意味着新创建的线程不会
        自动获得断点——如果需要在新建线程上也安装断点，需要在线程
        创建钩子处重新调用本方法
        """
        thread_ids = self.enumerate_threads()
        results: Dict[int, bool] = {}

        for tid in thread_ids:
            success = self.install_breakpoints_on_thread(tid)
            results[tid] = success
            if not success:
                __log.warning(
                    "Failed to install breakpoints on thread %d.", tid
                )

        success_count = sum(1 for v in results.values() if v)
        __log.info(
            "monitor_all_threads: %d/%d threads instrumented.",
            success_count, len(results)
        )
        return results

    def get_thread_context(self, thread_id: int) -> Optional[ThreadContext]:
        """Retrieve the缓存d thread context 快照"""
        return self._thread_contexts.get(thread_id)

    # Breakpoint hit 记录

    def log_breakpoint_hit(
        self, slot: int, dr6_status: DR6Status
    ) -> None:
        """Record a breakpoint hit event timestamp"""
        self._hit_log.append((
            slot,
            dr6_status,
            __import__("time").time(),
        ))

    def get_hit_log(self) -> List[Tuple[int, DR6Status, float]]:
        """Retrieve breakpoint hit history"""
        return list(self._hit_log)

    def clear_hit_log(self) -> None:
        """清除 hit 记录"""
        self._hit_log.clear()

    # Utility: summary

    def get_status_summary(self) -> Dict[str, Any]:
        """返回 a diagnostic summary 监控 state"""
        return {
            "target_pid": self._target_pid,
            "active_breakpoints": len(self._breakpoints),
            "active_slots_bitmap": bin(self._active_slots),
            "dr7_computed": hex(self.compute_dr7()),
            "monitored_threads": len(self._thread_contexts),
            "total_hits": len(self._hit_log),
            "breakpoints": [
                bp.to_dict() for bp in self._breakpoints.values()
            ],
        }

    def clear(self) -> None:
        """重置 state"""
        self._breakpoints.clear()
        self._active_slots = 0
        self._thread_contexts.clear()
        self._hit_log.clear()
