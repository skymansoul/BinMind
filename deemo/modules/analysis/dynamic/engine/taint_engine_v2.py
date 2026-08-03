# 2026-07-16
# AirTaint 风格二级污点引擎 —— 寄存器污点 + 字节粒度内存污点
# 设计思路：4KB 分页内存污点图，超过 50% 同质时折叠优化
# 默认策略覆盖 Unix syscall 和 Win32 API 的常见数据流入

import logging
from enum import IntFlag, Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any
from collections import defaultdict

_log = logging.getLogger(__name__)


# ===== 污点标记位 =====

class TaintTag(IntFlag):
    """污点来源标记 —— 位标志组合"""
    INPUT   = 1 << 0  # 用户输入
    NETWORK = 1 << 1  # 网络数据
    FILE    = 1 << 2  # 文件读取
    HEAP    = 1 << 3  # 堆分配
    STACK   = 1 << 4  # 栈数据
    DERIVED = 1 << 5  # 间接传播


class TaintSource(Enum):
    """对应 TaintTag 的可读枚举"""
    INPUT   = TaintTag.INPUT
    NETWORK = TaintTag.NETWORK
    FILE    = TaintTag.FILE
    HEAP    = TaintTag.HEAP
    STACK   = TaintTag.STACK
    DERIVED = TaintTag.DERIVED


# ===== 寄存器污点映射 =====

class RegTaintMap:
    """每个寄存器的污点状态"""

    def __init__(self):
        self._map: Dict[str, int] = {}  # reg_name → TaintTag int

    def set(self, reg_name: str, tags: TaintTag) -> None:
        self._map[reg_name] = tags.value if isinstance(tags, TaintTag) else int(tags)

    def get(self, reg_name: str) -> TaintTag:
        return TaintTag(self._map.get(reg_name, 0))

    def clear(self, reg_name: str) -> None:
        self._map.pop(reg_name, None)

    def clear_all(self) -> None:
        self._map.clear()

    # //// 寄存器间污点传递 ////
    def merge(self, reg_dest: str, reg_src: str) -> None:
        """dest 继承 src 的污点"""
        src_tags = self._map.get(reg_src, 0)
        if src_tags:
            self._map[reg_dest] = src_tags

    def union(self, reg_dest: str, reg_src1: str, reg_src2: str) -> None:
        """dest = src1 | src2"""
        tags = self._map.get(reg_src1, 0) | self._map.get(reg_src2, 0)
        if tags:
            self._map[reg_dest] = tags

    def snapshot(self) -> Dict[str, int]:
        return dict(self._map)

    def __repr__(self) -> str:
        return f"RegTaintMap({len(self._map)} regs)"


# ===== 内存污点映射 =====

PAGE_SIZE = 4096
COLLAPSE_THRESHOLD = 0.5  # 超过 50% 同质即折叠


class MemTaintMap:
    """
    字节粒度内存污点图
    用 4KB page chunk，每个 chunk 是 bytearray taint flags
    折叠优化: 若 chunk 内 >50% 字节有相同 taint，替换为 uniform 表示
    """

    def __init__(self):
        self._chunks: Dict[int, Any] = {}  # page_base → bytearray | (int, bool_collapsed)

    @staticmethod
    def _page_base(addr: int) -> int:
        return addr & ~(PAGE_SIZE - 1)

    def _get_chunk(self, addr: int) -> Any:
        return self._chunks.get(self._page_base(addr))

    def _ensure_chunk(self, addr: int) -> Any:
        pb = self._page_base(addr)
        if pb not in self._chunks:
            self._chunks[pb] = bytearray(PAGE_SIZE)  # 初始全 0
        return self._chunks[pb]

    def set(self, addr: int, size: int, tags: TaintTag) -> None:
        tag_byte = tags.value if isinstance(tags, TaintTag) else int(tags)
        end = addr + size
        while addr < end:
            chunk = self._ensure_chunk(addr)
            if isinstance(chunk, bytearray):
                # 可写入
                offset = addr & (PAGE_SIZE - 1)
                write_len = min(PAGE_SIZE - offset, end - addr)
                for i in range(write_len):
                    chunk[offset + i] = tag_byte
                addr += write_len
            else:
                # 已折叠 → 需要展开
                old_val = chunk[0]
                chunk = bytearray([old_val] * PAGE_SIZE)
                pb = self._page_base(addr)
                self._chunks[pb] = chunk
                # 不 advance addr, 下轮迭代写入

    def get(self, addr: int, size: int) -> Set[int]:
        """返回该范围所有不同的 taint flag"""
        tags: Set[int] = set()
        end = addr + size
        while addr < end:
            chunk = self._get_chunk(addr)
            if chunk is None:
                # 未映射区域: 跳到下一个 page
                addr = self._page_base(addr) + PAGE_SIZE
                continue
            offset = addr & (PAGE_SIZE - 1)
            read_len = min(PAGE_SIZE - offset, end - addr)
            if isinstance(chunk, tuple):
                # 折叠存储 → (uniform_value, True)
                tags.add(chunk[0])
            else:
                for i in range(read_len):
                    tags.add(chunk[offset + i])
            addr += read_len
        return tags

    def clear_range(self, addr: int, size: int) -> None:
        end = addr + size
        while addr < end:
            chunk = self._get_chunk(addr)
            if chunk is None:
                addr = self._page_base(addr) + PAGE_SIZE
                continue
            offset = addr & (PAGE_SIZE - 1)
            clear_len = min(PAGE_SIZE - offset, end - addr)
            if isinstance(chunk, bytearray):
                for i in range(clear_len):
                    chunk[offset + i] = 0
            else:
                chunk = bytearray([chunk[0]] * PAGE_SIZE)
                pb = self._page_base(addr)
                self._chunks[pb] = chunk
                for i in range(clear_len):
                    chunk[offset + i] = 0
            addr += clear_len

    # //// 折叠优化 ////
    def _maybe_collapse(self, page_base: int) -> None:
        chunk = self._chunks.get(page_base)
        if not isinstance(chunk, bytearray):
            return
        # 统计最常见 taint
        freq: Dict[int, int] = defaultdict(int)
        for b in chunk:
            freq[b] += 1
        most_val = max(freq, key=freq.get)
        if freq[most_val] / PAGE_SIZE > COLLAPSE_THRESHOLD:
            self._chunks[page_base] = (most_val, True)  # uniform + collapsed
            _log.debug("page 0x%x collapsed → tag %d (%.1f%%)",
                       page_base, most_val, freq[most_val] / PAGE_SIZE * 100)

    def collapse_all(self) -> int:
        """对所有 page 执行折叠，返回折叠数"""
        collapsed = 0
        for pb in list(self._chunks.keys()):
            self._maybe_collapse(pb)
            if isinstance(self._chunks.get(pb), tuple):
                collapsed += 1
        return collapsed

    def stats(self) -> Dict[str, Any]:
        pages = len(self._chunks)
        collapsed_pages = sum(1 for v in self._chunks.values() if isinstance(v, tuple))
        return {"pages": pages, "collapsed": collapsed_pages,
                "ratio": collapsed_pages / max(pages, 1)}


# ===== BB 污点规则 =====

@dataclass
class BBTaintRule:
    """基本块级别的污点传播规则"""
    name: str = ""
    input_regs: Set[str] = field(default_factory=set)
    input_mem_offsets: Set[int] = field(default_factory=set)
    output_regs: Set[str] = field(default_factory=set)
    output_mem_offsets: Set[int] = field(default_factory=set)

    def apply(self, ctx: 'TaintContext') -> None:
        """
        根据规则传播污点
        output_regs 继承 input_regs 的污点并集
        """
        if not self.output_regs:
            return
        # 计算所有输入寄存器的污点并集
        union_tag = TaintTag(0)
        for r in self.input_regs:
            union_tag |= ctx.reg_taint.get(r)
        for off in self.input_mem_offsets:
            mem_tags = ctx.mem_taint.get(off, 1)
            for t in mem_tags:
                union_tag |= TaintTag(t)

        # 传播到输出寄存器
        for r in self.output_regs:
            existing = ctx.reg_taint.get(r)
            ctx.reg_taint.set(r, existing | union_tag)

        # 传播到输出内存偏移
        for off in self.output_mem_offsets:
            ctx.mem_taint.set(off, 8, union_tag)  # 默认 8 字节


# ===== 污点上下文 =====

class TaintContext:
    """
    持有寄存器污点映射和内存污点映射
    提供常见操作的传播方法
    """

    def __init__(self):
        self.reg_taint = RegTaintMap()
        self.mem_taint = MemTaintMap()

    # //// 寄存器间移动 ////
    def propagate_register_move(self, dst: str, src: str) -> None:
        self.reg_taint.merge(dst, src)

    # //// 二元操作 ////
    def propagate_binary_op(self, dst: str, src1: str, src2: str) -> None:
        self.reg_taint.union(dst, src1, src2)

    # //// 加载: mem→reg ////
    def propagate_load(self, dst_reg: str, mem_addr: int, size: int) -> None:
        tags = self.mem_taint.get(mem_addr, size)
        combined = 0
        for t in tags:
            combined |= t
        if combined:
            self.reg_taint.set(dst_reg, TaintTag(combined))

    # //// 存储: reg→mem ////
    def propagate_store(self, mem_addr: int, src_reg: str, size: int) -> None:
        tag = self.reg_taint.get(src_reg)
        if tag != TaintTag(0):
            self.mem_taint.set(mem_addr, size, tag)

    def clear_register(self, reg: str) -> None:
        self.reg_taint.clear(reg)

    def clear_memory(self, addr: int, size: int) -> None:
        self.mem_taint.clear_range(addr, size)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "reg_taint": self.reg_taint.snapshot(),
            "mem_stats": self.mem_taint.stats(),
        }


# ===== 事件类型 =====

@dataclass
class TraceEvent:
    """单条 trace 记录"""
    address: int = 0
    instruction: str = ""
    type: str = ""  # "reg_write", "mem_read", "mem_write", "branch", "call", "系统调用"
    operands: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintEvent:
    """带污点信息的 trace 事件"""
    address: int = 0
    instruction: str = ""
    reg_taint_before: Dict[str, int] = field(default_factory=dict)
    reg_taint_after: Dict[str, int] = field(default_factory=dict)
    mem_taint_delta: List[Tuple[int, int, int]] = field(default_factory=list)  # (addr, size, tag_before→tag_after)


# ===== 污点引擎 V2 =====

class TaintEngineV2:
    """
    从执行 trace 中计算污点传播
    内置 Unix 系统调用 和 Win32 API 的默认策略
    """

    def __init__(self):
        self.ctx = TaintContext()
        self._rules: Dict[str, BBTaintRule] = {}
        self._unix_policy = self.default_unix_policy()
        self._win32_policy = self.default_win32_policy()

    # ===== 默认策略 =====

    @staticmethod
    def default_unix_policy() -> Dict[str, BBTaintRule]:
        """读取/recv/recvfrom → taint 缓冲区; 打开 → taint fd"""
        rules: Dict[str, BBTaintRule] = {}
        # read(fd, buf, count)
        rules["read"] = BBTaintRule(
            name="read", input_regs={"rax"}, output_regs={"rsi"},
        )
        # recv(sock, buf, len, flags)
        rules["recv"] = BBTaintRule(
            name="recv", input_regs={"rax"}, output_regs={"rsi"},
        )
        rules["recvfrom"] = BBTaintRule(
            name="recvfrom", input_regs={"rax"}, output_regs={"rsi"},
        )
        return rules

    @staticmethod
    def default_win32_policy() -> Dict[str, BBTaintRule]:
        """ReadFile → taint lp缓冲区; recv → taint buf; URLDownloadToFile → taint file"""
        rules: Dict[str, BBTaintRule] = {}
        rules["ReadFile"] = BBTaintRule(
            name="ReadFile", input_regs={"rcx"}, output_regs={"rdx"},
        )
        rules["recv"] = BBTaintRule(
            name="recv", input_regs={"rcx"}, output_regs={"rdx"},
        )
        rules["URLDownloadToFileW"] = BBTaintRule(
            name="URLDownloadToFileW", input_regs={"rcx"},
            output_mem_offsets={0},  # 简化: 文件内容被 taint
        )
        rules["URLDownloadToFileA"] = BBTaintRule(
            name="URLDownloadToFileA", input_regs={"rcx"},
            output_mem_offsets={0},
        )
        rules["InternetReadFile"] = BBTaintRule(
            name="InternetReadFile", input_regs={"rcx"}, output_regs={"rdx"},
        )
        return rules

    def add_rule(self, rule: BBTaintRule) -> None:
        self._rules[rule.name] = rule

    def remove_rule(self, name: str) -> bool:
        if name in self._rules:
            del self._rules[name]
            return True
        return False

    # ===== trace 处理 =====
    def process_trace(self, trace: 'List[TraceEvent]') -> List[TaintEvent]:
        """
        核心方法: 逐条处理 trace，计算污点传播
        返回带污点信息的 TaintEvent 列表
        """
        results: List[TaintEvent] = []
        for ev in trace:
            before = self.ctx.reg_taint.snapshot()

            # 根据指令类型传播污点
            if ev.type == "reg_write":
                ops = ev.operands
                dst = ops.get("dst", "")
                src = ops.get("src", "")
                src2 = ops.get("src2", "")
                if src2:
                    self.ctx.propagate_binary_op(dst, src, src2)
                elif src:
                    self.ctx.propagate_register_move(dst, src)
                else:
                    # xor eax, eax → 清污点
                    self.ctx.clear_register(dst)

            elif ev.type == "mem_read":
                ops = ev.operands
                dst_reg = ops.get("reg", "")
                addr = ops.get("addr", 0)
                size = ops.get("size", 4)
                if dst_reg:
                    self.ctx.propagate_load(dst_reg, addr, size)

            elif ev.type == "mem_write":
                ops = ev.operands
                src_reg = ops.get("reg", "")
                addr = ops.get("addr", 0)
                size = ops.get("size", 4)
                if src_reg:
                    self.ctx.propagate_store(addr, src_reg, size)

            elif ev.type == "call":
                # 检查是否有匹配的 syscall 规则
                target = ev.operands.get("target", "")
                rule = self._unix_policy.get(target) or \
                       self._win32_policy.get(target) or \
                       self._rules.get(target)
                if rule:
                    rule.apply(self.ctx)

            elif ev.type == "syscall":
                # 通过 系统调用 number 匹配
                sysnum = ev.operands.get("number", -1)
                # 简化的 Unix syscall 映射
                if sysnum in (0,):    # 读取
                    self.ctx.reg_taint.set("rsi", TaintTag.INPUT)
                elif sysnum in (1,):  # write (不 taint)
                    pass

            after = self.ctx.reg_taint.snapshot()
            results.append(TaintEvent(
                address=ev.address,
                instruction=ev.instruction,
                reg_taint_before=before,
                reg_taint_after=after,
            ))

        return results

    def reset(self) -> None:
        """重置所有污点状态"""
        self.ctx.reg_taint.clear_all()
        self.ctx.mem_taint = MemTaintMap()
