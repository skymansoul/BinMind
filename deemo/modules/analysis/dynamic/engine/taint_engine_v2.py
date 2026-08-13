# 2026-07-16
# AirTaint 风格二级污点引擎 —— 寄存器污点 + 字节粒度内存污点
# 设计思路：4KB 分页内存污点图，超过 50% 同质时折叠优化
# 默认策略覆盖 Unix syscall 和 Win32 API 的常见数据流入
# 同时提供基本块级（process_bb）与 trace 级（process_trace）两种处理入口，
# 前者面向静态分析事件流，后者面向动态执行 trace。

import logging
from enum import IntFlag, Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any
from collections import defaultdict

_log = logging.getLogger(__name__)


# 架构枚举 —— 用于寄存器集定义与访问模式切换

class Arch(Enum):
    """目标架构 —— 决定寄存器命名集合"""
    X86 = "x86"
    X64 = "x64"


# 污点标记位

class TaintTag(IntFlag):
    """污点来源标记 —— 位标志组合"""
    CLEAN       = 0
    USER_INPUT  = 1 << 0  # 用户输入
    NETWORK     = 1 << 1  # 网络数据
    FILE        = 1 << 2  # 文件读取
    HEAP        = 1 << 3  # 堆分配
    STACK       = 1 << 4  # 栈数据
    DERIVED     = 1 << 5  # 间接传播
    POISON      = 1 << 6  # 主动污染标记
    ANY         = 0xFF    # 任意污点掩码


class TaintSource(Enum):
    """对应 TaintTag 的可读枚举"""
    INPUT   = TaintTag.USER_INPUT
    NETWORK = TaintTag.NETWORK
    FILE    = TaintTag.FILE
    HEAP    = TaintTag.HEAP
    STACK   = TaintTag.STACK
    DERIVED = TaintTag.DERIVED


class TaintSink(Enum):
    """污点汇聚点 —— 危险操作位置"""
    EXEC    = TaintTag.USER_INPUT  # 代码执行
    WRITE   = TaintTag.NETWORK     # 内存写
    CALL    = TaintTag.FILE        # 函数调用参数


# 寄存器污点映射

class RegTaintMap:
    """每个寄存器的污点状态"""

    def __init__(self, arch: Arch = Arch.X64):
        self._arch = arch
        self._tags: Dict[str, int] = {}  # reg_name → TaintTag int
        # 预填寄存器键，保证 get/clear/is_tainted 对已知寄存器恒有效
        for r in self._registers(arch):
            self._tags[r] = 0

    @staticmethod
    def _registers(arch: Arch) -> Tuple[str, ...]:
        """返回架构对应的寄存器名集合"""
        if arch == Arch.X86:
            return ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
                    'ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp')
        return ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
                'zf', 'cf', 'sf', 'of')

    def set(self, reg_name: str, tags: TaintTag) -> None:
        """设置寄存器污点，支持组合标记"""
        self._tags[reg_name] = tags.value if isinstance(tags, TaintTag) else int(tags)

    def get(self, reg_name: str) -> TaintTag:
        """读取寄存器污点；未标注返回 CLEAN"""
        return TaintTag(self._tags.get(reg_name, 0))

    def clear(self, reg_name: str) -> None:
        """清除单个寄存器污点"""
        self._tags.pop(reg_name, None)

    def clear_all(self) -> None:
        """清空全部寄存器污点"""
        self._tags.clear()

    def is_tainted(self, reg_name: str) -> bool:
        """判断寄存器是否带有任意污点标记"""
        return self._tags.get(reg_name, 0) != 0

    def merge(self, reg_dest: str, reg_src: str) -> None:
        """dest 继承 src 的污点"""
        src_tags = self._tags.get(reg_src, 0)
        if src_tags:
            self._tags[reg_dest] = src_tags

    def union(self, reg_dest: str, *srcs: str) -> TaintTag:
        """dest = src1 | src2 | ...；返回合并后的污点标记。

        单源时相当于 merge；返回值便于调用方直接读取合并结果。
        """
        tags = 0
        for s in srcs:
            tags |= self._tags.get(s, 0)
        if tags:
            self._tags[reg_dest] = tags
        return TaintTag(tags)

    def snapshot(self) -> Dict[str, int]:
        """返回污点状态快照，供保存/恢复使用"""
        return dict(self._tags)

    def restore(self, snap: Dict[str, int]) -> None:
        """从快照恢复污点状态"""
        self._tags = dict(snap)

    def __repr__(self) -> str:
        return f"RegTaintMap({len(self._tags)} regs)"


# 内存污点映射

PAGE_SIZE = 4096
COLLAPSE_THRESHOLD = 0.5  # 超过 50% 同质即折叠


class MemTaintChunk:
    """单个 4KB 页的内存污点块 —— 字节粒度标记 + 折叠优化"""

    def __init__(self, base_addr: int):
        self.base = base_addr
        self.byte_tags = bytearray(PAGE_SIZE)  # 初始全 CLEAN
        self.full_taint: TaintTag = TaintTag.CLEAN  # 折叠表示

    def _is_collapsed(self) -> bool:
        """判断当前是否处于折叠态"""
        return self.full_taint != TaintTag.CLEAN and len(self.byte_tags) == 0

    def _expand(self) -> None:
        """将折叠态展开为字节数组"""
        val = self.full_taint.value if isinstance(self.full_taint, TaintTag) else int(self.full_taint)
        self.byte_tags = bytearray([val] * PAGE_SIZE)
        self.full_taint = TaintTag.CLEAN

    def set(self, offset: int, tag: TaintTag) -> None:
        """设置单字节污点；若处于折叠态需先展开"""
        if self._is_collapsed():
            self._expand()
        self.byte_tags[offset] = tag.value if isinstance(tag, TaintTag) else int(tag)
        self._maybe_collapse()

    def get(self, offset: int) -> TaintTag:
        """读取单字节污点"""
        if self._is_collapsed():
            return self.full_taint
        return TaintTag(self.byte_tags[offset])

    def set_range(self, offset: int, size: int, tag: TaintTag) -> None:
        """设置一段连续字节的污点"""
        if self._is_collapsed():
            self._expand()
        val = tag.value if isinstance(tag, TaintTag) else int(tag)
        end = min(offset + size, PAGE_SIZE)
        for i in range(offset, end):
            self.byte_tags[i] = val
        self._maybe_collapse()

    def any_tainted_in_range(self, offset: int, size: int) -> bool:
        """检查范围内是否存在任意污点"""
        if self._is_collapsed():
            return self.full_taint != TaintTag.CLEAN
        end = min(offset + size, PAGE_SIZE)
        for i in range(offset, end):
            if self.byte_tags[i] != 0:
                return True
        return False

    def _maybe_collapse(self) -> None:
        """统计最常见的污点值，若占比超阈值且非全 CLEAN 则折叠。

        CLEAN 占绝对多数时不折叠 —— 折叠态语义为"整页同值非零污点"，
        纯 CLEAN 页保持字节数组，避免折叠后丢失字节级信息。
        """
        if len(self.byte_tags) == 0:
            return
        freq: Dict[int, int] = defaultdict(int)
        for b in self.byte_tags:
            freq[b] += 1
        most_val = max(freq, key=freq.get)
        if most_val == 0:
            return
        if freq[most_val] / PAGE_SIZE >= COLLAPSE_THRESHOLD:
            self.full_taint = TaintTag(most_val)
            self.byte_tags = bytearray()  # 标记已折叠


class MemTaintMap:
    """
    字节粒度内存污点图
    用 4KB page chunk，每个 chunk 是 bytearray taint flags
    折叠优化: 若 chunk 内 >50% 字节有相同 taint，替换为 uniform 表示
    """

    def __init__(self):
        self._chunks: Dict[int, MemTaintChunk] = {}

    @property
    def chunk_count(self) -> int:
        return len(self._chunks)

    @staticmethod
    def _page_base(addr: int) -> int:
        return addr & ~(PAGE_SIZE - 1)

    def _get_chunk(self, addr: int) -> Optional[MemTaintChunk]:
        return self._chunks.get(self._page_base(addr))

    def _ensure_chunk(self, addr: int) -> MemTaintChunk:
        pb = self._page_base(addr)
        chunk = self._chunks.get(pb)
        if chunk is None:
            chunk = MemTaintChunk(pb)
            self._chunks[pb] = chunk
        return chunk

    def set(self, addr: int, tag: TaintTag, size: int = 1) -> None:
        """在指定地址写入污点标记，跨页时自动分段"""
        tag_val = tag.value if isinstance(tag, TaintTag) else int(tag)
        if tag_val == 0:
            self.clear_range(addr, size)
            return
        end = addr + size
        while addr < end:
            chunk = self._ensure_chunk(addr)
            offset = addr & (PAGE_SIZE - 1)
            write_len = min(PAGE_SIZE - offset, end - addr)
            chunk.set_range(offset, write_len, TaintTag(tag_val))
            addr += write_len

    def get(self, addr: int) -> TaintTag:
        """读取单字节污点"""
        chunk = self._get_chunk(addr)
        if chunk is None:
            return TaintTag.CLEAN
        return chunk.get(addr & (PAGE_SIZE - 1))

    def is_tainted(self, addr: int) -> bool:
        """判断地址是否带有污点"""
        return self.get(addr) != TaintTag.CLEAN

    def set_range(self, addr: int, size: int, tag: TaintTag) -> None:
        """设置连续地址范围的污点"""
        self.set(addr, tag, size)

    def any_in_range(self, addr: int, size: int) -> bool:
        """检查地址范围内是否存在任意污点"""
        end = addr + size
        while addr < end:
            chunk = self._get_chunk(addr)
            if chunk is None:
                # 未映射区域: 跳到下一个 page
                addr = self._page_base(addr) + PAGE_SIZE
                continue
            offset = addr & (PAGE_SIZE - 1)
            read_len = min(PAGE_SIZE - offset, end - addr)
            if chunk.any_tainted_in_range(offset, read_len):
                return True
            addr += read_len
        return False

    def clear_range(self, addr: int, size: int) -> None:
        """清除地址范围内的污点标记"""
        end = addr + size
        while addr < end:
            chunk = self._get_chunk(addr)
            if chunk is None:
                addr = self._page_base(addr) + PAGE_SIZE
                continue
            offset = addr & (PAGE_SIZE - 1)
            clear_len = min(PAGE_SIZE - offset, end - addr)
            chunk.set_range(offset, clear_len, TaintTag.CLEAN)
            addr += clear_len

    def clear(self) -> None:
        """清空全部内存污点"""
        self._chunks.clear()

    def stats(self) -> Dict[str, Any]:
        pages = len(self._chunks)
        collapsed = sum(1 for c in self._chunks.values() if c._is_collapsed())
        return {"pages": pages, "collapsed": collapsed,
                "ratio": collapsed / max(pages, 1)}


# BB 污点规则

@dataclass
class BBTaintRule:
    """基本块级别的污点传播规则"""
    name: str = ""
    input_regs: Set[str] = field(default_factory=set)
    input_mem_offsets: Set[int] = field(default_factory=set)
    output_regs: Set[str] = field(default_factory=set)
    output_mem_offsets: Set[int] = field(default_factory=set)

    def match(self, reg_taint: RegTaintMap, mem_taint: MemTaintMap,
              regs: Dict[str, int]) -> bool:
        """判断规则是否适用 —— 任一输入寄存器或内存偏移已污染"""
        for r in self.input_regs:
            if reg_taint.is_tainted(r):
                return True
        for off in self.input_mem_offsets:
            if mem_taint.is_tainted(off):
                return True
        return False

    def apply(self, reg_taint: RegTaintMap, mem_taint: MemTaintMap,
              regs: Dict[str, int]) -> None:
        """传播污点 —— 输出寄存器继承输入污点并集"""
        if not self.output_regs and not self.output_mem_offsets:
            return
        union_tag = TaintTag.CLEAN
        for r in self.input_regs:
            union_tag |= reg_taint.get(r)
        for off in self.input_mem_offsets:
            union_tag |= mem_taint.get(off)
        if union_tag == TaintTag.CLEAN:
            return
        for r in self.output_regs:
            existing = reg_taint.get(r)
            reg_taint.set(r, existing | union_tag)
        for off in self.output_mem_offsets:
            mem_taint.set(off, union_tag, size=8)


# 污点策略 —— 定义 source/sink 函数与传播规则

class TaintPolicy:
    """污点策略 —— 声明污点来源、汇聚点与传播规则"""

    def __init__(self, name: str = "default"):
        self.name = name
        self.sources: Set[str] = set()
        self.sinks: Set[str] = set()
        self.rules: Dict[str, BBTaintRule] = {}

    def add_source(self, func: str) -> None:
        self.sources.add(func)

    def add_sink(self, func: str) -> None:
        self.sinks.add(func)

    def add_rule(self, rule: BBTaintRule) -> None:
        self.rules[rule.name] = rule

    def is_source(self, func: str) -> bool:
        return func in self.sources

    def is_sink(self, func: str) -> bool:
        return func in self.sinks


def default_unix_policy() -> TaintPolicy:
    """Unix syscall 污点策略：read/recv 系列为来源，exec 系列为汇聚点"""
    policy = TaintPolicy("unix")
    for src in ('read', 'recv', 'recvfrom', 'readv', 'pread', 'fgets', 'scanf'):
        policy.add_source(src)
    for sink in ('execve', 'exec', 'system', 'mprotect', 'munmap', 'mmap'):
        policy.add_sink(sink)
    policy.add_rule(BBTaintRule(
        name="read", input_regs={'rax'}, output_regs={'rsi'}))
    policy.add_rule(BBTaintRule(
        name="recv", input_regs={'rax'}, output_regs={'rsi'}))
    policy.add_rule(BBTaintRule(
        name="recvfrom", input_regs={'rax'}, output_regs={'rsi'}))
    return policy


def default_win32_policy() -> TaintPolicy:
    """Win32 API 污点策略：ReadFile/recv 为来源，CreateProcess 为汇聚点"""
    policy = TaintPolicy("win32")
    for src in ('ReadFile', 'recv', 'InternetReadFile', 'URLDownloadToFileW',
                'URLDownloadToFileA', 'GetModuleHandleA', 'GetCommandLineA'):
        policy.add_source(src)
    for sink in ('CreateProcess', 'CreateProcessW', 'WinExec', 'ShellExecute',
                 'VirtualProtect', 'WriteProcessMemory'):
        policy.add_sink(sink)
    policy.add_rule(BBTaintRule(
        name="ReadFile", input_regs={'rcx'}, output_regs={'rdx'}))
    policy.add_rule(BBTaintRule(
        name="recv", input_regs={'rcx'}, output_regs={'rdx'}))
    policy.add_rule(BBTaintRule(
        name="URLDownloadToFileW", input_regs={'rcx'}, output_mem_offsets={0}))
    policy.add_rule(BBTaintRule(
        name="InternetReadFile", input_regs={'rcx'}, output_regs={'rdx'}))
    return policy


# 污点违规记录

@dataclass
class TaintViolation:
    """污点汇聚违规 —— 污染数据流入危险操作"""
    sink: str
    regs: List[str] = field(default_factory=list)
    tag: TaintTag = TaintTag.CLEAN
    addr: int = 0
    severity: str = "high"


# 污点上下文（兼容 AirTaint 风格的 trace 处理）

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
        tag = self.mem_taint.get(mem_addr)
        if tag != TaintTag.CLEAN:
            self.reg_taint.set(dst_reg, tag)

    # //// 存储: reg→mem ////
    def propagate_store(self, mem_addr: int, src_reg: str, size: int) -> None:
        tag = self.reg_taint.get(src_reg)
        if tag != TaintTag.CLEAN:
            self.mem_taint.set(mem_addr, tag, size)

    def clear_register(self, reg: str) -> None:
        self.reg_taint.clear(reg)

    def clear_memory(self, addr: int, size: int) -> None:
        self.mem_taint.clear_range(addr, size)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "reg_taint": self.reg_taint.snapshot(),
            "mem_stats": self.mem_taint.stats(),
        }


# 事件类型

@dataclass
class TraceEvent:
    """单条 trace 记录"""
    address: int = 0
    instruction: str = ""
    type: str = ""
    operands: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintEvent:
    """带污点信息的 trace 事件"""
    address: int = 0
    instruction: str = ""
    reg_taint_before: Dict[str, int] = field(default_factory=dict)
    reg_taint_after: Dict[str, int] = field(default_factory=dict)
    mem_taint_delta: List[Tuple[int, int, int]] = field(default_factory=list)


# 污点引擎 V2

class TaintEngineV2:
    """
    从执行 trace 中计算污点传播
    内置 Unix 系统调用 和 Win32 API 的默认策略
    """

    def __init__(self, policy: Optional[TaintPolicy] = None,
                 arch: Arch = Arch.X64):
        self.arch = arch
        self.policy = policy if policy is not None else default_unix_policy()
        self.reg_taint = RegTaintMap(arch)
        self.mem_taint = MemTaintMap()
        self._ctx = TaintContext()
        self._ctx.reg_taint = self.reg_taint
        self._ctx.mem_taint = self.mem_taint
        self._violations: List[TaintViolation] = []
        self._rules_fired = 0
        self._trace_events: List[TraceEvent] = []

    def process_bb(self, events: List[Dict[str, Any]]) -> None:
        """处理基本块事件流，应用污点来源/传播/汇聚检测"""
        for ev in events:
            etype = ev.get('type', '')
            func_name = ev.get('func_name', '')
            regs_in = ev.get('regs_in', {})
            regs_out = ev.get('regs_out', {})
            args = ev.get('args', [])

            if etype == 'syscall':
                # 来源函数：返回值寄存器标记污点
                if self.policy.is_source(func_name):
                    self._apply_source(func_name, args, regs_out)
                # 汇聚函数：检查参数寄存器污染
                if self.policy.is_sink(func_name):
                    self._check_sink(func_name, regs_in, args)
                continue

            if etype == 'instr':
                # 指令级传播：应用匹配的 BB 规则
                rule = self._match_rule(func_name, regs_in)
                if rule is not None:
                    rule.apply(self.reg_taint, self.mem_taint, regs_in)
                    self._rules_fired += 1

    def _apply_source(self, func: str, args: List[int],
                      regs_out: Dict[str, int]) -> None:
        """来源函数返回值标记污点 —— 读入数据进入寄存器"""
        tag = self._source_tag(func)
        if 'rax' in regs_out:
            self.reg_taint.set('rax', self.reg_taint.get('rax') | tag)

    def _source_tag(self, func: str) -> TaintTag:
        if func in ('recv', 'recvfrom', 'socket', 'accept'):
            return TaintTag.NETWORK
        if func in ('fopen', 'fread', 'fgets', 'read'):
            return TaintTag.USER_INPUT
        return TaintTag.USER_INPUT

    def _check_sink(self, func: str, regs_in: Dict[str, int],
                    args: List[int]) -> None:
        """检测汇聚点参数是否污染，记录违规"""
        tainted_regs: List[str] = []
        tag = TaintTag.CLEAN
        for reg, val in regs_in.items():
            if self.reg_taint.is_tainted(reg):
                tainted_regs.append(reg)
                tag |= self.reg_taint.get(reg)
        if not tainted_regs:
            return
        self._violations.append(TaintViolation(
            sink=func, regs=tainted_regs, tag=tag, severity="high"))

    def _match_rule(self, name: str, regs: Dict[str, int]) -> Optional[BBTaintRule]:
        """按规则名或输入寄存器匹配传播规则"""
        rule = self.policy.rules.get(name)
        if rule is not None:
            return rule
        for r in self.policy.rules.values():
            if r.input_regs and any(reg in regs for reg in r.input_regs):
                return r
        return None

    def check_violations(self) -> List[TaintViolation]:
        """返回当前累积的污点汇聚违规"""
        return self._violations

    def get_stats(self) -> Dict[str, Any]:
        """输出引擎统计信息"""
        return {
            'rules_fired': self._rules_fired,
            'violations': len(self._violations),
            'tainted_regs': sum(1 for _ in range(0)),
        }

    # 兼容 AirTaint 风格 —— 基于 TraceEvent 的逐条处理
    def process_trace(self, trace: List[TraceEvent]) -> List[TaintEvent]:
        """逐条处理 trace，计算污点传播并返回带污点信息的事件列表"""
        results: List[TaintEvent] = []
        for ev in trace:
            before = self.reg_taint.snapshot()
            if ev.type == "reg_write":
                ops = ev.operands
                dst = ops.get("dst", "")
                src = ops.get("src", "")
                src2 = ops.get("src2", "")
                if src2:
                    self._ctx.propagate_binary_op(dst, src, src2)
                elif src:
                    self._ctx.propagate_register_move(dst, src)
                else:
                    self._ctx.clear_register(dst)
            elif ev.type == "mem_read":
                ops = ev.operands
                dst_reg = ops.get("reg", "")
                addr = ops.get("addr", 0)
                size = ops.get("size", 4)
                if dst_reg:
                    self._ctx.propagate_load(dst_reg, addr, size)
            elif ev.type == "mem_write":
                ops = ev.operands
                src_reg = ops.get("reg", "")
                addr = ops.get("addr", 0)
                size = ops.get("size", 4)
                if src_reg:
                    self._ctx.propagate_store(addr, src_reg, size)
            elif ev.type == "call":
                # 检查是否有匹配的 syscall 规则
                target = ev.operands.get("target", "")
                rule = self.policy.rules.get(target)
                if rule is not None and rule.input_regs:
                    rule.apply(self.reg_taint, self.mem_taint, {})
            after = self.reg_taint.snapshot()
            results.append(TaintEvent(
                address=ev.address,
                instruction=ev.instruction,
                reg_taint_before=before,
                reg_taint_after=after,
            ))

        return results

    def reset(self) -> None:
        """重置所有污点状态"""
        self.reg_taint.clear_all()
        self.mem_taint.clear()
        self._violations = []
        self._rules_fired = 0
