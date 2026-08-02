# 2026-07-30

import random
import struct
import hashlib

# ---- ARM Memory Tagging Extension 模拟器 ----
# 基于ARMv8.5-A MTE规范，模拟tagged memory行为
# 支持TikTag式推测执行攻击分析


class TagMismatchFault(Exception):
    """标签不匹配时抛出 — 对应SIGSEGV同步异常"""

    def __init__(self, address: int, expected: int, actual: int):
        self.address = address
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"TagMismatch @ 0x{address:016x}: 期望0x{expected:x}, 实际0x{actual:x}"
        )


# ===== MTE状态机 =====
# 维护内存和标签映射，追踪分配/释放生命周期


class MTEState:
    def __init__(self, memory_size: int = 65536, tag_granule: int = 16):
        if tag_granule not in (16, 32, 64):
            raise ValueError("tag_granule必须是16/32/64")
        self._granule = tag_granule
        self._memory = bytearray(memory_size)
        _tag_count = (memory_size + tag_granule - 1) // tag_granule
        self._tags = bytearray(_tag_count)  # 每个granule一个4-bit tag (低4位)
        self._allocation_map: dict[int, int] = {}
        self._freed_set: set[int] = set()
        self._alloc_tag_counter = 0
        # TikTag风格: 追踪标签推测历史
        self._tag_probe_history: list[tuple[int, int, int, int]] = []

    # ---- 标签分配策略 ----
    # 三种策略对应不同的加固级别
    def tag_allocation(self, address: int, size: int, strategy: str = "sequential") -> int:
        _start_g = address // self._granule
        _end_g = (address + size + self._granule - 1) // self._granule
        if _end_g > len(self._tags):
            raise IndexError(f"分配越界: 地址0x{address:x}, 大小{size}")

        if strategy == "sequential":
            self._alloc_tag_counter = (self._alloc_tag_counter % 15) + 1
            tag = self._alloc_tag_counter
        elif strategy == "randomized":
            tag = random.randint(1, 15)  # tag=0保留为untagged
        elif strategy == "incremental":
            _h = struct.pack("<Q", address)
            _dig = hashlib.blake2b(_h, digest_size=2).digest()
            tag = (_dig[0] ^ _dig[1]) & 0x0F
            if tag == 0:
                tag = 1
        else:
            tag = 1

        # 写入标签到所有相关granule
        for _g in range(_start_g, _end_g):
            self._tags[_g] = tag
        self._allocation_map[address] = size
        self._freed_set.discard(address)
        return tag

    # ---- 带标签检查的存储 ----
    def store_with_tag(self, address: int, data: bytes, tag: int | None = None):
        _g = address // self._granule
        actual_tag = self._tags[_g] & 0x0F
        if tag is not None and (tag & 0x0F) != actual_tag:
            raise TagMismatchFault(address, tag & 0x0F, actual_tag)
        if address + len(data) > len(self._memory):
            raise IndexError(f"写入越界: 0x{address:x}+{len(data)}")
        self._memory[address:address + len(data)] = data

    # ---- 带标签验证的加载 ----
    def load_with_tag(self, address: int, size: int, expected_tag: int | None = None) -> bytes:
        _g = address // self._granule
        actual_tag = self._tags[_g] & 0x0F
        if expected_tag is not None and (expected_tag & 0x0F) != actual_tag:
            raise TagMismatchFault(address, expected_tag & 0x0F, actual_tag)
        if address + size > len(self._memory):
            raise IndexError(f"读取越界: 0x{address:x}+{size}")
        return bytes(self._memory[address:address + size])

    # ---- 基础操作 ----
    def check_tag(self, address: int) -> int:
        return self._tags[address // self._granule] & 0x0F

    # //// 内存安全检测 ////

    def detect_double_free(self, address: int) -> bool:
        return address in self._freed_set

    def detect_wild_free(self, address: int) -> bool:
        return address not in self._allocation_map and address not in self._freed_set

    def detect_uaf(self, address: int) -> bool:
        # Use-After-Free: 地址在freed_set中但仍被访问
        return address in self._freed_set

    def free_allocation(self, address: int):
        if address in self._allocation_map:
            _size = self._allocation_map.pop(address)
            _start_g = address // self._granule
            _end_g = (address + _size + self._granule - 1) // self._granule
            for _g in range(_start_g, min(_end_g, len(self._tags))):
                self._tags[_g] = 0  # 清空标签，实现use-after-free检测
            self._freed_set.add(address)

    # ===== TikTag式推测标签访问 =====
    # 模拟推测执行窗口内的标签检查：
    # - 推测执行不立即触发异常，而是记录结果
    # - 通过cache oracle推断标签值

    def check_speculative_tag_access(self, address: int) -> tuple[bool, int]:
        """推测性标签访问 — TikTag cache oracle风格.
        返回 (是否会触发fault, 解决的标签值).
        在推测窗口中不抛出异常，而是返回预测结果.
        """
        _g = address // self._granule
        if _g >= len(self._tags):
            return True, 0
        actual_tag = self._tags[_g] & 0x0F
        # 模拟推测窗口: 永远不fault, 但返回真实标签用于side-channel分析
        return False, actual_tag

    def speculative_load(
        self, address: int, size: int, predicted_tag: int
    ) -> tuple[bytes, bool]:
        """推测加载: 用预测的标签读取数据.
        返回 (数据, 预测是否正确).
        """
        actual_tag = self._tags[address // self._granule] & 0x0F
        correct = (predicted_tag & 0x0F) == actual_tag
        if address + size > len(self._memory):
            return b"", False
        self._tag_probe_history.append((address, predicted_tag, actual_tag, 1 if correct else 0))
        return bytes(self._memory[address:address + size]), correct


# ===== 地址标签提取 =====
# ARM TBI (Top Byte Ignore): 高8位用于存储tag
def get_tag_for_address(address: int, tag_shift: int = 4) -> int:
    """从ARM TBI地址中提取tag位"""
    return (address >> (64 - 4)) & 0x0F if tag_shift == 4 else (address >> 56) & 0xFF


# ===== MTESimulator 接口类 =====
# 包装MTEState，提供更易用的外部接口


class MTESimulator:
    def __init__(self, memory_size: int = 65536, tag_granule: int = 16):
        self._state = MTEState(memory_size, tag_granule)
        self.allocated: list[tuple[int, int, int]] = []

    def allocate(self, address: int, size: int, strategy: str = "sequential") -> int:
        tag = self._state.tag_allocation(address, size, strategy)
        self.allocated.append((address, size, tag))
        return tag

    def store(self, address: int, data: bytes, tag: int | None = None):
        self._state.store_with_tag(address, data, tag)

    def load(self, address: int, size: int, expected_tag: int | None = None) -> bytes:
        return self._state.load_with_tag(address, size, expected_tag)

    def check_use_after_free(self, address: int) -> bool:
        return self._state.detect_uaf(address)

    def check_double_free(self, address: int) -> bool:
        return self._state.detect_double_free(address)

    def free(self, address: int):
        self._state.free_allocation(address)

    def speculative_probe(self, address: int, predicted_tag: int) -> tuple[bool, int]:
        would_fault, resolved = self._state.check_speculative_tag_access(address)
        return would_fault, resolved

    def speculative_load(self, address: int, size: int, predicted_tag: int) -> tuple[bytes, bool]:
        return self._state.speculative_load(address, size, predicted_tag)

    def tag_at(self, address: int) -> int:
        return self._state.check_tag(address)

    # 导出状态快照，用于fuzzing和验证
    def snapshot(self) -> dict:
        return {
            "allocations": list(self._state._allocation_map.items()),
            "freed": list(self._state._freed_set),
            "tag_probe_history": list(self._state._tag_probe_history),
            "granule": self._state._granule,
        }
