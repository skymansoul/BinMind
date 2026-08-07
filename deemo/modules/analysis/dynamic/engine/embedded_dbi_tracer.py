# 创建: 2026-04-30 14:50
# 修改: 2026-04-30 — RISC-V/ARMv6M 8-byte 压缩追踪桩 + 环形 buffer
"""
嵌入式目标 DBI 追踪适配器 — RISC-V/ARM Cortex-M 的轻量动态插桩。

现有 DBI 框架 (Pin/DynamoRIO) 需要 GB 级内存和完整 OS——无法在
64KB SRAM 的 Cortex-M0 或 RISC-V RV32IMC 上运行。本模块提供
无运行时 DBI 的替代方案: 离线 IR 重写 + 嵌入式 trace buffer。

方案:
  1. 离线阶段: 在 Ghidra/Radare2 IR 层插入追踪桩代码 (tracepoint)
  2. 最小桩: 每条桩代码 ≤ 8 字节 (单条跳转 + 单条 store)
  3. 环形 trace buffer: 预分配的固定大小缓冲区, 通过 MMIO 或 SWO 输出
  4. ISA 适配: RISC-V (c.jal + c.sw) / ARMv6M (bl + str) 的压缩指令变体

为什么选择离线重写而非在线 JIT:
  嵌入式目标的代码通常在 Flash 中——不可运行时修改。
  离线重写生成插桩后的固件镜像, 烧录到硬件或加载到模拟器。

RISC-V 压缩指令的优势:
  RVC (Compressed) 扩展将 32-bit 指令压缩为 16-bit——
  追踪桩占用减少 50%, 对 I-cache 压力更小。
  ARMv6M 的 Thumb 模式也有类似效果。

ref: R-Visor — extensible DBI for RISC-V open ISAs,
     本项目取其 ISA 适配思想但针对无 OS 嵌入式场景改用离线重写
ref: Intel PT + DBI hybrid — hardware trace
     + software instrumentation, 本项目取其 trace buffer 压缩编码
ref: HALF — process hollowing 低开销 DBI, 本项目借鉴其
     "最小化 host process 足迹"思路, 适配到 MCU 级别
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ISAFamily(Enum):
    RISCV32 = 'riscv32'
    RISCV64 = 'riscv64'
    ARMV6M = 'armv6m'     # Cortex-M0/M0+
    ARMV7M = 'armv7m'     # Cortex-M3/M4/M7
    ARMV8M = 'armv8m'     # Cortex-M33


@dataclass
class Tracepoint:
    """单个追踪桩——插入到基本块入口的轻量代码。"""
    original_pc: int
    inserted_pc: int       # 桩代码的新位置
    encoded_bytes: bytes   # 桩代码的机器码 (≤8 bytes)
    bb_id: int             # 基本块 ID (用于压缩 trace)
    isa: ISAFamily


@dataclass
class TraceBuffer:
    """环形 trace buffer——嵌入式目标的追踪输出。"""
    data: bytearray
    head: int = 0
    capacity: int = 4096

    def push_bb(self, bb_id: int) -> bool:
        """推入基本块 ID——2 字节压缩编码。"""
        if self.head + 2 > self.capacity:
            self.head = 0  # 环形回绕
        struct.pack_into('<H', self.data, self.head, bb_id & 0xFFFF)
        self.head += 2
        return True

    def push_edge(self, from_bb: int, to_bb: int) -> bool:
        """推入边转换——4 字节编码。"""
        if self.head + 4 > self.capacity:
            self.head = 0
        struct.pack_into('<HH', self.data, self.head,
                         from_bb & 0xFFFF, to_bb & 0xFFFF)
        self.head += 4
        return True

    def read_all(self) -> bytes:
        return bytes(self.data[:self.head])

    def reset(self) -> None:
        self.head = 0


# ISA 指令编码器
# 为每种目标 ISA 生成追踪桩的机器码。
# 桩代码结构: [保存上下文] → [写入 BB ID 到 trace buffer] → [恢复上下文] → [跳回]

def encode_tracepoint_riscv32(bb_id: int, trace_buf_addr: int,
                               return_addr: int) -> bytes:
    """RISC-V RV32IMC 追踪桩编码——使用压缩指令最小化体积。

    桩代码 (8 字节, 4 条 c.指令):
      c.sw  a0, 0(tp)        # 保存 a0 (2B)
      c.li  a0, bb_id         # 加载 BB ID (2B)
      c.sw  a0, 0(trace_buf)  # 写入 trace buffer (2B)
      c.j   return_addr        # 跳回 (2B)
    总计: 8 字节——符合约束。"""
    # 简化: 返回桩代码的 hex 表示, 实际编码需完整 RISC-V 指令集
    return struct.pack('<HHHH',
        0xC2A,                           # c.swsp a0, 0(sp)
        (0x4501 | ((bb_id & 0x3F) << 2)), # c.li a0, bb_id
        0xC208,                           # c.sw a0, 0(tp)
        0xA001,                           # c.j 0 (相对偏移)
    )


def encode_tracepoint_armv6m(bb_id: int, trace_buf_addr: int,
                              return_addr: int) -> bytes:
    """ARMv6M (Cortex-M0) Thumb 追踪桩编码。

    桩代码 (8 字节):
      push {r0, lr}           # 保存上下文 (2B, 16-bit Thumb)
      movs r0, #bb_id         # 加载 BB ID (2B)
      str  r0, [r7, #offset]  # 写入 trace buffer (2B)
      pop  {r0, pc}           # 恢复 + 返回 (2B)
    总计: 8 字节——符合约束。"""
    return struct.pack('<HHHH',
        0xB500,                          # push {r0, lr}
        (0x2000 | (bb_id & 0xFF)),       # movs r0, #bb_id
        0x6038,                          # str r0, [r7, #0]
        0xBD01,                          # pop {r0, pc}
    )


# 离线重写引擎

class EmbeddedDBIRewriter:
    """嵌入式固件的离线 DBI 重写器。

    在 Ghidra/Radare2 的输出 IR 层插入追踪桩, 生成可烧录的
    插桩固件镜像。目标 ISA 决定桩代码的编码方式。"""

    __slots__ = ('_target_isa', '_tracepoints', '_trace_buf',
                 '_bb_counter')

    def __init__(self, isa: ISAFamily = ISAFamily.ARMV7M,
                 trace_buf_size: int = 4096):
        self._target_isa = isa
        self._tracepoints: list[Tracepoint] = []
        self._trace_buf = TraceBuffer(
            data=bytearray(trace_buf_size), capacity=trace_buf_size)
        self._bb_counter = 0

    def instrument_basic_block(self, original_pc: int,
                                original_bytes: bytes,
                                bb_id: int | None = None) -> Tracepoint:
        """为一个基本块生成追踪桩。返回 Tracepoint 描述。"""
        if bb_id is None:
            bb_id = self._bb_counter
            self._bb_counter += 1

        if self._target_isa in (ISAFamily.RISCV32, ISAFamily.RISCV64):
            encoded = encode_tracepoint_riscv32(bb_id, 0, original_pc)
        else:
            encoded = encode_tracepoint_armv6m(bb_id, 0, original_pc)

        tp = Tracepoint(
            original_pc=original_pc,
            inserted_pc=0,  # 由重写器分配
            encoded_bytes=encoded,
            bb_id=bb_id,
            isa=self._target_isa,
        )
        self._tracepoints.append(tp)
        return tp

    def rewrite_binary(self, original_bytes: bytearray,
                       bb_locations: list[tuple[int, int, int]],
                       ) -> tuple[bytearray, list[Tracepoint]]:
        """重写二进制: 在每个基本块入口插入桩代码。

        bb_locations: [(original_pc, size, new_pc), ...]——基本块在
        原始二进制中的位置, 以及重写后分配的地址。"""
        rewritten = bytearray(original_bytes)
        self._tracepoints = []

        for orig_pc, size, new_pc in bb_locations:
            tp = self.instrument_basic_block(orig_pc, bytes(original_bytes[orig_pc:orig_pc+size]))
            tp.inserted_pc = new_pc
            # 在原始块之前插入桩代码 (实际需处理重定位——此处简化)
            # 生产实现需要完整 binary rewriting pipeline

        return rewritten, self._tracepoints

    def tracepoints(self) -> list[Tracepoint]:
        return self._tracepoints

    def stats(self) -> dict:
        sizes = [len(tp.encoded_bytes) for tp in self._tracepoints]
        return {
            'target_isa': self._target_isa.value,
            'tracepoints': len(self._tracepoints),
            'total_stub_bytes': sum(sizes),
            'avg_stub_bytes': sum(sizes) / max(1, len(sizes)),
        }


# Trace 解码器
# 从嵌入式设备的 trace buffer 输出中解码执行路径。

class TraceDecoder:
    """解码环形 trace buffer 的原始输出——恢复 BB 序列。"""

    @staticmethod
    def decode(raw_trace: bytes) -> list[int]:
        """将原始 trace bytes 解码为 BB ID 序列。"""
        bb_ids = []
        for i in range(0, len(raw_trace) - 1, 2):
            bb_id = struct.unpack_from('<H', raw_trace, i)[0]
            bb_ids.append(bb_id)
        return bb_ids

    @staticmethod
    def coverage_from_trace(raw_trace: bytes) -> set[int]:
        """从 trace 中提取覆盖的 BB ID 集合——用于覆盖率报告。"""
        return set(TraceDecoder.decode(raw_trace))


__all__ = [
    'EmbeddedDBIRewriter', 'Tracepoint', 'TraceBuffer',
    'TraceDecoder', 'ISAFamily',
    'encode_tracepoint_riscv32', 'encode_tracepoint_armv6m',
]
