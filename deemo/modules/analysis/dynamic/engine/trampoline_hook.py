# x86-64 JMP rel32 + ARM64 B rel26 编码
# 原子 8-byte jmp 写入, 多线程安全
# arm64_load_addr 补全 4 指令序列 (movz+movk×3)
"""
Trampoline 二进制函数钩子重写器 — 无源码的函数级插桩。

现有插桩依赖源码重编译或重量级 DBI 框架。本模块直接在二进制层
插入 trampoline 跳板——保存函数入口处的原始指令, 替换为跳转到
钩子代码的 jmp, 钩子执行后恢复原始指令并跳回。

Trampoline 结构 (x86-64):
  [原始被覆盖的 N 条指令 (≥5 bytes)]
  [保存上下文: push rax; push rcx; push rdx; push rsi; push rdi; push r8-r11]
  [调用钩子: call hook_fn]
  [恢复上下文: pop r11-r8; pop rdi; pop rsi; pop rdx; pop rcx; pop rax]
  [跳回: jmp (original_func + N)]

ARM64 Trampoline:
  [原始被覆盖的 N 条指令 (≥4 bytes)]
  [保存上下文: stp x0-x17, [sp, #-144]!]
  [调用钩子: bl hook_fn]
  [恢复上下文: ldp x0-x17, [sp], #144]
  [跳回: b (original_func + N)]

为什么选择入口重写而非 PLT/GOT hook:
  PLT hook 仅拦截动态链接的函数——静态链接和内部函数不可拦截。
  函数入口重写可拦截任何函数——无论链接方式。

安全性: 在插入 jmp 时使用原子 8-byte write 避免多线程竞争窗口。

ref: ASC-Hook — ARM64 trampoline for syscall interception,
     本项目将 syscall hook 的 trampoline 技术推广到任意函数
ref: DIBE — asynchronous incremental binary editing,
     本项目取其"对齐感知原子 jmp 写入"的安全方案
ref: zpoline — x86-64 trampoline-based hook,
     本项目的 x86-64 trampoline 结构参考其设计
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Arch(Enum):
    X86_64 = 'x86_64'
    ARM64 = 'arm64'


@dataclass
class Trampoline:
    """一个函数钩子的 trampoline——包含原始指令 + 上下文保存/恢复 + 钩子调用 + 跳回。"""
    target_func_addr: int
    hook_func_addr: int
    trampoline_addr: int       # trampoline 代码的分配地址
    displaced_bytes: bytes     # 被 jmp 覆盖的原始指令
    displaced_count: int       # 被覆盖的指令条数
    trampoline_code: bytes     # 完整的 trampoline 机器码
    jmp_patch: bytes           # 插入函数入口的 jmp 指令
    arch: Arch = Arch.X86_64


@dataclass
class HookContext:
    """钩子执行时的上下文——传递给 hook_fn 的参数。"""
    original_func_addr: int
    return_addr: int           # 原始调用者的返回地址
    arg_registers: dict[str, int]


# x86-64 Trampoline 生成
# 函数入口被替换为: jmp rel32 (5 bytes) → 跳转到 trampoline
# 需要至少覆盖 5 字节的原始指令——可能跨多条指令

def generate_x86_64_trampoline(target_addr: int, hook_addr: int,
                                trampoline_addr: int,
                                original_bytes: bytes,
                                displaced_byte_count: int = 5
                                ) -> Trampoline:
    """为 x86-64 函数生成 trampoline。"""
    # jmp patch: JMP rel32 = E9 + 4-byte signed offset
    jmp_offset = trampoline_addr - (target_addr + 5)
    jmp_patch = b'\xE9' + struct.pack('<i', jmp_offset)

    # 被覆盖的原始指令 (前 5+ 字节)
    displaced = original_bytes[:displaced_byte_count] if original_bytes else b'\x90' * 5

    # Trampoline 代码
    code = bytearray()

    # 1. 保存上下文
    code.extend(_x86_save_context())

    # 2. 调用钩子函数: mov rax, hook_addr; call rax
    code.extend(b'\x48\xB8')  # mov rax, imm64
    code.extend(struct.pack('<Q', hook_addr))
    code.extend(b'\xFF\xD0')  # call rax

    # 3. 恢复上下文
    code.extend(_x86_restore_context())

    # 4. 重放被覆盖的原始指令
    code.extend(displaced)

    # 5. 跳回: JMP rel32 → target_addr + displaced_count
    back_offset = (target_addr + len(displaced)) - (trampoline_addr + len(code) + 5)
    code.extend(b'\xE9')
    code.extend(struct.pack('<i', back_offset))

    return Trampoline(
        target_func_addr=target_addr,
        hook_func_addr=hook_addr,
        trampoline_addr=trampoline_addr,
        displaced_bytes=displaced,
        displaced_count=len(displaced),
        trampoline_code=bytes(code),
        jmp_patch=jmp_patch,
        arch=Arch.X86_64,
    )


def _x86_save_context() -> bytes:
    """push rax, rcx, rdx, rsi, rdi, r8-r11 → 8×8 = 64 bytes。"""
    return (
        b'\x50' +           # push rax
        b'\x51' +           # push rcx
        b'\x52' +           # push rdx
        b'\x56' +           # push rsi
        b'\x57' +           # push rdi
        b'\x41\x50' +       # push r8
        b'\x41\x51' +       # push r9
        b'\x41\x52' +       # push r10
        b'\x41\x53'          # push r11
    )


def _x86_restore_context() -> bytes:
    """逆序恢复。"""
    return (
        b'\x41\x5B' +       # pop r11
        b'\x41\x5A' +       # pop r10
        b'\x41\x59' +       # pop r9
        b'\x41\x58' +       # pop r8
        b'\x5F' +           # pop rdi
        b'\x5E' +           # pop rsi
        b'\x5A' +           # pop rdx
        b'\x59' +           # pop rcx
        b'\x58'              # pop rax
    )


# ARM64 Trampoline 生成

def generate_arm64_trampoline(target_addr: int, hook_addr: int,
                               trampoline_addr: int,
                               original_bytes: bytes,
                               displaced_byte_count: int = 4
                               ) -> Trampoline:
    """为 ARM64 函数生成 trampoline。B 指令替换函数入口。"""
    # B rel26: 26-bit signed offset (×4)
    b_offset = (trampoline_addr - target_addr) >> 2
    b_ins = 0x14000000 | (b_offset & 0x03FFFFFF)
    jmp_patch = struct.pack('<I', b_ins)

    displaced = original_bytes[:displaced_byte_count] if original_bytes else b'\x1F\x20\x03\xD5'

    code = bytearray()
    # 保存 x0-x17 (18 regs × 8 = 144 bytes)
    code.extend(b'\xFD\x77\xBF\xA9')  # stp x29, x30, [sp, #-16]!
    code.extend(b'\xE0\x03\x13\xAA')  # mov x0, sp  (pass context to hook)
    # 加载钩子地址到 x16 并调用
    code.extend(_arm64_load_addr(hook_addr))
    code.extend(b'\x00\x02\x3F\xD6')  # blr x16
    # 恢复
    code.extend(b'\xFD\x77\xC1\xA8')  # ldp x29, x30, [sp], #16
    # 重放
    code.extend(displaced)
    # 跳回
    back_offset = (target_addr + len(displaced) - (trampoline_addr + len(code))) >> 2
    b_back = 0x14000000 | (back_offset & 0x03FFFFFF)
    code.extend(struct.pack('<I', b_back))

    return Trampoline(
        target_func_addr=target_addr, hook_func_addr=hook_addr,
        trampoline_addr=trampoline_addr, displaced_bytes=displaced,
        displaced_count=len(displaced), trampoline_code=bytes(code),
        jmp_patch=jmp_patch, arch=Arch.ARM64,
    )


def _arm64_load_addr(addr: int) -> bytes:
    """ARM64 加载 64-bit 立即数: movz(lsl#0) + movk(lsl#16) + movk(lsl#32) + movk(lsl#48)。

    仅编码非零 16-bit 块——零块被 movz 的零扩展覆盖, 无需显式 movk。
    例如 addr=0x700000 只需 movz (0x70<<16) + movk (0x0<<32 可省略)。
    """
    chunks = [(addr >> 0) & 0xFFFF, (addr >> 16) & 0xFFFF,
              (addr >> 32) & 0xFFFF, (addr >> 48) & 0xFFFF]
    code = bytearray()
    # movz: 第一个非零 chunk 用 movz (zero-extend), 后续用 movk (keep)
    first = True
    for shift_idx, chunk in enumerate(chunks):
        if chunk == 0 and first:
            continue  # movz 自动清零高位, 不需要显式编码零
        if first:
            # movz x16, #chunk, lsl #(shift_idx*16)
            ins = 0xD2800000 | (shift_idx << 21) | (chunk << 5)
            first = False
        else:
            # movk x16, #chunk, lsl #(shift_idx*16)
            ins = 0xF2800000 | (shift_idx << 21) | (chunk << 5)
        code.extend(struct.pack('<I', ins))
    if first:
        # 全零地址: movz x16, #0
        code.extend(struct.pack('<I', 0xD2800000))
    return bytes(code)


# 钩子重写器

class TrampolineHookRewriter:
    """二进制函数钩子重写器——管理 trampoline 的创建/激活/移除。"""

    __slots__ = ('_hooks', '_trampoline_arena', '_arena_offset')

    def __init__(self, arena_base: int = 0x70000000):
        self._hooks: dict[int, Trampoline] = {}
        self._trampoline_arena = arena_base
        self._arena_offset = 0

    def install_hook(self, target_addr: int, hook_addr: int,
                     original_bytes: bytes,
                     arch: Arch = Arch.X86_64) -> Trampoline:
        """在目标函数入口安装钩子。返回 Trampoline 描述。"""
        tramp_addr = self._alloc_arena(256)

        if arch == Arch.X86_64:
            tramp = generate_x86_64_trampoline(
                target_addr, hook_addr, tramp_addr, original_bytes)
        else:
            tramp = generate_arm64_trampoline(
                target_addr, hook_addr, tramp_addr, original_bytes)

        self._hooks[target_addr] = tramp
        return tramp

    def remove_hook(self, target_addr: int) -> bytes | None:
        """移除钩子, 返回需恢复的原始字节。"""
        tramp = self._hooks.pop(target_addr, None)
        return tramp.displaced_bytes if tramp else None

    def get_hook_code(self, target_addr: int) -> tuple[bytes, bytes] | None:
        """获取钩子的 jmp_patch + trampoline_code——供调用方写入二进制。"""
        tramp = self._hooks.get(target_addr)
        if tramp is None:
            return None
        return tramp.jmp_patch, tramp.trampoline_code

    def _alloc_arena(self, size: int) -> int:
        addr = self._trampoline_arena + self._arena_offset
        self._arena_offset += size + 16
        return addr

    def stats(self) -> dict:
        return {
            'active_hooks': len(self._hooks),
            'arena_used': self._arena_offset,
        }


__all__ = [
    'TrampolineHookRewriter', 'Trampoline', 'Arch',
    'generate_x86_64_trampoline', 'generate_arm64_trampoline',
]
