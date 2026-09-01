# 间接调用定位 + 函数类型恢复 + landing pad 插入

from dataclasses import dataclass, field
import struct
from collections import defaultdict
from typing import Optional


@dataclass
class IndirectCallSite:
    """一处间接调用 - 需要 CFI 保护的位置。"""
    pc: int
    target_reg: str = ''       # 间接跳转的目标寄存器
    is_tail_call: bool = False
    inferred_arg_count: int = 0
    landing_pad_bytes: bytes = b''
    original_bytes: bytes = b''


@dataclass
class FunctionSignature:
    """从二进制推断出的函数签名。"""
    func_addr: int
    arg_count: int = 0
    return_type_hint: str = 'void'  # 'void' | 'int' | 'ptr' | 'float'
    calling_convention: str = 'cdecl'
    type_id: int = 0               # 16-bit 类型标识
    confidence: float = 0.0


def locate_indirect_calls(instructions: list[dict]) -> list[IndirectCallSite]:
    """定位所有间接调用/跳转指令。"""
    sites = []
    for ins in instructions:
        mnemonic = ins.get('mnemonic', '').lower()
        ops = str(ins.get('operands', ''))
        if mnemonic != 'call' and not mnemonic.startswith('jmp'):
            continue
        # 间接: call reg / call [reg+off] / jmp reg
        if '[' in ops or any(r in ops.lower() for r in
            ('rax', 'eax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11')):
            # 提取目标寄存器名
            reg = ''
            for r in ('rax', 'eax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'):
                if r in ops.lower():
                    reg = r
                    break
            sites.append(IndirectCallSite(
                pc=ins.get('address', 0),
                target_reg=reg,
                is_tail_call=mnemonic.startswith('jmp'),
            ))
    return sites


def infer_function_signatures(functions: dict[int, list[dict]]) -> dict[int, FunctionSignature]:
    """从函数体指令推断函数签名 - arg count + return type。"""
    sigs = {}
    for func_addr, ins_list in functions.items():
        # 参数计数: 统计函数入口处的寄存器读取 (rdi/rsi/rdx/rcx/r8/r9)
        arg_regs_seen = set()
        for ins in ins_list[:20]:
            ops = str(ins.get('operands', '')).lower()
            for arg_reg in ('rdi', 'rsi', 'rdx', 'rcx', 'r8d', 'r9d'):
                if arg_reg in ops:
                    arg_regs_seen.add(arg_reg)

        # 返回类型: ret 之前的 rax/rax 使用模式
        ret_type = 'void'
        for ins in reversed(ins_list[-10:]):
            ops = str(ins.get('operands', '')).lower()
            if 'rax' in ops or 'eax' in ops:
                ret_type = 'int'
            if 'xmm0' in ops or 'st(0)' in ops.lower():
                ret_type = 'float'

        # 编码 type_id
        arg_count = len(arg_regs_seen)
        type_id = (arg_count & 0xFF)
        if ret_type == 'int':
            type_id |= (1 << 8)
        elif ret_type == 'ptr':
            type_id |= (2 << 8)
        elif ret_type == 'float':
            type_id |= (3 << 8)

        sigs[func_addr] = FunctionSignature(
            func_addr=func_addr,
            arg_count=arg_count,
            return_type_hint=ret_type,
            type_id=type_id,
            confidence=min(1.0, arg_count / 6.0),
        )
    return sigs


def generate_cfi_landing_pad(type_id: int, arch: str = 'x86_64') -> bytes:
    # x86-64: NOP 序列中嵌入 type_id → 5 bytes total
    # ARM64: MOVK x16, #type_id → 4 bytes
    # 生产环境建议使用 Intel CET endbr64 或 ARM BTI 指令
    if arch == 'x86_64':
        # 前缀: 0F 1F 00 (3-byte NOP) + 2-byte type_id
        return struct.pack('<B B B H', 0x0F, 0x1F, 0x00, type_id & 0xFFFF)
    else:
        # ARM64: mov w16, #type_id (简化)
        return struct.pack('<I', 0x52800010 | ((type_id & 0xFFFF) << 5))


def generate_cfi_check(call_site: IndirectCallSite,
                       target_type_id: int = 0) -> bytes:
    # x86-64: 在 call 前插入 cmp [target_func+3], type_id; jne abort
    # 注: 前 3 字节是 landing pad 的 NOP 指令, type_id 在偏移 +3 处
    if not call_site.target_reg:
        return b''
    # 简化为伪代码——完整实现需要处理寄存器保存/恢复
    # cmp word [target_reg + 3], type_id
    # jne cfi_violation_handler
    return struct.pack('<6B H 6B',
        0x66, 0x41, 0x81, 0x78, 0x03, target_type_id & 0xFFFF,
        0x0F, 0x85, 0x00, 0x00, 0x00, 0x00)  # JNE rel32 (需回填)


class ForwardEdgeCFI:
    """剥离二进制的前向边 CFI 插桩器。"""

    __slots__ = ('_sigs', '_call_sites', '_arch')

    def __init__(self, arch: str = 'x86_64'):
        self._sigs: dict[int, FunctionSignature] = {}
        self._call_sites: list[IndirectCallSite] = []
        self._arch = arch

    def analyze(self, instructions: list[dict],
                functions: dict[int, list[dict]]) -> None:
        self._call_sites = locate_indirect_calls(instructions)
        self._sigs = infer_function_signatures(functions)

    def instrument(self) -> dict[int, bytes]:
        """生成每个函数的 landing pad 插桩代码。返回 {func_addr: landing_pad_bytes}。"""
        pads = {}
        for addr, sig in self._sigs.items():
            pads[addr] = generate_cfi_landing_pad(sig.type_id, self._arch)
        return pads

    def type_check_hit_rate(self) -> float:
        """可类型检查的间接调用比例。"""
        if not self._call_sites:
            return 0.0
        checkable = 0
        for site in self._call_sites:
            if site.inferred_arg_count > 0:
                checkable += 1
        return checkable / len(self._call_sites)

    def stats(self) -> dict:
        return {
            'call_sites': len(self._call_sites),
            'function_signatures': len(self._sigs),
            'type_checkable_ratio': round(self.type_check_hit_rate(), 3),
        }


__all__ = ['ForwardEdgeCFI', 'IndirectCallSite', 'FunctionSignature',
           'locate_indirect_calls', 'infer_function_signatures',
           'generate_cfi_landing_pad']
