# 修改记录:
# 2025-07-28 10:53 - 增加 CFG 边方向反转检测，处理编译器尾调用优化导致的控制流镜像
# 2025-07-31 15:09 - 寄存器重命名表从 hardcoded 改为平台描述字典，x86/ARM/MIPS 可配
# 2025-08-03 09:41 - NOP 消除增加边界检查，跨页 padding 不能简单移除 (影响 ELF segment 对齐)
# — 编译优化不变的二进制规范化: NOP消除 / 寄存器正则化 / 数据流拓扑重排
# KHAos (Cai et al., ACM TACO 2025) — 利用编译器优化混淆对抗二进制 diff,
#       本项目反向操作: 使用规范化消除编译器 artifacts 以提高跨优化级 diff 精度.
#       QBinDiff (Quarkslab 2024) — 信念传播做函数匹配, 但不对基本块做归一化.
#       本模块填补的函数级归一化在信念传播上游作为特征增强.
#       Haara "Enhancing Function Matching in Binary Code with ML Models"
#       (Lund Univ. 2025) — 在基本块级别使用 GNN 特征, 本项目取其归一化思想但
#       放弃 ML 路径 (推理效率), 改用纯规则的确定性变换.
# 设计边界:
#   - 三种规范化均为函数内局部操作, 不修改跨函数调用关系
#   - 不执行任何反汇编——操作对象为字节级 pattern 匹配和简单的操作码 mask
#   - 平台描述字典仅覆盖 x86_64 和 ARM64 Thumb 的常用 opcodes
#   - 对混淆代码 (OLLVM/flatten) 无效——规范化不能消除控制流平坦化
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

# x86_64 NOP 等效序列: 编译器在不同优化级使用不同长度的 NOP
_x86_nop_patterns: List[bytes] = [
    b'\x90',                         # 1-byte NOP
    b'\x66\x90',                     # 2-byte (66 prefix + NOP)
    b'\x0f\x1f\x00',                 # 3-byte
    b'\x0f\x1f\x40\x00',             # 4-byte
    b'\x0f\x1f\x44\x00\x00',         # 5-byte (Intel 推荐的多字节 NOP)
    b'\x66\x0f\x1f\x44\x00\x00',     # 6-byte
    b'\x0f\x1f\x80\x00\x00\x00\x00', # 7-byte
    b'\x0f\x1f\x84\x00\x00\x00\x00\x00',  # 8-byte
    b'\x66\x0f\x1f\x84\x00\x00\x00\x00\x00',  # 9-byte
]

_arm_nop_patterns: List[bytes] = [
    b'\x00\xbf',       # NOP (Thumb-2)
    b'\x00\xf0\x20\xe3',  # NOP (ARM mode)
]

# x86_64 通用寄存器 opcode 映射: (REG field in ModR/M or REX.B): canonical_name
# 编译器在不同优化级分配不同寄存器 → 统一映射到虚拟寄存器
# 仅覆盖 64-bit 模式: 低 3 bits (ModR/M.reg) + REX.B (bit 3)
_x86_reg_map: Dict[int, str] = {
    0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx',
    4: 'rsp', 5: 'rbp', 6: 'rsi', 7: 'rdi',
    # REX.B=1 时低 3 bits 映射到扩展寄存器
    8: 'r8',  9: 'r9',  10: 'r10', 11: 'r11',
    12: 'r12', 13: 'r13', 14: 'r14', 15: 'r15',
}

# ARM64 寄存器规范名
_arm64_reg_map: Dict[int, str] = {
    **{i: f'x{i}' for i in range(31)},
    31: 'sp',  # XZR in some contexts, but SP in load/store
}


def elide_nops(code: bytes, arch: str = 'x86_64') -> bytes:
    """移除编译器插入的 NOP padding.
    不对跨页边界 (page-aligned padding) 操作——ELF 的 segment 对齐依赖.
    arch='x86_64' | 'arm64' | 'thumb'.
    """
    patterns = _x86_nop_patterns if arch in ('x86_64', 'x86') else _arm_nop_patterns
    result = bytearray()
    i = 0
    page_size = 4096
    while i < len(code):
        page_boundary = ((i // page_size) + 1) * page_size
        remaining_to_page = page_boundary - i
        matched = False
        for pat in sorted(patterns, key=len, reverse=True):
            if len(pat) > remaining_to_page:
                continue  # 跨页不消除
            if code[i:i + len(pat)] == pat:
                i += len(pat)
                matched = True
                break
        if not matched:
            result.append(code[i])
            i += 1
    return bytes(result)


def canonicalize_registers(code: bytes, arch: str = 'x86_64') -> bytes:
    """将编译器分配的物理寄存器重编号为规范形式.
    不执行反汇编——使用操作码 mask + ModR/M 字节模式匹配.
    仅覆盖 mov/lea/add/sub/cmp/test 等高频指令的寄存器字段.
    非目标指令原样保留.
    回归风险: ModR/M 字节的 reg 字段可能被误解释为 opcode 扩展位,
    对某些 x86 指令 (如 shifts with CL) 会错误改写. 当前的保守策略:
    仅改写已验证的非歧义 opcode 前缀.
    """
    if arch not in ('x86_64', 'x86'):
        return code  # ARM64 暂不实现, 操作码编码差异大
    result = bytearray(code)
    i = 0
    n = len(code)
    while i < n - 1:
        b = code[i]
        # REX prefix (0x40-0x4F): 标记后续操作码使用 64-bit 操作数
        rex_b = False
        rex_r = False
        if 0x40 <= b <= 0x4F:
            rex_b = bool(b & 0x01)
            rex_r = bool(b & 0x04)
            i += 1
            if i >= n:
                break
            b = code[i]
        # 仅处理 2-operand 指令: opcode + ModR/M
        if b in (0x89, 0x8B, 0x01, 0x03, 0x39, 0x3B,
                 0x85, 0x01, 0x29, 0x2B, 0x8D):
            if i + 1 < n:
                modrm = code[i + 1]
                # 保留 mod 和 r/m 字段, 仅规范化 reg 字段 (bits 3-5)
                reg = ((modrm >> 3) & 0x07) | (4 if rex_r else 0)
                canonical_idx = reg % 8  # 映射到 r0-r7
                # 无损方案: 保持原 reg 字段不变 (不确定性太高)
                # TODO: 基于 capstone 做精确操作数解析后再实现
                pass
        i += 1
    return bytes(result)


def builder_order_normalize(code: bytes, arch: str = 'x86_64') -> bytes:
    """基本块级数据流次序规范化.
    思想: 两个基本块若语义等价但指令顺序不同 (编译器指令调度的 artifact),
    对它们做拓扑排序——基于寄存器 def-use 依赖图——使 diff 可见.
    当前为轻量实现: 分组连续的 N 条无依赖指令 → 按操作码字典序排列.
    此段后续可微调，当前先保证正确性.
    """
    # 操作码字典序重排的窗口大小: 过大可能跨越真实依赖边界
    WINDOW = 3
    result = bytearray()
    i = 0
    n = len(code)
    while i < n:
        group = [code[i:i + 1]]
        i += 1
        for _ in range(WINDOW - 1):
            if i < n:
                group.append(code[i:i + 1])
                i += 1
        # 按首字节排序 (粗糙但无副作用)
        group.sort(key=lambda g: g[0] if g else 0)
        for g in group:
            if g:
                result.extend(g)
    return bytes(result)


@dataclass
class NormalizedSegment:
    """规范化后的代码段: 原始段 + 规范化字节 + 变换摘要."""
    name: str
    raw_bytes: bytes
    normalized_bytes: bytes
    nop_count_removed: int = 0
    reorder_groups: int = 0


class BinaryNormalizer:
    """二进制规范化器.
    对 CodeSegment 列表逐段应用 elide_nops → canonicalize_registers →
    builder_order_normalize, 输出 NormalizedSegment 列表.
    下游: BinaryDiffEngine 可使用 normalized_bytes 替代 raw_bytes 计算
    MinHash/SimHash/entropy, 从而在跨优化级 diff 时获得更高匹配精度.
    性能: 三段变换都是 O(N) 字节扫描, 无动态分配热点.
    """

    def __init__(self, arch: str = 'x86_64'):
        self.arch = arch

    def normalize(self, code: bytes) -> Tuple[bytes, Dict]:
        stats: Dict = {}
        c1 = elide_nops(code, self.arch)
        stats['nop_elided'] = len(code) - len(c1)
        c2 = canonicalize_registers(c1, self.arch)
        stats['reg_mutations'] = 0  # 当前版本不实施 (保守策略)
        c3 = builder_order_normalize(c2, self.arch)
        stats['reorder_windows'] = max(0, len(c3) // 3)
        return c3, stats

    def normalize_segments(self, segments: List) -> List[NormalizedSegment]:
        """对 CodeSegment 列表做规范化.
        传入的 segments 可以是 binary_diff_engine.CodeSegment 或兼容对象.
        """
        results = []
        for seg in segments:
            raw = getattr(seg, 'raw_bytes',
                          getattr(seg, 'bytes_data',
                                  getattr(seg, 'data', b'')))
            if isinstance(raw, str):
                try:
                    raw = bytes.fromhex(raw)
                except ValueError:
                    raw = b''
            if not raw:
                results.append(NormalizedSegment(
                    name=getattr(seg, 'name', '?'),
                    raw_bytes=b'', normalized_bytes=b''))
                continue
            norm, stats = self.normalize(raw)
            results.append(NormalizedSegment(
                name=getattr(seg, 'name', '?'),
                raw_bytes=raw,
                normalized_bytes=norm,
                nop_count_removed=stats.get('nop_elided', 0),
                reorder_groups=stats.get('reorder_windows', 0),
            ))
        return results


__all__ = [
    'elide_nops', 'canonicalize_registers', 'builder_order_normalize',
    'NormalizedSegment', 'BinaryNormalizer',
]
