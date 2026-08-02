# 2026-07-24
# Test case generation — random, boundary, grammar, mutation, templates
# 设计取舍：语法生成用递归展开 + 深度守卫防无限循环，而不是全生成→过滤
# （后者在复杂语法上会爆炸）。变异生成用位翻转 + 结构保留变异组合。
import random
import struct
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


@dataclass
class Grammar:
    rules: Dict[str, List[List[str]]] = field(default_factory=dict)
    start_symbol: str = "S"

    def add_rule(self, nonterminal: str, productions: List[List[str]]):
        self.rules.setdefault(nonterminal, []).extend(productions)


# ================================================
class TestGenerator:
    """多维测试用例生成器。
    支持：随机字节、边界值、语法驱动、变异（基于种子）、二进制模板。
    """

    def __init__(self, seed: int = None):
        self._rng = random.Random(seed)
        self._stat = {"generated": 0, "mutated": 0}

    # ---- Random byte generation ----
    def generate_random(self, count: int = 100,
                        size_range: Tuple[int, int] = (1, 4096)) -> List[bytes]:
        """生成随机字节流测试用例。"""
        _cases = []
        for _ in range(count):
            _sz = self._rng.randint(*size_range)
            _cases.append(bytes([self._rng.randint(0, 255) for _ in range(_sz)]))
        self._stat["generated"] += count
        return _cases

    # ---- Boundary value generation ----
    def generate_boundary(self, count: int = 50) -> List[bytes]:
        """生成边界值测试用例：0, 1, 0x7F, 0x80, 0xFE, 0xFF,
        零长度、单字节、大小端最大值、全 0 块、全 0xFF 块。
        """
        _cases = []

        # 单字节边界
        for _v in [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]:
            _cases.append(bytes([_v]))

        # 多字节边界
        for _sz in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]:
            _cases.append(b'\x00' * _sz)  # all zeros
            _cases.append(b'\xff' * _sz)  # all ones
            _cases.append(b'\x00' * (_sz - 1) + b'\x01')  # max-1
            _cases.append(b'\x00' * (_sz - 1) + b'\xff')  # only LSB set

        # 整数边界值 (signed/unsigned 转换)
        for _bits in [8, 16, 32, 64]:
            _max_u = (1 << _bits) - 1
            _max_s = (1 << (_bits - 1)) - 1
            _min_s = -(1 << (_bits - 1))
            _cases.append(_max_u.to_bytes(_bits // 8, 'big'))
            _cases.append(_max_s.to_bytes(_bits // 8, 'big', signed=True))
            _cases.append(_min_s.to_bytes(_bits // 8, 'big', signed=True))

        # 空输入、单字节
        _cases.append(b'')

        # 截断到 count
        _cases = _cases[:count]
        self._stat["generated"] += len(_cases)
        return _cases

    # ---- Grammar-based generation ----
    def generate_grammar(self, grammar: Grammar,
                         count: int = 50,
                         max_depth: int = 20) -> List[bytes]:
        """语法驱动生成 —— 从 start_symbol 递归展开。
        深度守卫：>max_depth 时直接 emit 终结符或当前最浅展开。
        """
        _cases = []
        for _ in range(count):
            _s = self._expand_grammar(grammar, grammar.start_symbol, max_depth)
            _cases.append(_s.encode(errors="replace"))
        self._stat["generated"] += count
        return _cases

    def _expand_grammar(self, grammar: Grammar, symbol: str,
                        depth: int = 0, max_depth: int = 20) -> str:
        """递归展开。超过深度限制时随机选择一个终端。"""
        if depth > max_depth:
            # Depth guard: emit a terminal
            _terminals = self._find_terminals(grammar, symbol, set())
            if _terminals:
                return self._rng.choice(_terminals)
            return symbol  # 无法展开，返回符号本身

        _prods = grammar.rules.get(symbol, [[symbol]])
        _chosen = self._rng.choice(_prods)
        _result = ""
        for _tok in _chosen:
            if _tok in grammar.rules:
                _result += self._expand_grammar(grammar, _tok, depth + 1, max_depth)
            else:
                _result += _tok
        return _result

    def _find_terminals(self, grammar: Grammar, symbol: str,
                        visited: Set[str]) -> List[str]:
        """从给定符号开始找到所有可到达的终结符。"""
        if symbol in visited:
            return []
        visited.add(symbol)
        _terms = []
        for _prod_list in grammar.rules.get(symbol, [[]]):
            for _tok in _prod_list:
                if _tok in grammar.rules:
                    _terms.extend(self._find_terminals(grammar, _tok, visited))
                elif _tok:
                    _terms.append(_tok)
        return _terms

    # ---- Mutation-based generation ----
    def generate_mutation(self, seed_data: bytes,
                          count: int = 50) -> List[bytes]:
        """基于种子的变异生成。操作：位翻转、字节翻转、字节插入/删除、
        块复制、块反转、算术增量。
        """
        _mutants = []
        _ops = [
            self._mutate_bit_flip,
            self._mutate_byte_flip,
            self._mutate_byte_insert,
            self._mutate_byte_delete,
            self._mutate_block_dup,
            self._mutate_block_reverse,
            self._mutate_arithmetic,
        ]
        for _ in range(count):
            _op = self._rng.choice(_ops)
            _m = _op(seed_data)
            if _m is not None:
                _mutants.append(_m)
        self._stat["mutated"] += len(_mutants)
        return _mutants

    def _mutate_bit_flip(self, data: bytes) -> Optional[bytes]:
        if not data:
            return None
        _pos = self._rng.randint(0, len(data) - 1)
        _bit = self._rng.randint(0, 7)
        _arr = bytearray(data)
        _arr[_pos] ^= (1 << _bit)
        return bytes(_arr)

    def _mutate_byte_flip(self, data: bytes) -> Optional[bytes]:
        if not data:
            return None
        _pos = self._rng.randint(0, len(data) - 1)
        _arr = bytearray(data)
        _arr[_pos] = self._rng.randint(0, 255)
        return bytes(_arr)

    def _mutate_byte_insert(self, data: bytes) -> bytes:
        _pos = self._rng.randint(0, len(data))
        _byte = self._rng.randint(0, 255)
        return data[:_pos] + bytes([_byte]) + data[_pos:]

    def _mutate_byte_delete(self, data: bytes) -> Optional[bytes]:
        if len(data) <= 1:
            return None
        _pos = self._rng.randint(0, len(data) - 1)
        return data[:_pos] + data[_pos + 1:]

    def _mutate_block_dup(self, data: bytes) -> Optional[bytes]:
        if len(data) < 2:
            return None
        _blk_sz = self._rng.randint(1, min(len(data), 64))
        _src = self._rng.randint(0, len(data) - _blk_sz)
        _block = data[_src:_src + _blk_sz]
        _dst = self._rng.randint(0, len(data))
        return data[:_dst] + _block + data[_dst:]

    def _mutate_block_reverse(self, data: bytes) -> Optional[bytes]:
        if len(data) < 2:
            return None
        _blk_sz = self._rng.randint(2, min(len(data), 64))
        _src = self._rng.randint(0, len(data) - _blk_sz)
        _rev = data[_src:_src + _blk_sz][::-1]
        return data[:_src] + _rev + data[_src + _blk_sz:]

    def _mutate_arithmetic(self, data: bytes) -> Optional[bytes]:
        if not data:
            return None
        _pos = self._rng.randint(0, len(data) - 1)
        _delta = self._rng.choice([-1, 1, -16, 16, -64, 64])
        _arr = bytearray(data)
        _arr[_pos] = (_arr[_pos] + _delta) & 0xFF
        return bytes(_arr)

    # ---- Binary template generation ----
    def generate_binary_template(self,
                                  template_desc: str) -> Optional[bytes]:
        """根据描述生成最小有效二进制文件。
        支持："ELF x86-64", "PE 32-bit", "Mach-O arm64"。
        """
        _t = template_desc.lower()
        if "elf" in _t and "x86-64" in _t:
            return self._gen_elf64()
        elif "pe" in _t and "32" in _t:
            return self._gen_pe32()
        elif "mach" in _t and "arm64" in _t:
            return self._gen_macho_arm64()
        return None

    def _gen_elf64(self) -> bytes:
        # Minimal ELF64: header (64B) + single null terminator
        _h = bytearray(64)
        _h[0:4] = b'\x7fELF'
        _h[4] = 2       # 64-bit
        _h[5] = 1       # little-endian
        _h[6] = 1       # ELF version
        _h[16:18] = (2).to_bytes(2, 'little')  # ET_EXEC
        _h[18:20] = (0x3E).to_bytes(2, 'little')  # x86-64
        _h[20:24] = (1).to_bytes(4, 'little')  # version
        _h[24:32] = (0x400000).to_bytes(8, 'little')  # entry
        _h[32:40] = (64).to_bytes(8, 'little')  # phoff
        _h[40:48] = (0).to_bytes(8, 'little')  # shoff
        _h[52:54] = (64).to_bytes(2, 'little')  # ehsize
        _h[54:56] = (56).to_bytes(2, 'little')  # phentsize
        _h[56:58] = (1).to_bytes(2, 'little')  # phnum
        _h[58:60] = (64).to_bytes(2, 'little')  # shentsize
        # Program header (PHDR): 56 bytes of PT_LOAD
        _ph = bytearray(56)
        _ph[0:4] = (1).to_bytes(4, 'little')  # PT_LOAD
        _ph[4:8] = (5).to_bytes(4, 'little')  # flags: read+exec
        _ph[8:16] = (0).to_bytes(8, 'little')  # offset
        _ph[32:40] = (0x1000).to_bytes(8, 'little')  # filesz
        _ph[40:48] = (0x1000).to_bytes(8, 'little')  # memsz
        return bytes(_h) + bytes(_ph)

    def _gen_pe32(self) -> bytes:
        # Minimal PE32: DOS header + PE signature + COFF header + optional header
        _dos = bytearray(64)
        _dos[0:2] = b'MZ'
        _dos[60:64] = (64).to_bytes(4, 'little')  # e_lfanew -> PE sig
        _pe = b'PE\x00\x00'
        _coff = bytearray(20)
        _coff[0:2] = (0x14C).to_bytes(2, 'little')  # x86
        _coff[2:4] = (1).to_bytes(2, 'little')      # 1 section
        _coff[16:18] = (224).to_bytes(2, 'little')   # optional header size
        _opt = bytearray(224)
        _opt[0:2] = (0x10B).to_bytes(2, 'little')   # PE32
        _opt[28:32] = (0x1000).to_bytes(4, 'little')  # image base
        _opt[48:52] = (0x1000).to_bytes(4, 'little')  # section alignment
        _opt[52:56] = (0x200).to_bytes(4, 'little')   # file alignment
        _opt[72:76] = (4).to_bytes(4, 'little')       # major subsystem
        _opt[76:80] = (0x100000).to_bytes(4, 'little')  # size of stack reserve
        return bytes(_dos) + _pe + bytes(_coff) + bytes(_opt)

    def _gen_macho_arm64(self) -> bytes:
        # Minimal Mach-O arm64: header + load command
        _h = bytearray(32)
        _h[0:4] = (12).to_bytes(4, 'little')  # MH_CPU_ARM64 = 12
        _h[4:8] = (0x0100000C).to_bytes(4, 'little')  # CPU_TYPE_ARM64
        _h[8:12] = (0).to_bytes(4, 'little')  # CPU_SUBTYPE_ARM64_ALL
        _h[12:16] = (2).to_bytes(4, 'little')  # MH_EXECUTE
        _h[16:20] = (1).to_bytes(4, 'little')  # 1 load command
        _h[20:24] = (56).to_bytes(4, 'little')  # sizeofcmds
        _h[24:28] = (7).to_bytes(4, 'little')   # flags
        _h[28:32] = (0).to_bytes(4, 'little')   # reserved
        return bytes(_h)
