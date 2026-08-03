# 2026-07-21
# 污点追踪引擎 — 静态指令级数据流分析，标记敏感输入→危险sink的传播路径
# 设计思路：模拟x86_64常见指令的污点传播语义，维护寄存器/内存污点标签映射
# 权衡：不做符号执行和路径分支；XOR清零识别用于消减假阳性；sanitizer检测补充完整性检查

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Tuple
import re


class TaintSource(Enum):
    STDIN = auto()
    FILE_READ = auto()
    NETWORK_RECV = auto()
    ARGV = auto()
    ENVIRON = auto()
    MEMORY_MAP = auto()

class TaintSink(Enum):
    SYSTEM = auto()
    EXECVE = auto()
    MEMCPY_DST = auto()
    STRCPY_DST = auto()
    SPRINTF_DST = auto()
    WRITE = auto()

# ---- 敏感函数名映射到sink类型 ----
_SINK_MAP = {
    'system': TaintSink.SYSTEM,
    'execve': TaintSink.EXECVE,
    'execvp': TaintSink.EXECVE,
    'execl': TaintSink.EXECVE,
    'memcpy': TaintSink.MEMCPY_DST,
    'memmove': TaintSink.MEMCPY_DST,
    'strcpy': TaintSink.STRCPY_DST,
    'strncpy': TaintSink.STRCPY_DST,
    'sprintf': TaintSink.SPRINTF_DST,
    'snprintf': TaintSink.SPRINTF_DST,
    'write': TaintSink.WRITE,
    'send': TaintSink.WRITE,
}


@dataclass
class TaintPolicy:
    track_registers: bool = True
    track_memory: bool = True
    track_flags: bool = False
    sanitizer_detection: bool = True
    xor_clearing: bool = True


class TaintPropagator:
    """指令级污点传播模拟 — 不依赖动态trace，纯静态推演"""

    def __init__(self, policy: Optional[TaintPolicy] = None):
        self._policy = policy or TaintPolicy()
        self._reg_taint: Dict[str, Set[TaintSource]] = {}
        self._mem_taint: Dict[int, Set[TaintSource]] = {}
        self._sanitizers: List[Tuple[int, str]] = []
        # 模拟栈指针 — 从某个初始SP开始递减
        self._rsp = 0x7ffffffde00
        # 污点传播统计
        self._propagate_count = 0
        self._sink_hits = 0

    # ===== 污点标记 =====
    def mark_source(self, reg_or_addr: str, source: TaintSource):
        """在寄存器或内存地址上设置污点源"""
        if reg_or_addr.startswith('0x') or reg_or_addr.startswith('$'):
            try:
                _a = int(reg_or_addr.lstrip('$'), 0)
                self._mem_taint.setdefault(_a, set()).add(source)
            except ValueError:
                pass
        else:
            self._reg_taint.setdefault(reg_or_addr, set()).add(source)

    # //// 主传播引擎 ////
    def propagate(self, instruction: str):
        """解析单条指令并传播污点"""
        self._propagate_count += 1
        _opc, _dst, _srcs = self._parse_operands(instruction)
        if _opc is None:
            return

        # XOR清零检测
        if self._policy.xor_clearing and self._is_xor_clear(instruction):
            if _dst and _dst in self._reg_taint:
                del self._reg_taint[_dst]
            return

        _dst_taint: Set[TaintSource] = set()

        # ---- MOV / MOVZX / MOVSX ----
        if _opc in ('mov', 'movzx', 'movsx', 'movsxd'):
            for _s in _srcs:
                if _s in self._reg_taint:
                    _dst_taint |= self._reg_taint[_s]
                _sa = self._resolve_addr(_s)
                if _sa is not None and _sa in self._mem_taint:
                    _dst_taint |= self._mem_taint[_sa]

        # ---- 算术/逻辑: ADD, SUB,, OR, XOR(dst!=src), SHL, SHR ----
        elif _opc in ('add', 'sub', 'and', 'or', 'xor', 'shl', 'shr', 'sar',
                      'imul', 'mul', 'div', 'idiv', 'neg', 'not', 'inc', 'dec'):
            if _dst and _dst in self._reg_taint:
                _dst_taint |= self._reg_taint[_dst]
            for _s in _srcs:
                if _s in self._reg_taint:
                    _dst_taint |= self._reg_taint[_s]
                _sa = self._resolve_addr(_s)
                if _sa is not None and _sa in self._mem_taint:
                    _dst_taint |= self._mem_taint[_sa]

        # ---- PUSH: 寄存器→栈 ----
        elif _opc == 'push':
            for _s in _srcs:
                if _s in self._reg_taint:
                    _stack_a = self._rsp - self._get_op_size(instruction)
                    self._mem_taint[_stack_a] = set(self._reg_taint[_s])
                _sa = self._resolve_addr(_s)
                if _sa is not None and _sa in self._mem_taint:
                    _stack_a = self._rsp - self._get_op_size(instruction)
                    self._mem_taint[_stack_a] = set(self._mem_taint[_sa])
            self._rsp -= self._get_op_size(instruction)

        # ---- POP: 栈→寄存器 ----
        elif _opc == 'pop':
            _stack_a = self._rsp
            if _dst and _stack_a in self._mem_taint:
                _dst_taint |= self._mem_taint[_stack_a]
            self._rsp += self._get_op_size(instruction)

        # ---- LEA: 仅当基址寄存器有污点时传播 ----
        elif _opc == 'lea':
            for _s in _srcs:
                _base = self._extract_base_reg(_s)
                if _base and _base in self._reg_taint:
                    _dst_taint |= self._reg_taint[_base]

        # ---- CALL: 检查前6个参数(rdi/rsi/rdx/rcx/r8/r9)是否有污点流入sink ----
        elif _opc == 'call':
            _call_target = _dst or (_srcs[0] if _srcs else '')
            # 如果call目标本身是一个寄存器且该寄存器被污点标记
            if _call_target in self._reg_taint:
                pass  # 污点通过函数指针传播，保守不做跨函数分析

        # 应用污点到目的地
        if _dst and _dst_taint:
            if _dst.startswith('[') or _dst.startswith('ptr'):
                _ma = self._resolve_addr(_dst)
                if _ma is not None:
                    self._mem_taint.setdefault(_ma, set()).update(_dst_taint)
            else:
                self._reg_taint.setdefault(_dst, set()).update(_dst_taint)

    # ===== sink检查 =====
    def check_sink(self, instruction: str, sink: TaintSink) -> bool:
        """检查污点数据是否到达危险sink — 返回值True表示发现注入点"""
        _opc, _dst, _srcs = self._parse_operands(instruction)
        _args = []

        # 提取参数来源
        if _opc == 'call':
            # 假设函数调用的参数在 rdi, rsi, rdx, rcx, r8, r9
            _arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            for _r in _arg_regs:
                if _r in self._reg_taint:
                    _args.append((_r, self._reg_taint[_r]))
                _sa = self._resolve_addr(_r)
                if _sa is not None and _sa in self._mem_taint:
                    _args.append((f'mem[0x{_sa:x}]', self._mem_taint[_sa]))

        if _args:
            self._sink_hits += 1
            return True
        return False

    # //// sanitizer检测 ////
    def detect_sanitizers(self, instructions: List[str]):
        """在危险调用前检测长度检查和空指针检查 — 减少误报"""
        if not self._policy.sanitizer_detection:
            return

        for _i, _insn in enumerate(instructions):
            _lower = _insn.lower().strip()

            # cmp X, Y; jcc → 长度/边界检查
            if _lower.startswith('cmp '):
                _parts = _lower.split()
                if len(_parts) >= 3:
                    # 检查后续几条指令是否有条件跳转
                    for _j in range(_i + 1, min(_i + 4, len(instructions))):
                        _next = instructions[_j].lower().strip()
                        if any(_next.startswith(k) for k in ('j', 'jb', 'jbe', 'ja', 'jae', 'jg', 'jge', 'jl', 'jle', 'je', 'jne', 'jz', 'jnz')):
                            self._sanitizers.append((_i, f'length_check: cmp+jcc at insn {_i}'))
                            break

            # test X, X; jz → 空指针/null检查
            elif _lower.startswith('test '):
                for _j in range(_i + 1, min(_i + 4, len(instructions))):
                    _next = instructions[_j].lower().strip()
                    if _next.startswith('jz') or _next.startswith('je'):
                        self._sanitizers.append((_i, f'null_check: test+jz at insn {_i}'))
                        break

    # ===== 污点清除 =====
    def clear_taint(self, reg_or_addr: str):
        """移除指定寄存器或地址的污点标记"""
        if reg_or_addr.startswith('0x') or reg_or_addr.startswith('$'):
            try:
                _a = int(reg_or_addr.lstrip('$'), 0)
                self._mem_taint.pop(_a, None)
            except ValueError:
                pass
        else:
            self._reg_taint.pop(reg_or_addr, None)

    def get_taint(self, reg_or_addr: str) -> Set[TaintSource]:
        """查询寄存器或地址的污点源"""
        if reg_or_addr.startswith('0x') or reg_or_addr.startswith('$'):
            try:
                _a = int(reg_or_addr.lstrip('$'), 0)
                return self._mem_taint.get(_a, set())
            except ValueError:
                return set()
        return self._reg_taint.get(reg_or_addr, set())

    # ---- 指令解析 ----
    def _parse_operands(self, insn: str) -> Tuple[Optional[str], Optional[str], List[str]]:
        """粗糙指令解析: 返回(opcode, dest, [src1, src2,.])"""
        _s = insn.strip()
        # 去除注释
        if ';' in _s:
            _s = _s.split(';')[0].strip()
        if '#' in _s:
            _s = _s.split('#')[0].strip()

        _parts = _s.replace(',', ' ').split()
        if not _parts:
            return None, None, []

        _opc = _parts[0].lower()
        _operands = _parts[1:]

        if not _operands:
            return _opc, None, []

        # 调用约定: call target
        if _opc == 'call':
            return _opc, _operands[0], _operands[1:] if len(_operands) > 1 else []

        # 单操作数指令: push, pop, inc, dec,, neg
        if _opc in ('push', 'pop', 'inc', 'dec', 'not', 'neg', 'jmp', 'j', 'je',
                     'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae',
                     'jb', 'jbe', 'ret', 'call'):
            return _opc, _operands[0], []

        # 双操作数指令: mov dst, src; add dst, src; etc
        if len(_operands) >= 2:
            return _opc, _operands[0], _operands[1:]

        return _opc, _operands[0] if _operands else None, []

    def _is_xor_clear(self, insn: str) -> bool:
        """检测 xor reg, reg 清零模式"""
        _lower = insn.lower().strip()
        if not _lower.startswith('xor '):
            return False
        _parts = _lower.replace(',', ' ').split()
        if len(_parts) >= 3:
            _a = _parts[1]
            _b = _parts[2]
            return _a == _b
        return False

    # //// 地址解析 ////
    def _resolve_addr(self, operand: str) -> Optional[int]:
        """尝试从操作数字符串解析内存地址"""
        _s = operand.lower().strip()
        # 直接十六进制地址: 0x
        if _s.startswith('0x') or _s.startswith('$0x'):
            try:
                return int(_s.lstrip('$'), 16)
            except ValueError:
                return None
        # qword/word/dword ptr [addr]
        _m = re.search(r'\[(0x[0-9a-fA-F]+)\]', _s)
        if _m:
            return int(_m.group(1), 16)
        # [reg + offset] — 简单情况: [rsp+0x8]
        _m2 = re.search(r'\[(\w+)\s*[-+]\s*(0x[0-9a-fA-F]+|\d+)\]', _s)
        if _m2:
            _base_reg = _m2.group(1)
            _offset_str = _m2.group(2)
            try:
                if _offset_str.startswith('0x'):
                    _offset = int(_offset_str, 16)
                else:
                    _offset = int(_offset_str)
            except ValueError:
                return None
            if _base_reg == 'rsp' or _base_reg == 'esp':
                return self._rsp + _offset
            if _base_reg == 'rbp' or _base_reg == 'ebp':
                return 0x7ffffffde00 + _offset  # 粗略模拟
        return None

    def _extract_base_reg(self, operand: str) -> Optional[str]:
        """从内存操作数'[reg+offset]'中提取基址寄存器"""
        _s = operand.lower().strip().replace('[', '').replace(']', '')
        _parts = _s.replace('+', ' ').replace('-', ' ').split()
        if _parts:
            _candidate = _parts[0]
            if _candidate in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                              'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp'):
                return _candidate
        return None

    def _get_op_size(self, insn: str) -> int:
        """推断指令操作数大小 (字节)"""
        _lower = insn.lower()
        if 'qword' in _lower or 'qword' in _lower:
            return 8
        if 'dword' in _lower:
            return 4
        if 'word' in _lower:
            return 2
        if 'byte' in _lower:
            return 1
        # 64位默认push/pop操作8字节
        if _lower.startswith('push ') or _lower.startswith('pop '):
            _op_reg = _lower.split()[-1]
            if _op_reg in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                           'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
                return 8
            return 4
        return 8  # 默认64位操作

    # ===== 汇总 =====
    def taint_summary(self) -> Dict:
        """返回当前完整污点状态快照"""
        # 按source类型分组统计
        _by_source: Dict[str, List[str]] = {}
        for _reg, _sources in self._reg_taint.items():
            for _src in _sources:
                _by_source.setdefault(_src.name, []).append(f'reg:{_reg}')
        for _addr, _sources in self._mem_taint.items():
            for _src in _sources:
                _by_source.setdefault(_src.name, []).append(f'mem:0x{_addr:x}')

        return {
            'tainted_registers': {_r: [s.name for s in _srcs] for _r, _srcs in self._reg_taint.items()},
            'tainted_memory': {f'0x{_a:x}': [s.name for s in _srcs] for _a, _srcs in self._mem_taint.items()},
            'by_source': _by_source,
            'sanitizers': [(idx, desc) for idx, desc in self._sanitizers],
            'propagate_count': self._propagate_count,
            'sink_hits': self._sink_hits,
            'policy': {
                'track_registers': self._policy.track_registers,
                'track_memory': self._policy.track_memory,
                'sanitizer_detection': self._policy.sanitizer_detection,
                'xor_clearing': self._policy.xor_clearing,
            }
        }
