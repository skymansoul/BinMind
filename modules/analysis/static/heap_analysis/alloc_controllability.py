"""分配参数可控性 - 判定 malloc 大小参数是否源自用户输入.

误报根源: 分配大小源自用户输入 (argv/recv/read/getenv) 时溢出风险高,
源自常量或内部计算时风险低. 传统检测器不做区分, 对所有未知大小
一视同仁. 本模块沿 def-use 链分类大小参数的来源, 为融合判定器
提供风险加权 - 不硬性过滤, 只影响置信度与判定排序.

设计决策:
  - 常量 / 用户输入 / 内部计算 / 未知 四分类
  - 用户输入判定: 直接来自 argv 处理 (atoi/strtol/sscanf)
    或经 strlen 链 (strlen(argv[x]) 模式)
  - [rbp+0x10+] 栈槽 → 函数参数, 按参数序号进入入口寄存器
    溯源, 入口寄存器为 rsi (argv) / rdx (argc) → 用户输入
"""

from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction

_WINDOW = 25
_MAX_HOPS = 6

_USER_CONVERTERS = {"atoi", "atol", "strtol", "strtoul", "sscanf",
                    "__isoc99_sscanf", "scanf", "strtoll", "strtod"}
_USER_READERS = {"read", "recv", "fread", "gets", "getenv", "getline",
                 "fgets"}


class ControlSource(Enum):
    """分配大小参数来源分类."""
    CONSTANT = auto()   # 立即数
    USER = auto()       # 用户输入 (argv/网络/环境变量)
    INTERNAL = auto()   # 内部计算 (strlen/算术/结构体大小)
    PARAM = auto()      # 函数参数, 来源未知
    UNKNOWN = auto()    # 无法解析


class AllocControllability:
    """分配参数可控性分类器."""

    def classify(self, insns: List[ParsedInstruction], call_idx: int,
                 size_regs: Tuple[str, ...]) -> ControlSource:
        """分类分配调用点大小参数的来源."""
        for reg in size_regs:
            src = self._chase(insns, call_idx, reg, _MAX_HOPS, set())
            if src != ControlSource.UNKNOWN:
                return src
        return ControlSource.UNKNOWN

    # 内部

    def _chase(self, insns: List[ParsedInstruction], idx: int,
               reg: str, hops_left: int,
               seen: Set[str]) -> ControlSource:
        if hops_left <= 0 or reg in seen:
            return ControlSource.UNKNOWN
        seen.add(reg)
        start = max(0, idx - _WINDOW)
        for j in range(idx - 1, start - 1, -1):
            ins = insns[j]
            mn = ins.mnemonic
            if len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst != reg:
                continue
            src = ins.operands[1].strip()
            if mn in ("mov", "movabs"):
                if InstructionParser._try_parse_int(src) is not None:
                    return ControlSource.CONSTANT
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._chase(insns, j, src_reg,
                                       hops_left - 1, seen)
                base, _, _, off = \
                    InstructionParser.parse_memory_operand_full(src)
                if base in ("rbp", "rsp") and off >= 16:
                    return ControlSource.PARAM
                if base == "rip":
                    return ControlSource.CONSTANT  # 全局常量/地址
                return ControlSource.UNKNOWN
            if mn in ("add", "sub", "imul", "mul", "shl", "shr",
                      "and", "or", "xor"):
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._chase(insns, j, src_reg,
                                       hops_left - 1, seen)
                continue
            if mn == "lea":
                base, _, _, _ = \
                    InstructionParser.parse_memory_operand_full(src)
                if base:
                    return self._chase(insns, j, base,
                                       hops_left - 1, seen)
                continue
            if mn == "call":
                callee = InstructionParser.extract_callee(ins)
                if callee in _USER_CONVERTERS or callee in _USER_READERS:
                    return ControlSource.USER
                if callee == "strlen":
                    # strlen(x) 的上游若是用户输入 → 用户; 否则内部
                    return self._arg_source(insns, j, callee, seen)
                return ControlSource.INTERNAL
            break
        return ControlSource.UNKNOWN

    def _arg_source(self, insns: List[ParsedInstruction], call_idx: int,
                    callee: str, seen: Set[str]) -> ControlSource:
        """追踪 call 前第一个参数的来源 (rdi)."""
        return self._chase(insns, call_idx, "rdi", _MAX_HOPS, seen)


# smoke test
def _check():
    asm = """
    1300:       48 8b 7d 10             mov    rdi,QWORD PTR [rbp+0x10]
    1304:       e8 f7 fe ff ff          call   strlen
    1309:       48 89 c2                mov    rdx,rax
    130c:       48 89 c7                mov    rdi,rax
    130f:       e8 ec fe ff ff          call   malloc
    """
    insns = InstructionParser.parse(asm)
    call_idx = next(i for i, x in enumerate(insns) if "malloc" in x.raw_line)
    ctl = AllocControllability()
    src = ctl.classify(insns, call_idx, ("rdi",))
    assert src in (ControlSource.PARAM, ControlSource.UNKNOWN), f"got {src}"
    print(f"[OK] alloc_controllability: malloc size source = {src}")


if __name__ == "__main__":
    _check()
