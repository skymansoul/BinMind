# 跨函数来源摘要 (Interprocedural Provenance Summary) - PcWBI来源约束写界推断.
#
# 决策逻辑:
#   单函数来源传播在函数边界截断: 被调函数内部的 def-use 链在调用点不可见,
#   导致经参数传入的写入大小在返回后来源退化为 UNKNOWN, 产生一类
#   "跨函数不确定" 误报. 本模块为每个用户函数构建摘要:
#     {out_reg: (输入参数寄存器索引, 常量偏移)}
#   即"哪个输出寄存器拷贝自哪个参数". 调用者在调用点可把该输出寄存器
#   重写为对应参数来源, 从而跨函数保持 ALLOC_LINKED / INPUT_TAINTED 类别.
#   摘要仅捕获高置信结构:
# 参数寄存器经 mov 拷贝到其他寄存器 (无算术变换)
# 参数寄存器加/减常量后传播
#     - 参数寄存器作为 malloc size 时, rax 标记 ALLOC_LINKED
#   摘要之外的模式保持保守, 不引入猜测.
#

from typing import Dict, List, Optional, Tuple


class FunctionProvenanceSummary:
    """单个函数的来源摘要."""

    __slots__ = ("name", "copy_chains", "alloc_return")

    def __init__(self, name: str):
        self.name = name
        self.copy_chains: Dict[str, Tuple[int, int]] = {}
        self.alloc_return: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "copy_chains": {k: list(v) for k, v in self.copy_chains.items()},
            "alloc_return": self.alloc_return,
        }


class InterprocSummaryBuilder:
    """从指令序列构建函数来源摘要."""

    _ALLOC_FUNCS = {"malloc", "calloc", "_Znwm", "_Znam", "g_malloc"}

    def __init__(self, arg_regs=None):
        self._arg_regs = arg_regs or ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        self._summaries: Dict[str, FunctionProvenanceSummary] = {}

    def build(self, func_name: str, instructions: List[dict],
              is_win64: bool = False) -> FunctionProvenanceSummary:
        """扫描单个函数, 构建摘要."""
        args = ("rcx", "rdx", "r8", "r9") if is_win64 else self._arg_regs
        arg_idx = {r: i for i, r in enumerate(args)}
        summary = FunctionProvenanceSummary(func_name)

        for ins in instructions:
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if not ops:
                continue

            if mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
                dst = self._norm_reg(ops[0])
                src = self._norm_reg(ops[1])
                if src in arg_idx and dst not in arg_idx:
                    summary.copy_chains[dst] = (arg_idx[src], 0)
                continue

            if mnem in ("add", "sub") and len(ops) >= 2:
                dst = self._norm_reg(ops[0])
                if dst in summary.copy_chains:
                    delta = self._parse_imm(ops[1])
                    if delta is not None:
                        idx, base = summary.copy_chains[dst]
                        summary.copy_chains[dst] = (idx, base + delta)
                continue

            if mnem == "call" and ops:
                from .disasm_util import extract_func_name
                func = extract_func_name(ops[0])
                if func in self._ALLOC_FUNCS:
                    # 第一个参数寄存器为size来源.
                    size_reg = args[0]
                    if size_reg in summary.copy_chains:
                        summary.alloc_return = summary.copy_chains[size_reg][0]

        self._summaries[func_name] = summary
        return summary

    def get(self, func_name: str) -> Optional[FunctionProvenanceSummary]:
        return self._summaries.get(func_name)

    def rewrite_reg(self, func_name: str, reg: str) -> Optional[int]:
        summary = self._summaries.get(func_name)
        if summary is None:
            return None
        return summary.copy_chains.get(reg)

    @staticmethod
    def _norm_reg(op: str) -> str:
        op = op.strip().lower().lstrip("%").lstrip("$")
        if "[" in op or op.startswith("0x") or op.isdigit():
            return ""
        return op

    @staticmethod
    def _parse_imm(s: str) -> Optional[int]:
        s = s.strip().lstrip("$").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None


__all__ = ["InterprocSummaryBuilder", "FunctionProvenanceSummary"]
