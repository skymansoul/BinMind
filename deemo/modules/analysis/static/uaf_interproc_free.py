# 过程间 Free 摘要分析器 (Interprocedural Free Summary)
#
# 核心问题: 函数 A 调用函数 B, B 内部 free(*参数) 或 free(参数->field),
# 调用者 A 不知道自己的指针已被释放, 后续使用 → UAF 漏报.
#
# 传统二进制 UAF 检测器只做函数内分析, 跨函数 free 通过间接参数传递时
# 完全遗漏. 动态方案 (ASan) 需要运行, 无法覆盖所有路径.
#
# 本模块构建函数级 free 摘要:
#   Phase 1: 扫描每个函数, 记录哪些参数 (通过 rcx/rdx/r8/r9 或栈) 被 free
#   Phase 2: 调用者遇到 call B 时, 查摘要 → 若 B 会 free 参数 N → 标记该参数为 freed
#
# 支持的间接 free 模式:
# free(rcx): 直接释放第一个参数
#   - free(*rcx): 释放参数指向的对象 (双重指针) - mov rax,[rcx]; mov rcx,rax; call free
#   - free(rcx->field): 释放参数结构体字段 - mov rax,[rcx+offset]; call free
# callee 内部调用其他 free-like 函数: 递归摘要 (1层)
#
# 理论依据:
#   二进制级过程间分析, 以函数摘要传播 free 参数
#

import re
from typing import Dict, List, Optional, Set, Tuple

from .disasm_util import norm_reg, extract_func_name, extract_stack_slot


# free 系列函数完整集合
_FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete",
               "g_free", "ExFreePool", "kfree", "vfree", "__builtin_free"}
_ALLOC_FUNCS = {"malloc", "calloc", "_Znwm", "_Znam",
                "operator_new", "g_malloc"}


class FreeSummary:
    """单个函数的 free 摘要 - 描述哪些参数被间接释放."""
    __slots__ = ("func_name", "func_start", "func_end",
                 "freed_params", "has_direct_free", "calls_free_like")

    def __init__(self, func_name: str, func_start: int, func_end: int):
        self.func_name = func_name
        self.func_start = func_start
        self.func_end = func_end
        self.freed_params: Set[int] = set()           # 参数索引 (0=rcx/rdi, 1=rdx/rsi, ...)
        self.has_direct_free: bool = False             # 函数内直接调用 free
        self.calls_free_like: Set[str] = set()         # 调用的其他 free-like 函数名


class InterprocFreeAnalyzer:
    """过程间 free 摘要分析器.

    两阶段:
      Phase 1 (build_summaries): 对每个函数构建 free 摘要
      Phase 2 (get_freed_params): 查询函数调用的间接释放参数
    """

    _WIN64_ARGS = ("rcx", "rdx", "r8", "r9")
    _SYSV_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

    def __init__(self, use_win64_abi: bool = True):
        self._summaries: Dict[str, FreeSummary] = {}
        self._addr_to_name: Dict[int, str] = {}
        self._arg_regs = self._WIN64_ARGS if use_win64_abi else self._SYSV_ARGS

    def build_summaries(self, instructions: List[dict],
                        func_ranges: List[Tuple[int, int]] = None):
        """Phase 1: 构建所有函数的 free 摘要.

        从call指令操作数提取 <func_name> 标记构建函数表,
        再按函数地址排序得到独立函数范围.
        """
        self._summaries.clear()
        self._addr_to_name.clear()

        func_table = self._build_func_table(instructions)
        if not func_table:
            return
        sorted_starts = sorted(func_table.keys())

        for idx, start in enumerate(sorted_starts):
            end = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else start + 0x200
            name = func_table[start]
            if name in _FREE_FUNCS or name in _ALLOC_FUNCS:
                continue
            func_ins = [i for i in instructions if start <= i.get("address", 0) < end]
            if not func_ins:
                continue
            summary = self._analyze_function(func_ins, start, end, name)
            self._summaries[name] = summary
            self._addr_to_name[start] = name

    def _build_func_table(self, instructions: List[dict]) -> Dict[int, str]:
        """从call指令操作数提取函数名和地址."""
        table: Dict[int, str] = {}
        libc = _FREE_FUNCS | _ALLOC_FUNCS
        for ins in instructions:
            if ins.get("mnemonic", "").lower() not in ("call", "jmp"):
                continue
            ops = ins.get("operands", [])
            if not ops:
                continue
            m = re.search(r'<([^>]+)>', ops[0])
            if not m:
                continue
            name = m.group(1).split("@")[0].split(".")[-1]
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
                continue
            addr_part = ops[0].split()[0]
            try:
                addr = int(addr_part, 16)
            except ValueError:
                continue
            if name not in libc and addr not in table:
                table[addr] = name
        return table

    def _analyze_function(self, func_ins: List[dict], lo: int, hi: int,
                          name: str) -> FreeSummary:
        """分析单个函数内的 free 模式.

        支持两种 free 调用形式:
          - call <free>: 常规调用
          - jmp <free>: O2/Os tail-call 优化 (mov rcx,[rcx]; jmp free)
        """
        summary = FreeSummary(name, lo, hi)
        arg_map = {reg: idx for idx, reg in enumerate(self._arg_regs)}

        for i, ins in enumerate(func_ins):
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)

            if mnem in ("call", "jmp") and ops:
                callee = extract_func_name(ops[0])
                if callee in _FREE_FUNCS:
                    summary.has_direct_free = True
                    freed_param = self._trace_free_arg(func_ins, i, addr)
                    if freed_param is not None:
                        summary.freed_params.add(freed_param)
                    else:
                        summary.freed_params.add(99)
                    self._check_deref_free_pattern(func_ins, i, addr, summary, arg_map)
                elif mnem == "call" and callee in self._summaries:
                    nested = self._summaries[callee]
                    summary.calls_free_like.add(callee)
                    summary.freed_params.update(nested.freed_params)

        return summary

    def _trace_free_arg(self, func_ins: List[dict], call_idx: int,
                        call_addr: int) -> Optional[int]:
        """回溯 free() 的参数来源, 判断是否来自函数参数寄存器.

        通用寄存器链回溯: 从 call 前的 arg0 赋值反向追踪 mov 链,
        识别:
          - 直接参数: mov rcx, arg_reg; call free
          - 栈转存参数: mov [rbp+x], rcx; mov rcx,[rbp+x]; call free
          - double-pointer: mov rax,[param]; mov rcx,rax; call free
          - 栈参数 + double-deref:
            mov [rbp+0x10], rcx; mov rax,[rbp+0x10]; mov rax,[rax];
            mov rcx,rax; call free  (free(*pp))
        链回溯至函数入口 (无前驱 mov) 或 arg_reg 即判定参数索引.
        """
        arg0 = self._arg_regs[0] if self._arg_regs else "rcx"
        arg_reg_set = {reg: idx for idx, reg in enumerate(self._arg_regs)}

        current = arg0
        for j in range(call_idx - 1, max(-1, call_idx - 25), -1):
            ins = func_ins[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem in ("mov", "movzx", "movsx") and len(ops) >= 2:
                dst = norm_reg(ops[0])
                if dst == arg0:
                    src = norm_reg(ops[1])
                    if src in arg_reg_set:
                        return arg_reg_set[src]
                    return None
            if mnem == "call":
                break
            if mnem not in ("mov", "movzx", "movsx") or len(ops) < 2:
                continue
            dst = norm_reg(ops[0])
            if dst != current:
                continue
            src_raw = ops[1].strip()
            src = norm_reg(src_raw)

            if src in arg_reg_set:
                return arg_reg_set[src]
            if "[" in src_raw.lower():
                base_reg = self._extract_base_reg(src_raw)
                slot = extract_stack_slot(src_raw)
                if slot:
                    # 栈槽 [rbp+0x10] 可能是参数转存: 找写入该槽的 mov
                    for k in range(j - 1, max(-1, j - 15), -1):
                        p = func_ins[k]
                        p_ops = p.get("operands", [])
                        if p.get("mnemonic", "").lower() == "mov" \
                                and len(p_ops) >= 2 \
                                and extract_stack_slot(p_ops[0]) == slot:
                            src2 = norm_reg(p_ops[1])
                            if src2 in arg_reg_set:
                                return arg_reg_set[src2]
                            break
                # double-pointer: 内存解引用的基址是参数寄存器
                if base_reg and base_reg in arg_reg_set:
                    return arg_reg_set[base_reg]
                # 多层解引用: base 是中间寄存器 → 继续追踪 base 的来源
                if base_reg:
                    current = base_reg
                    continue
                return None
            current = src
        return None


    def _parse_mem_base(op: str):
        """解析内存操作数, 返回 (基址寄存器, 偏移)."""
        m = re.search(r"\[([a-z][a-z0-9]*)", op.lower())
        if m:
            base = norm_reg(m.group(1))
            off = 0
            m2 = re.search(r"([+-]0x[0-9a-f]+)", op.lower())
            if m2:
                try:
                    off = int(m2.group(1), 16)
                except ValueError:
                    off = 0
            return base, off
        return None, 0


    def _check_deref_free_pattern(self, func_ins: List[dict], call_idx: int,
                                  call_addr: int, summary: FreeSummary,
                                  arg_map: Dict[str, int]):
        """检测 free(*param) 模式: 间接解引用参数后 free.

        支持的指令链模式:
          - 直接: mov rax,[rcx]; mov rcx,rax; call free
          - 栈转存: mov [rbp+x],rcx; mov rax,[rbp+x]; mov rax,[rax]; mov rcx,rax; call free
          - 偏移: mov rax,[rcx+0x8]; mov rcx,rax; call free
        回溯free参数源寄存器, 再追踪该寄存器是否来自参数解引用.
        """
        if call_idx < 1:
            return
        free_arg = self._arg_regs[0] if self._arg_regs else "rcx"

        chain_regs = self._trace_back_chain(func_ins, call_idx, free_arg, max(0, call_idx - 12))
        if not chain_regs:
            return

        for j in range(call_idx - 1, max(-1, call_idx - 12), -1):
            ins = func_ins[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem not in ("mov", "movzx", "movsx") or len(ops) < 2:
                if mnem == "call":
                    break
                continue
            dst = norm_reg(ops[0])
            src_raw = ops[1].strip()
            src_reg = norm_reg(src_raw)
            if dst in chain_regs and "[" in src_raw.lower():
                base = self._extract_base_reg(src_raw)
                if base in arg_map:
                    # 字段释放判别: [base+offset] 释放的是字段对象, 非base对象.
                    # 只有 [base] (offset==0, 双重指针) 才标记参数本身被释放.
                    if self._mem_offset(src_raw) == 0:
                        summary.freed_params.add(arg_map[base])
                    return
                if base in chain_regs:
                    continue
            # [DEPRECATED] 移除过宽分支(原代码):
            #   if dst in arg_map and src_reg in chain_regs:
            #       summary.freed_params.add(arg_map[dst]); return
            # 理由: 该分支会把"free实参寄存器接收字段加载值(mov rcx, rax)"
            # 误判为释放参数本身 → 字段释放被错误标记为父对象释放(double_free FP).
            # 直接free由_trace_free_arg覆盖; 解引用free由[base]分支(含offset判别)覆盖.
            # 等待明确确认后可恢复/删除此注释块.

    def _trace_back_chain(self, func_ins: List[dict], call_idx: int,
                          start_reg: str, lo_idx: int) -> Set[str]:
        """追踪寄存器数据流: 从 start_reg 回溯找出关联的寄存器集合."""
        chain: Set[str] = {start_reg}
        changed = True
        while changed:
            changed = False
            for j in range(call_idx - 1, lo_idx - 1, -1):
                ins = func_ins[j]
                mnem = ins.get("mnemonic", "").lower()
                ops = ins.get("operands", [])
                if mnem not in ("mov", "movzx", "movsx") or len(ops) < 2:
                    if mnem == "call":
                        break
                    continue
                dst = norm_reg(ops[0])
                src = norm_reg(ops[1].strip())
                if dst in chain and src not in chain:
                    chain.add(src)
                    changed = True
        return chain

    def get_freed_params(self, callee_name: str) -> Set[int]:
        """查询函数会间接释放哪些参数索引."""
        summary = self._summaries.get(callee_name)
        if summary:
            return set(summary.freed_params)
        return set()

    def is_free_like(self, func_name: str) -> bool:
        """判断函数是否为 free-like (会释放参数)."""
        summary = self._summaries.get(func_name)
        return summary is not None and len(summary.freed_params) > 0

    @staticmethod
    def _infer_func_name(func_ins: List[dict], func_start: int) -> Optional[str]:
        """保留接口兼容性 - 实际函数名由 _build_func_table 提供."""
        return None

    @staticmethod
    def _extract_base_reg(operand: str) -> str:
        """从 [rcx] 或 [rcx+0x8] 提取基址寄存器."""
        o = operand.strip().lower()
        m = re.search(r'\[([a-z0-9]+)', o)
        if m:
            return norm_reg(m.group(1))
        return ""

    @staticmethod
    def _mem_offset(operand: str) -> int:
        """从 [rcx+0x8] / [rcx-0x4] 提取位移量."""
        o = operand.strip().lower()
        m = re.search(r'\[[a-z0-9]+\s*([+-]\s*0x[0-9a-f]+)\]', o)
        if not m:
            return 0
        s = m.group(1).replace(" ", "")
        try:
            if s.startswith("+0x"):
                return int(s[1:], 16)
            if s.startswith("-0x"):
                return -int(s[1:], 16)
            return int(s, 16)
        except ValueError:
            return 0


__all__ = ["InterprocFreeAnalyzer", "FreeSummary"]
