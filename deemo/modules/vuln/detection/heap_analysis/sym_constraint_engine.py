# coding: utf-8
# 拆分: 2026-08-09 | sym_types+sym_parser+sym_solver独立, 本文件仅保留引擎主类
"""符号化大小约束传播 (Symbolic Size-Bound Constraint Propagation).

将malloc的size参数和memcpy的len参数建模为符号变量,
沿数据流传播算术关系(add/sub/mul/wrap), 在写入点求解
alloc_size与write_size的约束不等式, 判定是否可证明安全.

复杂度: O(N) per function, N=指令数。不做路径枚举,
       路径敏感性由branch_narrower.py处理.

  SAIL— 稀疏值流图, 我们用简化版前向传播
  Crab(VMCAI'19)— 区间+符号区间抽象域, 我们只保留符号关系
  Inferbo— 二进制booster, interval domain + 缓冲区推理
"""
from typing import Dict, List, Optional

from modules.vuln.detection.heap_analysis.sym_types import (
    SymExpr, ConstraintRecord, SymAllocRecord, SymWriteRecord,
    SymAnalysisResult,
)
from modules.vuln.detection.heap_analysis.sym_parser import (
    normalize_reg, extract_imm, parse_insn, get_callee, get_addr,
    detect_abi, parse_mem_operand, ARG_REGS_SYSV, ARG_REGS_WIN64,
    _ALLOC_FUNCS, _WRITE_FUNCS,
    normalize_reg as _normalize_reg,
    extract_imm as _extract_imm,
    parse_insn as _parse_insn,
)
from modules.vuln.detection.heap_analysis.sym_solver import (
    solve_write, find_jcc_op, find_alloc_by_label, extract_offset,
    clobber,
)

class SymConstraintEngine:
    """符号化大小约束传播引擎

    单函数内前向扫描:
      1. 寄存器/栈槽绑定SymExpr
      2. malloc的size参数绑定到arg符号
      3. write的len参数绑定到SymExpr, 求精与alloc的关系
      4. cmp+jcc记录路径约束
      5. 在write点求解 write_size <= alloc_size + offset?
    """

    def __init__(self, abi: str = "auto", base_addr: int = 0x400000):
        self.abi = abi
        self.base_addr = base_addr

    def analyze(self, insns_raw: List[str],
                func_name: str = "") -> SymAnalysisResult:
        """分析单函数, 返回符号约束传播结果"""
        result = SymAnalysisResult()
        if not insns_raw:
            return result

        abi = (detect_abi(insns_raw) if self.abi == "auto"
               else (ARG_REGS_WIN64 if self.abi == "win64"
                     else ARG_REGS_SYSV))

        regs: Dict[str, SymExpr] = {}
        stack: Dict[int, SymExpr] = {}
        self._stack_ptr: Dict[int, str] = {}

        for i, reg in enumerate(abi, 1):
            regs[reg] = SymExpr(var=f"arg{i}", coeff=1, const=0)

        alloc_by_label: Dict[str, SymAllocRecord] = {}
        cur_constraints: List[ConstraintRecord] = []
        ptr_labels: Dict[str, str] = {}

        for i, raw in enumerate(insns_raw):
            mnem, ops = parse_insn(raw)
            addr = get_addr(raw, self.base_addr, i)

            callee = get_callee(raw)

            if callee and any(a in callee for a in _ALLOC_FUNCS):
                size_reg = abi[0]
                size_expr = regs.get(size_reg,
                                     SymExpr(is_const=True, const=0))
                if 'calloc' in callee and len(abi) >= 2:
                    n_expr = regs.get(abi[0], SymExpr(is_const=True, const=0))
                    s_expr = regs.get(abi[1], SymExpr(is_const=True, const=0))
                    n_val = n_expr.eval({})
                    s_val = s_expr.eval({})
                    if n_val is not None and s_val is not None:
                        size_expr = SymExpr(is_const=True,
                                            const=n_val * s_val)
                    else:
                        size_expr = SymExpr(var=None, coeff=0, const=0)

                label = f"malloc@{addr:x}"
                alloc = SymAllocRecord(
                    insn_idx=i, addr=addr, func=callee,
                    size_expr=size_expr, return_label=label)
                result.allocs.append(alloc)
                alloc_by_label[label] = alloc
                ptr_labels["rax"] = label
                clobber(regs, ptr_labels)
                ptr_labels["rax"] = label
                continue

            if callee and callee in _WRITE_FUNCS:
                size_arg_idx = _WRITE_FUNCS[callee]
                if size_arg_idx < len(abi):
                    len_reg = abi[size_arg_idx]
                    len_expr = regs.get(
                        len_reg, SymExpr(is_const=True, const=0))
                else:
                    len_expr = SymExpr(is_const=True, const=0)

                dst_reg = abi[0]
                dst_label = ptr_labels.get(dst_reg, "unknown")
                offset_expr = extract_offset(dst_reg, regs)
                alloc = find_alloc_by_label(dst_label, alloc_by_label)

                write = SymWriteRecord(
                    insn_idx=i, addr=addr, func=callee,
                    dst_label=dst_label, size_expr=len_expr,
                    offset_expr=offset_expr, linked_alloc=alloc)
                result.writes.append(write)

                verdict = solve_write(write, cur_constraints)
                if verdict == "safe":
                    result.proven_safe.append(i)
                elif verdict == "overflow":
                    result.proven_overflow.append(i)
                else:
                    result.uncertain.append(i)

                clobber(regs, ptr_labels)
                continue

            if callee and callee in ('strcpy', 'strcat', 'gets', 'sprintf'):
                dst_reg = abi[0]
                dst_label = ptr_labels.get(dst_reg, "unknown")
                offset_expr = extract_offset(dst_reg, regs)
                alloc = find_alloc_by_label(dst_label, alloc_by_label)
                write = SymWriteRecord(
                    insn_idx=i, addr=addr, func=callee,
                    dst_label=dst_label,
                    size_expr=SymExpr(var="unbounded", coeff=0, const=-1),
                    offset_expr=offset_expr, linked_alloc=alloc)
                result.writes.append(write)
                result.uncertain.append(i)
                clobber(regs, ptr_labels)
                continue

            if mnem == 'call':
                clobber(regs, ptr_labels)
                continue

            if mnem in ('mov', 'movzx', 'movsx', 'movsxd'):
                self._handle_mov(mnem, ops, regs, stack, ptr_labels)
                continue

            if mnem == 'lea':
                self._handle_lea(ops, regs)
                continue

            if mnem in ('add', 'sub'):
                self._handle_addsub(mnem, ops, regs, ptr_labels)
                continue

            if mnem in ('xor', 'pxor'):
                if len(ops) >= 2:
                    r1 = normalize_reg(ops[0])
                    r2 = normalize_reg(ops[1])
                    if r1 and r2 and r1 == r2:
                        regs[r1] = SymExpr(is_const=True, const=0)
                continue

            if mnem == 'imul' and len(ops) >= 3:
                dst = normalize_reg(ops[0])
                src = normalize_reg(ops[1])
                imm = extract_imm(ops[2])
                if dst and src and imm is not None:
                    src_expr = regs.get(src)
                    if src_expr:
                        regs[dst] = src_expr.mul_const(imm)
                continue

            if mnem == 'cmp' and len(ops) >= 2:
                reg = normalize_reg(ops[0])
                imm = extract_imm(ops[1])
                if reg and imm is not None:
                    op = find_jcc_op(insns_raw, i)
                    if op:
                        cur_constraints.append(
                            ConstraintRecord(var=reg, op=op, value=imm))
                continue

        result.constraints = cur_constraints
        result.env = {}
        return result

    def _handle_mov(self, mnem: str, ops: List[str],
                    regs: Dict[str, SymExpr],
                    stack: Dict[int, SymExpr],
                    ptr_labels: Dict[str, str]) -> None:
        """mov指令处理 — 符号表达式传播

        关键: 栈槽追踪, 含QWORD PTR [rbp-N]格式的正确解析
        """
        if len(ops) < 2:
            return
        dst = ops[0].strip()
        src = ops[1].strip()
        dst_reg = normalize_reg(dst)

        if '[' in dst:
            base_reg, offset = parse_mem_operand(dst)
            if base_reg in ('rbp', 'rsp') and offset is not None:
                src_reg = normalize_reg(src)
                if src_reg and src_reg in regs:
                    stack[offset] = regs[src_reg]
                if src_reg and src_reg in ptr_labels:
                    self._stack_ptr[offset] = ptr_labels[src_reg]
            return

        if dst_reg:
            src_reg = normalize_reg(src)
            if src_reg and src_reg in regs:
                regs[dst_reg] = regs[src_reg]
                if src_reg in ptr_labels:
                    ptr_labels[dst_reg] = ptr_labels[src_reg]
                else:
                    ptr_labels.pop(dst_reg, None)
            elif src_reg and src_reg in ptr_labels:
                ptr_labels[dst_reg] = ptr_labels[src_reg]
            elif '[' in src:
                base_reg, offset = parse_mem_operand(src)
                if base_reg in ('rbp', 'rsp') and offset is not None:
                    if offset in stack:
                        regs[dst_reg] = stack[offset]
                    if offset in self._stack_ptr:
                        ptr_labels[dst_reg] = self._stack_ptr[offset]
                    else:
                        ptr_labels.pop(dst_reg, None)
                elif base_reg and base_reg in ptr_labels:
                    ptr_labels[dst_reg] = ptr_labels[base_reg]
                else:
                    regs.pop(dst_reg, None)
                    ptr_labels.pop(dst_reg, None)
            else:
                imm = extract_imm(src)
                if imm is not None:
                    regs[dst_reg] = SymExpr(is_const=True, const=imm)
                    ptr_labels.pop(dst_reg, None)
                else:
                    regs.pop(dst_reg, None)
                    ptr_labels.pop(dst_reg, None)

    def _handle_lea(self, ops: List[str],
                    regs: Dict[str, SymExpr]) -> None:
        """lea dst, [base+offset] → 地址计算"""
        if len(ops) < 2:
            return
        dst_reg = normalize_reg(ops[0])
        src = ops[1].strip()
        if not dst_reg or '[' not in src:
            return
        inner = src.split('[')[1].split(']')[0]
        base_reg = normalize_reg(
            inner.split('+')[0].split('-')[0].strip())
        offset = 0
        for sep in ['+', '-']:
            if sep in inner:
                try:
                    off_str = inner.split(sep)[-1].strip()
                    off = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
                    offset = off if sep == '+' else -off
                    break
                except ValueError:
                    pass
        if base_reg and base_reg in regs:
            base_expr = regs[base_reg]
            regs[dst_reg] = SymExpr(
                var=base_expr.var, coeff=base_expr.coeff,
                const=base_expr.const + offset,
                is_const=base_expr.is_const)
        else:
            regs.pop(dst_reg, None)

    def _handle_addsub(self, mnem: str, ops: List[str],
                       regs: Dict[str, SymExpr],
                       ptr_labels: Dict[str, str]) -> None:
        """add/sub reg, src → 符号表达式更新"""
        if len(ops) < 2:
            return
        dst_reg = normalize_reg(ops[0])
        if not dst_reg:
            return
        cur = regs.get(dst_reg)
        if cur is None:
            return

        src_reg = normalize_reg(ops[1])
        imm = extract_imm(ops[1])

        if imm is not None:
            delta = imm if mnem == 'add' else -imm
            regs[dst_reg] = SymExpr(
                var=cur.var, coeff=cur.coeff,
                const=cur.const + delta, is_const=cur.is_const)
        elif src_reg and src_reg in regs:
            other = regs[src_reg]
            if mnem == 'add':
                regs[dst_reg] = cur.add(other)
            else:
                regs[dst_reg] = cur.sub(other)

def analyze_function_symbolic(
        insns_raw: List[str],
        func_name: str = "",
        abi: str = "auto",
        base_addr: int = 0x400000) -> SymAnalysisResult:
    """对单函数执行符号约束传播分析"""
    engine = SymConstraintEngine(abi=abi, base_addr=base_addr)
    return engine.analyze(insns_raw, func_name)

__all__ = [
    "SymExpr", "SymAllocRecord", "SymWriteRecord",
    "SymAnalysisResult", "ConstraintRecord",
    "SymConstraintEngine", "analyze_function_symbolic",
]
