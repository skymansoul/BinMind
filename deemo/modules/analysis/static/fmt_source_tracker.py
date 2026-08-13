# 格式字符串来源追踪器 v4 (Format String Source Provenance Tracker)
#
# v4: 全局函数指针追踪 — 支持通过全局变量间接调用的格式字符串检测.
# 追踪 refptr→寄存器→全局变量→寄存器→间接调用的完整链
# 两阶段分析: 预扫阶段建立全局函数指针映射, 主分析阶段使用该映射
# 解决callback/函数指针模式下的漏报问题
#
# v3: 三通道来源追踪 (寄存器→内存→栈) + 跨函数参数传播.
#
# 核心决策:
#   现有检测器仅追踪单层mov/lea的立即数来源, 但对跨函数传播
#   和间接加载无能为力. 例如:
#     lea rcx, [rip+.fmt]  → rcx="literal"  ✓
#     mov rcx, [rbp-0x8]   → rcx="stack"    ✓
#     但 caller: mov rcx, argv[0]; call debug
#          callee: fprintf(stderr, rcx)       ✗ (rcx来源丢失)
#     但 callback:  g_log = printf; call g_log(user_input)  ✗ (间接调用)
#
#   本模块增强四层追踪:
#     1. 寄存器→寄存器 (现有)
#     2. 寄存器→内存→寄存器 (栈槽/RIP-relative)
#     3. 跨函数参数传播 (caller→callee, depth=1)
#     4. 全局函数指针追踪 (refptr→global→间接调用) [v4 NEW]
#
# 理论依据:
#   "Precise and Scalable Taint Tracking for Binary":
#     寄存器+内存的双向污点传播提升格式字符串检测精度.
#   "UAFx: Use-After-Free Detection with Path-Sensitive Analysis":
#     全局变量状态追踪对二进制级漏洞检测至关重要.
#
# 创建: 2024-12-11

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from .disasm_util import norm_reg, resolve_rip_relative, extract_func_name, extract_stack_slot


# printf族函数名模式 — 用于从refptr符号名中识别
_PRINTF_NAME_PATTERNS = [
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf", "vdprintf", "syslog", "vsyslog",
    "__mingw_printf", "__mingw_fprintf",
]


def _extract_printf_name(symbol: str) -> Optional[str]:
    """从refptr符号名中提取printf族函数名.

    例如: '.refptr.__mingw_printf' → 'printf'
          '.refptr.printf' → 'printf'
    """
    sym_lower = symbol.strip("<>.").lower()
    for pat in _PRINTF_NAME_PATTERNS:
        if pat in sym_lower:
            # 标准化为基础函数名
            for base in ("printf", "fprintf", "sprintf", "snprintf",
                         "vprintf", "vfprintf", "vsprintf", "vsnprintf",
                         "dprintf", "vdprintf", "syslog", "vsyslog"):
                if base in pat:
                    return base
    return None


def _is_printf_func(name: str) -> bool:
    n = name.lower().strip("_")
    return any(p in n for p in _PRINTF_NAME_PATTERNS)


class FmtSourceTracker:
    """格式字符串来源追踪 — 四通道传播 (v4: 含全局函数指针)."""

    def __init__(self, use_win64: bool = False):
        # reg → source_type 映射: "literal" | "stack_var" | "heap" | "argv" | "unknown"
        self._reg_src: Dict[str, str] = {}
        # 内存地址 → source_type
        self._mem_src: Dict[int, str] = {}
        # 栈槽 → source_type
        self._stack_src: Dict[str, str] = {}
        # 函数参数传播记录: func_addr → [(arg_reg, source_type)]
        self._func_arg_src: Dict[int, List[Tuple[str, str]]] = {}
        # 指令快照 (用于回溯)
        self._snapshot: Dict[int, dict] = {}
        # Win64 arg regs
        self._arg_regs = ("rcx","rdx","r8","r9") if use_win64 else ("rdi","rsi","rdx","rcx","r8","r9")

        # v4: 函数指针追踪
        # reg → func_name (当reg持有已知函数指针时)
        self._reg_func_ptr: Dict[str, str] = {}
        # 全局地址 → func_name (已知存储函数指针的全局变量)
        self._global_func_ptr: Dict[int, str] = {}
        # 栈槽 → func_name (持有函数指针的栈槽)
        self._stack_func_ptr: Dict[str, str] = {}
        # call地址 → {reg: func_name} (函数指针参数快照)
        self._func_ptr_snapshots: Dict[int, Dict[str, str]] = {}
        # 当前函数内已处理的指令地址集合 (用于避免跨函数污染)
        self._current_func_start: int = 0

        # 调用者保存寄存器: ret后清除, 防止CRT状态泄漏到用户代码.
        # Win64: rax,rcx,rdx,r8,r9,r10,r11; SysV额外: rsi,rdi.
        if use_win64:
            self._caller_saved = {"rax","rcx","rdx","r8","r9","r10","r11"}
        else:
            self._caller_saved = {"rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11"}

# 公开API

    def feed(self, ins: dict):
        """逐指令馈入, 维护来源追踪."""
        addr = ins.get("address", 0)
        self._snapshot[addr] = ins
        if len(self._snapshot) > 500:
            del self._snapshot[min(self._snapshot.keys())]

        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])

        # ret: 清除调用者保存寄存器, 防止CRT状态泄漏到后续用户代码.
        if mnem == "ret":
            for reg in self._caller_saved:
                self._reg_src.pop(reg, None)
                self._reg_func_ptr.pop(reg, None)
            return

        if mnem == "call" and ops:
            self._handle_call(ins, ops, addr)
        elif mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            self._track_mov(ins, ops, addr)
        elif mnem == "lea" and len(ops) >= 2:
            self._track_lea(ins, ops, addr)

    def get_source(self, reg: str) -> str:
        """获取寄存器的格式字符串来源分类."""
        return self._reg_src.get(norm_reg(reg), "unknown")

    def get_func_ptr(self, reg: str) -> Optional[str]:
        """获取寄存器持有的已知函数指针名称 (如 'printf', 'fprintf').

        若寄存器未持有已知函数指针则返回 None.
        """
        r = norm_reg(reg)
        # 直接查_reg_func_ptr
        if r in self._reg_func_ptr:
            return self._reg_func_ptr[r]
        # 32位寄存器 → 查对应的64位寄存器
        w64 = _W32_TO_W64.get(r)
        if w64 and w64 in self._reg_func_ptr:
            return self._reg_func_ptr[w64]
        return None

    def get_global_func_ptr(self, rip_addr: int) -> Optional[str]:
        """获取已知存储函数指针的全局地址对应的函数名."""
        return self._global_func_ptr.get(rip_addr)

    def mark_global_func_ptr(self, addr: int, func_name: str):
        """手动标记全局地址为持有指定函数指针.

        由预扫阶段调用, 用于建立全局函数指针映射.
        """
        self._global_func_ptr[addr] = func_name

    def get_arg_source(self, ins: dict, arg_idx: int) -> str:
        """获取指定调用点的第arg_idx个参数的来源."""
        if arg_idx >= len(self._arg_regs):
            return "stack"
        return self._reg_src.get(self._arg_regs[arg_idx], "unknown")

    def apply_caller_sources(self, call_ins_addr: int):
        """将被调用函数入口处的参数来源设置为调用者传递的值.

        在callee的第一条指令处调用此方法.
        """
        # 恢复参数来源
        snapshot = self._func_arg_src.get(call_ins_addr)
        if snapshot:
            for reg, src in snapshot:
                self._reg_src[reg] = src

        # v4: 恢复函数指针来源
        func_ptr_snapshot = self._func_ptr_snapshots.get(call_ins_addr)
        if func_ptr_snapshot:
            for reg, func_name in func_ptr_snapshot.items():
                self._reg_func_ptr[reg] = func_name

    def mark_argv(self, reg: str):
        """将指定寄存器标记为argv来源 (从main的argc/argv推理)."""
        self._reg_src[norm_reg(reg)] = "argv"

    def reset(self):
        self._reg_src.clear()
        self._mem_src.clear()
        self._stack_src.clear()
        self._func_arg_src.clear()
        self._snapshot.clear()
        self._reg_func_ptr.clear()
        self._stack_func_ptr.clear()
        self._func_ptr_snapshots.clear()
        # 注意: _global_func_ptr 不在此清理, 因为它由预扫阶段填充

# 内部追踪逻辑

    def _handle_call(self, ins: dict, ops: List[str], addr: int):
        """记录函数调用时的参数来源, 用于跨函数传播."""
        # 记录参数来源快照
        arg_snapshot = []
        for reg in self._arg_regs:
            src = self._reg_src.get(reg)
            if src:
                arg_snapshot.append((reg, src))
        if arg_snapshot:
            self._func_arg_src[addr] = arg_snapshot

        # v4: 记录函数指针参数快照
        func_ptr_snapshot = {}
        for reg in self._arg_regs:
            fp = self._reg_func_ptr.get(reg)
            if fp:
                func_ptr_snapshot[reg] = fp
        if func_ptr_snapshot:
            self._func_ptr_snapshots[addr] = func_ptr_snapshot

    def _track_mov(self, ins: dict, ops: List[str], addr: int):
        dst_raw, src_raw = ops[0].strip(), ops[1].strip()
        dst = norm_reg(dst_raw)
        src_lower = src_raw.lower()

# v4: 函数指针追踪路径

        # 路径FP1: mov reg, [rip+refptr_XXX] → 从refptr加载函数指针
        if "rip" in src_lower and "[" in src_lower:
            rip_addr = resolve_rip_relative(ins, src_raw, addr)
            if rip_addr is not None:
                # 检查是否已在_global_func_ptr中
                known_func = self._global_func_ptr.get(rip_addr)
                if known_func:
                    self._reg_func_ptr[dst] = known_func
                # 从操作数字符串中提取符号名
                symbol = _extract_symbol_from_operand(src_raw)
                if symbol:
                    func_name = _extract_printf_name(symbol)
                    if func_name:
                        self._reg_func_ptr[dst] = func_name

        # 路径FP2: mov [rip+offset], reg → 存储函数指针到全局
        if "[" in dst_raw.lower() and "rip" in dst_raw.lower():
            src_reg = norm_reg(src_raw)
            func_name = self._reg_func_ptr.get(src_reg)
            if func_name:
                rip_addr = resolve_rip_relative(ins, dst_raw, addr)
                if rip_addr is not None:
                    self._global_func_ptr[rip_addr] = func_name
                    return  # 全局存储处理完毕

        # 路径FP3: mov [rbp-XX]/[rsp+XX], reg → 存储函数指针到栈
        if "[" in dst_raw.lower() and ("rbp" in dst_raw.lower() or "rsp" in dst_raw.lower()):
            src_reg = norm_reg(src_raw)
            func_name = self._reg_func_ptr.get(src_reg)
            if func_name:
                slot = extract_stack_slot(dst_raw)
                if slot is not None:
                    self._stack_func_ptr[slot] = func_name
                    return  # 栈存储处理完毕

        # 路径FP4: mov reg, [rip+XXX] → 从全局加载函数指针
        if "rip" in src_lower and "[" in src_lower:
            rip_addr = resolve_rip_relative(ins, src_raw, addr)
            if rip_addr is not None and rip_addr in self._global_func_ptr:
                self._reg_func_ptr[dst] = self._global_func_ptr[rip_addr]

        # 路径FP5: mov reg, [rbp-XX]/[rsp+XX] → 从栈加载函数指针
        if "[" in src_lower and ("rbp" in src_lower or "rsp" in src_lower):
            slot = extract_stack_slot(src_raw)
            if slot is not None and slot in self._stack_func_ptr:
                self._reg_func_ptr[dst] = self._stack_func_ptr[slot]

        # 路径FP6: mov reg2, reg1 → 传播函数指针
        src_reg = norm_reg(src_raw)
        func_name = self._reg_func_ptr.get(src_reg)
        if func_name:
            self._reg_func_ptr[dst] = func_name

# 原有来源追踪路径

        # 情况1: mov reg, imm → literal
        if any(src_lower.startswith(p) for p in ("0x", "$", "-")) or src_lower.isdigit():
            self._reg_src[dst] = "literal"
            return

        # 情况2: mov reg, [rip+XXX] → RIP相对地址
        if "rip" in src_lower:
            rip_addr = resolve_rip_relative(ins, src_raw, addr)
            if rip_addr is not None:
                mem_src = self._mem_src.get(rip_addr, "literal")
                self._reg_src[dst] = mem_src
                return
            self._reg_src[dst] = "literal"
            return

        # 情况3: mov reg, [rbp-XXX] / [rsp+XXX] → 栈加载
        slot = extract_stack_slot(src_raw)
        if slot is not None:
            stack_src = self._stack_src.get(slot)
            if stack_src:
                self._reg_src[dst] = stack_src
            else:
                self._reg_src[dst] = "stack_var"
            return

        # 情况4: mov reg, [reg] → 内存间接
        if "[" in src_lower:
            self._reg_src[dst] = "heap"
            return

        # 情况5: mov reg, reg → 传播
        src_reg = norm_reg(src_raw)
        propagated = self._reg_src.get(src_reg)
        if propagated:
            self._reg_src[dst] = propagated
            return

        # 未识别的源 → 保持dst原有标记或设为register
        if dst not in self._reg_src:
            self._reg_src[dst] = "register"

        # 情况6: mov [mem], reg → 存入内存
        if "[" in dst_raw.lower():
            if "rip" in dst_raw.lower():
                rip_addr = resolve_rip_relative(ins, dst_raw, addr)
                if rip_addr is not None:
                    self._mem_src[rip_addr] = self._reg_src.get(src_reg, "register")
                    return
            slot = extract_stack_slot(dst_raw)
            if slot is not None:
                self._stack_src[slot] = self._reg_src.get(src_reg, "register")
                return

    def _track_lea(self, ins: dict, ops: List[str], addr: int):
        dst_raw, src_raw = ops[0].strip(), ops[1].strip()
        dst = norm_reg(dst_raw)
        src_lower = src_raw.lower()

        # lea reg, [rip+XXX] → 字面量地址
        if "rip" in src_lower:
            rip_addr = resolve_rip_relative(ins, src_raw, addr)
            if rip_addr is not None:
                self._reg_src[dst] = self._mem_src.get(rip_addr, "literal")
            else:
                self._reg_src[dst] = "literal"
            return

        # lea reg, [rbp-XXX] → 栈变量地址 (不是字面量)
        if "rbp" in src_lower or "rsp" in src_lower:
            self._reg_src[dst] = "stack_var"
            return

        # lea reg, [reg] → 内存地址
        if "[" in src_lower:
            self._reg_src[dst] = "heap"
            return

        # lea reg, reg → 传播
        src_reg = norm_reg(src_raw)
        propagated = self._reg_src.get(src_reg)
        if propagated:
            self._reg_src[dst] = propagated
            return


# 辅助函数

def _extract_symbol_from_operand(op: str) -> Optional[str]:
    """从操作数字符串中提取符号名.

    例如: 'QWORD PTR [rip+0x9eb3] # 14000b680 <.refptr.__mingw_printf>'
          → '.refptr.__mingw_printf'
          'rax # 14000f080 <g_log_v_2016_1686_libpng>'
          → 'g_log_v_2016_1686_libpng'
    """
    # 查找 # 注释部分
    if "#" in op:
        comment = op.split("#", 1)[1].strip()
        # 提取 <symbol> 部分
        import re
        m = re.search(r'<([^>]+)>', comment)
        if m:
            return m.group(1)
    return None


# Win32寄存器→Win64映射 (复用disasm_util的逻辑)
_W32_TO_W64 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
    "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
}


def pre_scan_global_func_ptrs(instructions: List[dict]) -> Dict[int, str]:
    """预扫阶段: 建立全局函数指针映射.

    通过简化的指令级追踪, 识别通过全局变量存储的函数指针.
    返回 {global_addr: func_name} 映射.

    追踪链:
      mov reg, [rip+refptr_printf]  → reg持有printf
      mov rcx, reg                   → 传播
      call set_logger                → 保存快照
      (进入set_logger)               → 恢复快照
      mov [rip+g_log], reg           → 记录global_addr→printf
    """
    result: Dict[int, str] = {}

    # 收集call目标和函数入口
    call_targets: Dict[int, int] = {}  # call_addr → target_addr
    for ins in instructions:
        if ins.get("mnemonic", "").lower() == "call" and ins.get("operands"):
            target = _resolve_call_target(ins)
            if target:
                call_targets[ins["address"]] = target

    # 简化的寄存器追踪: reg → func_name
    reg_fp: Dict[str, str] = {}
    # 栈槽追踪: "func_addr:offset" → func_name
    stack_fp: Dict[str, str] = {}
    # call地址 → {reg: func_name} 快照
    call_snapshots: Dict[int, Dict[str, str]] = {}

    # 当前函数入口地址 (用于检测跨函数边界)
    # Win64 arg regs (PE文件默认)
    arg_regs = ("rcx", "rdx", "r8", "r9")

    for ins in instructions:
        addr = ins.get("address", 0)
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])

        # 函数入口检测 — 应用调用者快照
        for call_addr, target_addr in call_targets.items():
            if target_addr == addr:
                snap = call_snapshots.get(call_addr)
                if snap:
                    for r, fn in snap.items():
                        reg_fp[r] = fn
                break

        if mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            dst_raw, src_raw = ops[0].strip(), ops[1].strip()
            dst = norm_reg(dst_raw)
            src_lower = src_raw.lower()

            # 从refptr加载函数指针
            if "rip" in src_lower and "[" in src_lower:
                rip_addr = resolve_rip_relative(ins, src_raw, addr)
                if rip_addr is not None and rip_addr in result:
                    reg_fp[dst] = result[rip_addr]
                symbol = _extract_symbol_from_operand(src_raw)
                if symbol:
                    func_name = _extract_printf_name(symbol)
                    if func_name:
                        reg_fp[dst] = func_name

            # 从全局加载函数指针
            if "rip" in src_lower and "[" in src_lower:
                rip_addr = resolve_rip_relative(ins, src_raw, addr)
                if rip_addr is not None and rip_addr in result:
                    reg_fp[dst] = result[rip_addr]

            # 存储到全局
            if "[" in dst_raw.lower() and "rip" in dst_raw.lower():
                src_reg = norm_reg(src_raw)
                fn = reg_fp.get(src_reg)
                if fn:
                    rip_addr = resolve_rip_relative(ins, dst_raw, addr)
                    if rip_addr is not None:
                        result[rip_addr] = fn
                        continue

            # 存储到栈
            if "[" in dst_raw.lower() and ("rbp" in dst_raw.lower() or "rsp" in dst_raw.lower()):
                src_reg = norm_reg(src_raw)
                fn = reg_fp.get(src_reg)
                if fn:
                    slot = extract_stack_slot(dst_raw)
                    if slot is not None:
                        stack_fp[f"{addr}:{slot}"] = fn
                        continue

            # 从栈加载
            if "[" in src_lower and ("rbp" in src_lower or "rsp" in src_lower):
                slot = extract_stack_slot(src_raw)
                if slot is not None:
                    fn = stack_fp.get(f"{addr}:{slot}")
                    if fn:
                        reg_fp[dst] = fn
                    # 也尝试无地址前缀的查找
                    if dst not in reg_fp:
                        for key, fn_val in stack_fp.items():
                            if key.endswith(f":{slot}"):
                                reg_fp[dst] = fn_val
                                break

            # 寄存器传播
            if dst not in reg_fp:
                src_reg = norm_reg(src_raw)
                fn = reg_fp.get(src_reg)
                if fn:
                    reg_fp[dst] = fn

        elif mnem == "call" and ops:
            # 保存函数指针参数快照
            snap = {}
            for r in arg_regs:
                fn = reg_fp.get(r)
                if fn:
                    snap[r] = fn
            if snap:
                call_snapshots[addr] = snap

            # 调用后: 返回值rax不再持有之前的函数指针
            # (保守处理: 不清除, 因为可能在其他路径上仍然有效)

    return result


def _resolve_call_target(ins: dict) -> Optional[int]:
    """解析call指令的目标地址."""
    import re
    ops = ins.get("operands", [])
    if not ops:
        return None
    target = ops[0].strip().lower()
    for prefix in ("call ", "callq "):
        if target.startswith(prefix):
            target = target[len(prefix):]
    try:
        if target.startswith("0x"):
            return int(target, 16)
        if target.isdigit():
            return int(target)
    except ValueError:
        pass
    m = re.search(r"0x([0-9a-f]+)", target)
    if m:
        return int(m.group(1), 16)
    return None


__all__ = ["FmtSourceTracker", "pre_scan_global_func_ptrs", "_is_printf_func",
           "_extract_printf_name", "_extract_symbol_from_operand"]
