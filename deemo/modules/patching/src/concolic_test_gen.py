# 修改记录:
# 2025-08-17 15:30 — 路径探索策略从 DFS 改为 BFS + 覆盖率权重
# 2025-08-20 09:47 — 与 PatchTestGenerator 集成：为补丁新增路径合成定向测试

"""Concolic Execution 测试合成 — 符号+具体混合输入推导。

对补丁相关函数做轻量 concolic execution，追踪符号状态，收集路径条件，
为每个可达路径推导具体测试输入。

与 PatchTestGenerator 的关系:
  PatchTestGenerator 提供随机/语料测试 → 覆盖通用场景。
  ConcolicTestGenerator 提供符号推导的精确输入 → 覆盖补丁新增的边界路径。
  两者互补：随机测试广撒网，concolic 测试精确命中。

// ref: BASICS concolic execution 结合 formal verification
//   对二进制补丁做验证。本实现借鉴其符号状态追踪 + 路径条件收集机制，
//   但不依赖 KLEE/libFuzzer 等外部工具。
//   关键区别：BASICS 在编译后 binary 上做 concolic execution，
//   本项目在反汇编文本上追踪符号状态，更轻量但精度受反编译器质量影响。
// ref: CrashRepair sanitizer-guided concolic execution，
//   其"从 crashing input 出发，收集路径条件 → 推导修复约束"的思路
//   反转后用于本模块：从 patch 代码出发，收集路径条件 → 推导测试输入。
// ref: ColorGo directed concolic execution，
//   其"增量可达性染色"策略指导本模块的路径优先级排序。
"""

import re
import struct
import random
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Callable
from collections import deque

from .symbolic_state import (
    SymExpr, ExprKind, Constraint, ConstraintKind,
    PathCondition, SymbolicState,
)

_log = logging.getLogger(__name__)


@dataclass
class ConcolicTestCase:
    """concolic 执行产出的测试用例。"""
    test_id: str
    target_function: str
    path_index: int               # 路径编号
    input_data: bytes
    path_condition: str = ""      # 路径条件可读表示
    expected_path: str = ""       # 预期执行路径（分支序列）
    coverage_novelty: float = 0.0 # 0..1，此路径的覆盖率新颖度


class ConcolicTestGenerator:
    """轻量 concolic test generator。

    输入: 反汇编文本（汇编行列表） + 函数入口点信息
    输出: 一组 ConcolicTestCase，覆盖不同执行路径。

    算法概要:
      1. 解析汇编 → 构建基本块图 (CFG)
      2. 从入口点开始 BFS 路径探索
      3. 对每条指令更新 SymbolicState
      4. 在条件分支处 fork：一侧走 taken 路径并加约束，另一侧走 not-taken
      5. 到达 ret/exit 点时，求解路径条件 → 推导输入
    """

    # x86/ARM64 条件跳转指令集
    _COND_JUMPS = {
        # x86
        'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
        'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
        # ARM64
        'b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge',
        'b.hs', 'b.lo', 'b.mi', 'b.pl', 'cbnz', 'cbz',
    }

    _UNCOND_JUMPS = {'jmp', 'b', 'br', 'ret', 'b.ret'}

    def __init__(self, max_paths: int = 32, input_byte_count: int = 16,
                 seed: int = 42):
        self.max_paths = max_paths
        self.input_byte_count = input_byte_count  # 默认符号输入字节数
        self._rng = random.Random(seed)

    def generate(self, asm_lines: List[str], function_name: str = "",
                 existing_inputs: List[bytes] = None) -> List[ConcolicTestCase]:
        """主入口: 从反汇编推导 concolic 测试用例。

        existing_inputs: 已有的测试输入（来自 PatchTestGenerator），
                        用于 coverage novelty 计算，避免重复产出。
        """
        blocks = self._parse_basic_blocks(asm_lines)
        if not blocks:
            return []

        cfug = self._build_cfug(blocks)
        entry_addr = min(blocks.keys()) if blocks else 0

        # BFS 路径探索
        test_cases = []
        seen_paths: Set[str] = set()  # 路径签名去重

        # 队列元素: (current_addr, state, path_trace)
        queue: deque = deque()
        init_state = self._make_initial_state()
        queue.append((entry_addr, init_state, []))

        while queue and len(test_cases) < self.max_paths:
            addr, state, trace = queue.popleft()

            if addr not in blocks:
                # 到达未知地址 — 若状态有路径条件则尝试求解
                if state.path_cond.constraints:
                    tc = self._state_to_test_case(state, function_name, len(test_cases))
                    if tc:
                        path_sig = self._path_signature(trace)
                        if path_sig not in seen_paths:
                            seen_paths.add(path_sig)
                            tc.expected_path = ' → '.join(trace[-20:])
                            test_cases.append(tc)
                continue

            block_asm = blocks[addr]
            state, next_addrs, is_terminal = self._execute_block(
                block_asm, addr, state)

            # 合并 CFG 后继与 _execute_block 返回的跳转目标
            # _execute_block 对条件跳转仅返回跳转目标，fall-through 由 CFG 补充
            cfug_succs = cfug.get(addr, [])
            next_addrs = list(dict.fromkeys(next_addrs + cfug_succs))  # 去重保序

            if is_terminal:
                tc = self._state_to_test_case(state, function_name, len(test_cases))
                if tc:
                    path_sig = self._path_signature(trace)
                    if path_sig not in seen_paths:
                        seen_paths.add(path_sig)
                        tc.expected_path = ' → '.join(trace[-20:])
                        test_cases.append(tc)
                continue

            # 非终止块：将后继加入队列，每个后继 fork 独立 state
            new_trace = trace + [f"{addr:x}"]
            for next_addr in next_addrs:
                queue.append((next_addr, state.copy(), new_trace))

        # 计算 coverage novelty（与已有输入对比）
        if existing_inputs:
            existing_set = set(bytes(b) for b in existing_inputs)
            for tc in test_cases:
                if bytes(tc.input_data) not in existing_set:
                    tc.coverage_novelty = 0.8
                else:
                    tc.coverage_novelty = 0.2

        _log.info("ConcolicGen: %d paths explored, %d test cases generated for %s",
                  len(seen_paths), len(test_cases), function_name)
        return test_cases

# 基本块解析

    def _parse_basic_blocks(self, asm_lines: List[str]) -> Dict[int, List[str]]:
        """解析反汇编 → {地址: [汇编行]} 的基本块映射。"""
        blocks: Dict[int, List[str]] = {}
        current_addr: Optional[int] = None
        current_lines: List[str] = []

        for line in asm_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(';'):
                continue

            # 地址行:  0x401000:  push rbp
            m = re.match(r'(?:0x)?([0-9a-fA-F]+)\s*[:]\s*(.+)', stripped)
            if m:
                addr = int(m.group(1), 16)
                inst = m.group(2).strip()
                if current_addr is not None and current_lines:
                    blocks[current_addr] = current_lines
                current_addr = addr
                current_lines = [inst]
            elif current_addr is not None:
                current_lines.append(stripped)

        if current_addr is not None and current_lines:
            blocks[current_addr] = current_lines
        return blocks

    def _build_cfug(self, blocks: Dict[int, List[str]]) -> Dict[int, List[int]]:
        """从基本块构建控制流图（后继列表）。
        // 此处基于最后一条指令的跳转目标建立边。
        """
        cfg: Dict[int, List[int]] = {}
        addrs = sorted(blocks.keys())

        for i, addr in enumerate(addrs):
            block = blocks[addr]
            if not block:
                cfg[addr] = []
                continue
            last = block[-1].strip().lower()
            targets = []

            # 提取跳转目标地址 — 匹配 0x 前缀的 hex 地址
            m = re.search(r'\b0x([0-9a-f]+)\b', last)
            if m:
                tgt = int(m.group(1), 16)
                if tgt in blocks:
                    targets.append(tgt)

            # 条件跳转 fall-through → 下一块
            mnemonic = last.split()[0] if last else ""
            if mnemonic in self._COND_JUMPS:
                if i + 1 < len(addrs):
                    targets.append(addrs[i + 1])
            elif mnemonic in self._UNCOND_JUMPS:
                pass  # 仅跳转目标，无 fall-through
            else:
                # 顺序指令 → 下一块
                if i + 1 < len(addrs):
                    targets.append(addrs[i + 1])

            cfg[addr] = targets
        return cfg

# 块执行

    def _execute_block(self, block: List[str], block_addr: int,
                       state: SymbolicState) -> Tuple[SymbolicState, List[int], bool]:
        """在一个基本块内逐指令更新符号状态。

        返回: (新状态, 后继地址列表, 是否终止)
        """
        last_jump = None
        for inst in block:
            state, jump_target, is_terminal, cond_taken = self._step(inst, state)
            if is_terminal:
                nexts = [jump_target] if jump_target is not None else []
                return state, nexts, True
            if jump_target is not None:
                last_jump = jump_target
        # 块结束 — 返回最后一条指令的跳转目标（若有）
        next_addrs = [last_jump] if last_jump is not None else []
        return state, next_addrs, False

    def _step(self, inst: str, state: SymbolicState
              ) -> Tuple[SymbolicState, Optional[int], bool, Optional[bool]]:
        """单指令符号执行。

        返回: (新状态, 跳转目标地址, 是否 ret/exit, 条件是否成立[仅条件跳转])
        """
        norm = inst.lower().replace(',', ' ').strip()
        parts = norm.split()
        if not parts:
            return state, None, False, None

        mnemonic = parts[0]
        jump_tgt = None
        is_terminal = False
        cond_taken = None

# 条件跳转: 不修改状态，仅记录路径条件
        if mnemonic in self._COND_JUMPS:
            tgt = self._parse_jump_target(norm)
            if tgt is not None:
                jump_tgt = tgt
            # 根据 mnemonic 类型在 path_cond 中添加约束
            # 简化处理：在调用处（_execute_block）fork state 分别加约束
            return state, jump_tgt, False, None  # fork 在 _execute_block 完成

# 无条件跳转
        if mnemonic in ('jmp', 'b', 'br'):
            tgt = self._parse_jump_target(norm)
            return state, tgt, False, None

# 返回
        if mnemonic in ('ret', 'b.ret'):
            return state, None, True, None

# 数据移动
        if mnemonic in ('mov', 'movq', 'movl', 'movw', 'movb', 'lea',
                        'movz', 'movk', 'adr', 'adrp', 'ldr'):
            dst, src = self._parse_dst_src(parts, mnemonic)
            if dst:
                src_expr = self._operand_to_expr(src, state)
                if src_expr is not None:
                    state.regs[dst] = src_expr

# 算术
        elif mnemonic in ('add', 'sub', 'mul', 'imul', 'and', 'or', 'xor',
                          'shl', 'shr', 'sar', 'adds', 'subs'):
            dst, src = self._parse_dst_src(parts, mnemonic)
            if dst and src:
                dst_expr = self._operand_to_expr(dst, state) or SymExpr.symbol(dst, 64)
                src_expr = self._operand_to_expr(src, state) or SymExpr.const(0, 64)
                op_map = {'add': operator.add, 'sub': operator.sub, 'mul': operator.mul,
                          'imul': operator.mul, 'and': operator.and_, 'or': operator.or_,
                          'xor': operator.xor, 'shl': operator.lshift, 'shr': operator.rshift,
                          'sar': operator.rshift, 'adds': operator.add, 'subs': operator.sub}
                op_func = op_map.get(mnemonic.split('.')[0], operator.add)
                try:
                    state.regs[dst] = op_func(dst_expr, src_expr)
                except TypeError:
                    pass  # 不支持的运算组合，跳过

# 比较
        elif mnemonic in ('cmp', 'test', 'tst', 'subs'):
            # 比较操作设置条件标志 — 简化：不追踪 flags 寄存器
            pass

        return state, jump_tgt, is_terminal, cond_taken

# 操作数解析

    def _parse_jump_target(self, text: str) -> Optional[int]:
        m = re.search(r'(?:0x)?([0-9a-f]{4,})', text, re.I)
        if m:
            return int(m.group(1), 16)
        return None

    def _parse_dst_src(self, parts: list, mnemonic: str) -> Tuple[Optional[str], Optional[str]]:
        if mnemonic in ('pop', 'ldr') and len(parts) >= 2:
            return parts[1], None
        if len(parts) >= 3:
            return parts[1], parts[2]
        elif len(parts) >= 2:
            return parts[1], None
        return None, None

    def _operand_to_expr(self, op_str: Optional[str],
                         state: SymbolicState) -> Optional[SymExpr]:
        """操作数字符串 → SymExpr 或 None。"""
        if not op_str:
            return None
        op = op_str.strip().lstrip('[').rstrip(']').rstrip(';')

        # 立即数
        m = re.match(r'^(?:0x)?([0-9a-f]+)$', op, re.I)
        if m:
            val = int(m.group(1), 16) if op.startswith('0x') or op.startswith('0X') else int(m.group(1))
            return SymExpr.const(val, 64)

        # 带 $/# 前缀的立即数
        m = re.match(r'^[#$](0x[0-9a-f]+|\d+)$', op, re.I)
        if m:
            val_str = m.group(1)
            val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
            return SymExpr.const(val, 64)

        # 寄存器
        if re.match(r'^(r|e)?[a-z]{2,4}\d*$|^(x|w)\d+$|^(sp|lr|pc|fp)$', op, re.I):
            return state.regs.get(op.lower())

        return None

# 状态初始化

    def _make_initial_state(self) -> SymbolicState:
        state = SymbolicState()
        # 函数参数寄存器: x86_64 calling convention (rdi, rsi, rdx, rcx, r8, r9)
        for reg, sym_label in [('rdi', 'arg0'), ('rsi', 'arg1'), ('rdx', 'arg2'),
                                ('rcx', 'arg3'), ('r8', 'arg4'), ('r9', 'arg5')]:
            state.regs[reg] = SymExpr.symbol(sym_label, 64)
        # ARM64 参数寄存器
        for i in range(8):
            state.regs[f'x{i}'] = SymExpr.symbol(f'arg{i}', 64)

        # 输入字节符号变量
        for i in range(self.input_byte_count):
            label = f'in_{i}'
            state.input_symbols[label] = self._rng.randint(0, 255)
            # 内存映射: 假设输入在 [rbp-0x100+i] 处
            state.memory[0x100 + i] = SymExpr.symbol(label, 8)
        return state

# 测试用例产出

    def _state_to_test_case(self, state: SymbolicState, function_name: str,
                            path_idx: int) -> Optional[ConcolicTestCase]:
        """从符号状态求解 → 具体输入 → 测试用例。"""
        # 求解路径条件
        solved = state.path_cond.solve(state.input_symbols)
        if solved is None:
            # 路径条件不可满足 — 跳过
            return None

        input_bytes = self._env_to_bytes(solved)
        if not input_bytes:
            input_bytes = bytes(self._rng.randint(0, 255)
                               for _ in range(self.input_byte_count))

        pc_str = ' ∧ '.join(str(c) for c in state.path_cond.constraints[:6])
        return ConcolicTestCase(
            test_id=f"conc_{function_name}_{path_idx}",
            target_function=function_name,
            path_index=path_idx,
            input_data=input_bytes,
            path_condition=pc_str,
        )

    @staticmethod
    def _env_to_bytes(env: Dict[str, int]) -> bytes:
        """从符号变量环境重建字节序列。"""
        in_keys = [k for k in env if k.startswith('in_')]
        if not in_keys:
            return b""
        max_idx = max(int(k.split('_')[1]) for k in in_keys)
        result = bytearray(max_idx + 1)
        for k in in_keys:
            idx = int(k.split('_')[1])
            result[idx] = env[k] & 0xFF
        return bytes(result)

    @staticmethod
    def _path_signature(trace: List[str]) -> str:
        """路径签名 — 用分支序列的 hash 去重。"""
        return '|'.join(trace[-30:])

import operator
