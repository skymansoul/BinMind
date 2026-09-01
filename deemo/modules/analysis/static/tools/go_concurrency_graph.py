# coding: utf-8
# Go runtime 调用签名: 识别 channel/sync/goroutine 操作
# 通信图构建: 节点=goroutine函数, 边=channel send->recv配对
# 修复配对: 调用图距离+名称相似度替代索引配对
# 寄存器追踪: 提取channel指针所在寄存器, 同寄存器=同channel

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# Go runtime 函数签名, 用于识别 stripped binary 中的 runtime 调用

# Go runtime 内部函数名及其并发语义
_GO_RUNTIME_OPS: Dict[str, Tuple[str, float]] = {
    # (正则模式, (操作类型, 识别置信度))
    # Goroutine
    r'runtime\.newproc':        ('goroutine_spawn', 0.95),
    r'runtime\.newproc1':       ('goroutine_spawn', 0.90),
    # Channel send
    r'runtime\.chansend1':      ('channel_send', 0.95),
    r'runtime\.chansend2':      ('channel_send', 0.90),
    # Channel receive
    r'runtime\.chanrecv1':      ('channel_recv', 0.95),
    r'runtime\.chanrecv2':      ('channel_recv', 0.90),
    # Select
    r'runtime\.selectgo':       ('select', 0.95),
    r'runtime\.selectnbsend':   ('select_nb_send', 0.85),
    r'runtime\.selectnbrecv':   ('select_nb_recv', 0.85),
    # Synchronization
    r'runtime\.semacquire':     ('sem_acquire', 0.85),
    r'runtime\.semrelease':     ('sem_release', 0.85),
    r'sync\.\(\*Mutex\)\.Lock':   ('mutex_lock', 0.90),
    r'sync\.\(\*Mutex\)\.Unlock': ('mutex_unlock', 0.90),
    r'sync\.\(\*WaitGroup\)\.Add': ('wg_add', 0.85),
    r'sync\.\(\*WaitGroup\)\.Done':('wg_done', 0.85),
    r'sync\.\(\*WaitGroup\)\.Wait':('wg_wait', 0.85),
    # Channel operations
    r'runtime\.closechan':      ('channel_close', 0.90),
    r'runtime\.makechan':       ('channel_make', 0.90),
    # Defer/panic
    r'runtime\.deferproc':      ('defer', 0.80),
    r'runtime\.gopanic':        ('panic', 0.85),
}


@dataclass
class GoConcurrencyOp:
    """单个 Go 并发操作的实例"""
    op_type: str                # goroutine_spawn | channel_send | ...
    func_name: str              # 包含此操作的函数
    func_address: int = 0
    call_address: int = 0       # 调用指令的地址
    confidence: float = 0.0
    # 额外信息
    channel_hint: str = ''      # channel 变量的启发式标识
    channel_arg_reg: str = ''   # channel 指针所在的寄存器 (如 'rax'), 同寄存器=同channel


@dataclass
class GoConcurrencyGraph:
    """Go 程序的并发通信图"""
    # 每函数: {go_func_name: [GoConcurrencyOp]}
    ops_by_function: Dict[str, List[GoConcurrencyOp]]
    # 函数->goroutine 边: spawner -> spawned
    goroutine_edges: List[Tuple[str, str]]
    # Channel 边: sender_func -> receiver_func
    channel_edges: List[Tuple[str, str, str]]  # (sender, receiver, channel_hint)


class GoConcurrencyRecoverer:

    def __init__(self):
        self._call_graph: Dict[str, List[str]] = {}

    def _get_callees(self, func_name: str) -> List[str]:
        """返回函数的被调用者列表, 从存储的调用图中查询"""
        return self._call_graph.get(func_name, [])

    def recover(
        self,
        functions: Dict[str, List[str]],
        call_graph: Optional[Dict[str, List[str]]] = None,
    ) -> GoConcurrencyGraph:
        self._call_graph = call_graph or {}
        ops_by_func: Dict[str, List[GoConcurrencyOp]] = defaultdict(list)

        # 阶段 1: 扫描每函数的 runtime 调用
        for func_name, asm_lines in functions.items():
            text = '\n'.join(asm_lines)
            ops_by_func[func_name] = self._scan_ops(
                func_name, text
            )

        # 阶段 2: 构建 goroutine spawn 边
        goroutine_edges = self._build_goroutine_edges(
            ops_by_func, functions, call_graph,
        )

        # 阶段 3: 推断 channel 通信边 (配对 send->recv)
        channel_edges = self._infer_channel_edges(ops_by_func)

        return GoConcurrencyGraph(
            ops_by_function=dict(ops_by_func),
            goroutine_edges=goroutine_edges,
            channel_edges=channel_edges,
        )

    def _scan_ops(
        self, func_name: str, asm_text: str,
    ) -> List[GoConcurrencyOp]:
        """扫描反汇编文本中的 Go runtime 调用"""
        ops: List[GoConcurrencyOp] = []
        text_lower = asm_text.lower()

        for pattern, (op_type, confidence) in _GO_RUNTIME_OPS.items():
            count = len(re.findall(pattern, text_lower, re.I))
            if count > 0:
                # 尝试提取 channel 指针所在的寄存器
                chan_reg = self._extract_channel_reg(
                    asm_text, pattern
                )
                ops.append(GoConcurrencyOp(
                    op_type=op_type,
                    func_name=func_name,
                    confidence=confidence,
                    channel_arg_reg=chan_reg,
                ))

        # 增强: 从 call 目标地址推断 runtime 函数
        # 若符号已被剥离, 检查函数序言模式
        if not ops:
            ops.extend(self._heuristic_ops(func_name, asm_text))

        return ops

    def _heuristic_ops(
        self, func_name: str, asm_text: str,
    ) -> List[GoConcurrencyOp]:
        """启发式检测, 用于符号完全剥离的场景

        无符号时从指令模式推断:
        - goroutine: lea rax, [func_addr]; mov [rsp], rax; call runtime.newproc
          识别: 连续两个函数地址加载+系统调用
        """
        ops = []
        text_lower = asm_text.lower()

        # 模式: 多个连续的 call 指令->可能是 select 的分发
        call_count = len(re.findall(r'\bcall\s+0x[0-9a-f]+', text_lower))
        if call_count >= 4:
            ops.append(GoConcurrencyOp(
                op_type='select',
                func_name=func_name,
                confidence=0.45,  # 启发式, 置信度较低
                channel_hint=f'{call_count}-way dispatch',
            ))

        return ops

    def _build_goroutine_edges(
        self,
        ops_by_func: Dict[str, List[GoConcurrencyOp]],
        functions: Dict[str, List[str]],
        call_graph: Optional[Dict[str, List[str]]],
    ) -> List[Tuple[str, str]]:
        """构建 goroutine spawn 边: spawner->spawned

        通过分析 goroutine_spawn 操作的上下文推断被创建的函数
        """
        edges: List[Tuple[str, str]] = []

        for func_name, ops in ops_by_func.items():
            for op in ops:
                if op.op_type != 'goroutine_spawn':
                    continue

                # 尝试从调用图推断被 spawn 的函数
                if call_graph and func_name in call_graph:
                    callees = call_graph[func_name]
                    # goroutine spawn 通常调用一个函数字面量
                    # 在 call_graph 中表现为: spawner -> anonymous_func
                    for callee in callees:
                        if self._looks_like_goroutine_func(
                            callee, functions.get(callee, [])
                        ):
                            edges.append((func_name, callee))
                            break

        return edges

    @staticmethod
    def _extract_channel_reg(asm_text: str, runtime_func: str) -> str:
        """提取 channel 操作前的参数寄存器

        Go x86_64 ABI: channel 指针作为第一个参数传入
        在 call runtime.xxx 之前, 参数已在特定寄存器中设置
        扫描 call 前 3 条指令找 mov/lea 到参数寄存器的操作
        """
        import re
        # Go ABI 参数寄存器 (按顺序): AX, BX, CX, DI, SI, R8, R9, R10, R11
        go_param_regs = [
            'rax', 'eax', 'rbx', 'ebx', 'rcx', 'ecx',
            'rdi', 'edi', 'rsi', 'esi', 'r8', 'r9', 'r10', 'r11',
        ]
        # 查找 runtime 函数调用前的参数加载
        pattern = re.compile(
            r'(?:mov|lea)\s+(%s),\s*\[?([^\n;]+)\]?\s*\n'
            r'(?:(?:mov|lea|cmp|test).*\n)?'
            r'(?:(?:mov|lea|cmp|test).*\n)?'
            r'call\s+.*%s' % ('|'.join(go_param_regs), re.escape(runtime_func)),
            re.I,
        )
        m = pattern.search(asm_text)
        if m:
            return m.group(1).lower()
        return ''

    def _looks_like_goroutine_func(
        self, func_name: str, asm_lines: List[str],
    ) -> bool:
        """启发式: 判断函数是否为 goroutine 体"""
        text = '\n'.join(asm_lines).lower()
        # goroutine 体通常较短且包含 channel/sync 操作
        has_chan = any(
            kw in text for kw in ('chansend', 'chanrecv', 'selectgo')
        )
        return has_chan and len(asm_lines) < 100

    def _infer_channel_edges(
        self, ops_by_func: Dict[str, List[GoConcurrencyOp]],
    ) -> List[Tuple[str, str, str]]:
        """推断 channel 通信边, 配对 send 和 recv

        四级启发式按优先级:
          0. 同寄存器配对: send和recv使用同一个寄存器传channel指针
          1. 同函数内配对: 同一函数内的 send+recv (如 select/pipeline)
          2. caller-callee配对: sender调用receiver或反之
          3. 名称相似度 fallback
        """
        edges: List[Tuple[str, str, str]] = []
        paired: Set[Tuple[str, str]] = set()

        # 收集所有 send/recv 操作及其 channel 寄存器
        all_sends = [
            (name, op) for name, ops in ops_by_func.items()
            for op in ops if op.op_type == 'channel_send'
        ]
        all_recvs = [
            (name, op) for name, ops in ops_by_func.items()
            for op in ops if op.op_type == 'channel_recv'
        ]

        # 规则 0: 同寄存器配对 -- channel 指针在同一个寄存器中
        for s_name, s_op in all_sends:
            if not s_op.channel_arg_reg:
                continue
            for r_name, r_op in all_recvs:
                if (s_name, r_name) in paired:
                    continue
                if (s_op.channel_arg_reg == r_op.channel_arg_reg
                        and s_op.channel_arg_reg != ''):
                    edges.append((s_name, r_name, f'reg:{s_op.channel_arg_reg}'))
                    paired.add((s_name, r_name))

        funcs_with_send = {
            name for name, ops in ops_by_func.items()
            if any(o.op_type == 'channel_send' for o in ops)
        }
        funcs_with_recv = {
            name for name, ops in ops_by_func.items()
            if any(o.op_type == 'channel_recv' for o in ops)
        }

        # 规则 1: 同函数内有 send 和 recv -> 自通信边
        for name in funcs_with_send & funcs_with_recv:
            edges.append((name, name, 'same_func'))
            paired.add((name, name))

        # 规则 2: caller-callee 配对, 若 sender 调用 receiver 或被 receiver 调用
        for s_name in funcs_with_send - {e[0] for e in paired}:
            for r_name in funcs_with_recv - {e[1] for e in paired}:
                if (s_name, r_name) in paired or (r_name, s_name) in paired:
                    continue
                # 单向: sender 调用 receiver 或 receiver 调用 sender
                s_calls_r = r_name in self._get_callees(s_name)
                r_calls_s = s_name in self._get_callees(r_name)
                if s_calls_r or r_calls_s:
                    hint = 'caller_callee'
                    edges.append((s_name, r_name, hint))
                    paired.add((s_name, r_name))

        # 规则 3: 剩余未配对, 按名称相似度匹配 (fallback)
        remaining_s = [n for n in funcs_with_send if n not in {e[0] for e in paired}]
        remaining_r = [n for n in funcs_with_recv if n not in {e[1] for e in paired}]
        for s_name in remaining_s:
            best_r = None
            best_overlap = 0
            s_words = set(s_name.lower().replace('_', ' ').split())
            for r_name in remaining_r:
                r_words = set(r_name.lower().replace('_', ' ').split())
                overlap = len(s_words & r_words)
                if overlap > best_overlap:
                    best_overlap = overlap
                    best_r = r_name
            if best_r and best_overlap > 0:
                edges.append((s_name, best_r, 'name_similarity'))
                remaining_r.remove(best_r)

        return edges
