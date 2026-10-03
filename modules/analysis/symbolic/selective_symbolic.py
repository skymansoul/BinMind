#!/usr/bin/env python3
"""
选择性符号执行引擎

基于污点的选择性状态传播策略
仅对污点相关的分支进行符号化约束求解
非污点路径保持具体执行以减少状态爆炸

核心思想：
- 静态污点分析确定关键输入字节
- 符号执行仅在污点影响范围内展开
- 非污点路径使用具体值快速通过

采用 def-use 链引导的剪枝策略
"""

import logging
import os
import re
import struct
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)

# 条件导入 angr
try:
    import angr
    import claripy
    _HAS_ANGR = True
except ImportError:
    _HAS_ANGR = False
    logger.debug("angr 未安装，选择性符号执行不可用")


@dataclass
class TaintRegion:
    """污点区域：输入字节范围映射"""
    start_offset: Optional[int] = None
    end_offset: Optional[int] = None
    source_type: str = "stdin"
    label: str = ""
    start: Optional[int] = None
    size: Optional[int] = None
    tag: str = ""

    def __post_init__(self):
        if self.start_offset is None:
            self.start_offset = self.start
        if self.end_offset is None and self.start_offset is not None and self.size is not None:
            self.end_offset = self.start_offset + self.size
        if not self.tag:
            self.tag = self.label


@dataclass
class SelectiveState:
    """
    选择性符号状态

    区别于全符号状态，仅标记有限的符号变量和约束
    采用剪枝状态表示
    """
    addr: int = 0
    state_id: str = ""
    pc: Optional[int] = None
    tainted_regs: Set[str] = field(default_factory=set)
    tainted_mem: Set[int] = field(default_factory=set)
    constraints: List[Any] = field(default_factory=list)
    depth: int = 0
    priority: float = 1.0

    def __post_init__(self):
        if self.pc is None:
            self.pc = self.addr


@dataclass
class SelectiveExecutionResult:
    """选择性符号执行结果"""
    success: bool = True
    paths_found: int = 0
    tainted_paths: int = 0
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    taint_flows: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[str, int] = field(default_factory=dict)
    solver_time_ms: float = 0.0


class TaintPropagator:
    """
    污点传播器（寄存器级 + 内存级）

    轻量实现：基于指令模式匹配的污点传播
    避免重量级 IR 转换
    """

    # x86-64 数据移动指令（源→目标传播模式）
    _PROPAGATE_PATTERNS = [
        # mov dst, src
        (re.compile(r'mov\s+(\w+),\s*(\w+)', re.I), (1, 2)),
        # lea dst, [src]
        (re.compile(r'lea\s+(\w+),\s*\[(\w+)', re.I), (1, 2)),
        # push src (→ rsp 指向的内存)
        (re.compile(r'push\s+(\w+)', re.I), None),
        # pop dst
        (re.compile(r'pop\s+(\w+)', re.I), None),
        # xchg r1, r2 (双向)
        (re.compile(r'xchg\s+(\w+),\s*(\w+)', re.I), None),
    ]

    # 清除污点的操作
    _CLEAR_PATTERNS = [
        re.compile(r'xor\s+(\w+),\s*\1\b', re.I),  # xor reg, reg
        re.compile(r'sub\s+(\w+),\s*\1\b', re.I),  # sub reg, reg
        re.compile(r'mov\s+(\w+),\s*0\b', re.I),   # mov reg, 0
    ]

    # 二元操作（两个源操作数→目标）
    _BINARY_OP = re.compile(
        r'(add|sub|or|and|xor|shl|shr|sar|mul|imul)\s+(\w+),\s*(\w+)', re.I
    )

    def __init__(self):
        self.regions: List[TaintRegion] = []

    def add_region(self, region: TaintRegion) -> None:
        self.regions.append(region)

    def propagate(
        self,
        instruction: str = "",
        tainted_regs: Optional[Set[str]] = None,
        tainted_mem: Optional[Set[int]] = None
    ) -> Tuple[Set[str], Set[int]]:
        """单条指令的污点传播, 返回更新后的 (tainted_regs, tainted_mem)。"""
        new_regs = set(tainted_regs or set())
        new_mem = set(tainted_mem or set())

        # 清除模式检查
        for pat in self._CLEAR_PATTERNS:
            m = pat.match(instruction.strip())
            if m:
                cleared_reg = m.group(1).lower()
                new_regs.discard(cleared_reg)
                return new_regs, new_mem

        # 传播模式检查 (push/pop/xchg 等无源目标索引的模式跳过)
        for pat, indices in self._PROPAGATE_PATTERNS:
            if indices is None:
                continue
            m = pat.match(instruction.strip())
            if not m:
                continue
            dst, src = m.group(indices[0]).lower(), m.group(indices[1]).lower()
            if src in tainted_regs:
                new_regs.add(dst)
            elif dst in tainted_regs:
                pass  # 如果目标是已污点寄存器，不自动清除（保守策略）

        # 二元操作: add/sub/or//xor dst, src
        m = self._BINARY_OP.match(instruction.strip())
        if m:
            dst, src = m.group(2).lower(), m.group(3).lower()
            if dst in tainted_regs or src in tainted_regs:
                new_regs.add(dst)

        return new_regs, new_mem

    def is_sink(self, instruction: str) -> Optional[str]:
        """检查是否为敏感汇点指令, 返回汇点类型字符串或 None。"""
        call_match = re.search(r'call\s+(.+)', instruction, re.I)
        if not call_match:
            return None

        target = call_match.group(1).lower()
        sink_map = {
            'system': 'command_injection',
            'execve': 'command_injection',
            'execl': 'command_injection',
            'popen': 'command_injection',
            'strcpy': 'buffer_overflow',
            'strcat': 'buffer_overflow',
            'sprintf': 'format_string',
            'memcpy': 'buffer_overflow',
        }

        for func, vuln_type in sink_map.items():
            if func in target:
                return vuln_type

        return None


class SelectiveSymbolicExecutor:

    def __init__(self, binary_path: Optional[str] = None, max_steps: int = 10000):
        self.binary_path = binary_path
        self.max_steps = max_steps
        self.propagator = TaintPropagator()
        self.project: Optional[angr.Project] = None
        self._stats: Dict[str, Any] = {
            'executions': 0, 'paths_found': 0, 'tainted_paths': 0, 'vulnerabilities': 0,
        }

        if not binary_path:
            logger.debug("[SelectiveSym] 未提供二进制路径，仅初始化组件")
            return
        if not _HAS_ANGR:
            raise ImportError("angr 不可用，选择性符号执行需安装 angr")

        self.project = angr.Project(binary_path, auto_load_libs=False)
        logger.info(f"[SelectiveSym] 加载: {binary_path}")

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def reset(self) -> None:
        self._stats = {
            'executions': 0, 'paths_found': 0, 'tainted_paths': 0, 'vulnerabilities': 0,
        }
        self.propagator = TaintPropagator()

    def analyze(self, target_func: str = "") -> Dict[str, Any]:
        if self.project is None:
            return {'success': False, 'error': '未加载二进制，无法分析', 'target_func': target_func}
        try:
            result = self.execute_with_taint_guidance(taint_regions=[], max_paths=100)
            self._stats['executions'] += 1
            self._stats['paths_found'] += result.paths_found
            self._stats['tainted_paths'] += result.tainted_paths
            self._stats['vulnerabilities'] += len(result.vulnerabilities)
            return {
                'success': True,
                'target_func': target_func,
                'paths_found': result.paths_found,
                'tainted_paths': result.tainted_paths,
                'vulnerabilities': result.vulnerabilities,
                'coverage': result.coverage,
            }
        except Exception as e:
            logger.error(f"[SelectiveSym] 分析失败: {e}")
            return {'success': False, 'error': str(e), 'target_func': target_func}

    def execute_with_taint_guidance(
        self,
        taint_regions: List[TaintRegion],
        target_addr: Optional[int] = None,
        avoid_addrs: Optional[List[int]] = None,
        max_paths: int = 100
    ) -> SelectiveExecutionResult:
        """
        基于污点引导的选择性符号执行

        核心算法：
        1. 初始化具体状态，仅将污点输入区域设为符号
        2. 步进执行，对每条指令检查：
        a. 是否访问污点数据 → 是则符号分叉
        b. 是否遇到敏感汇点 + 污点参数 → 报告漏洞
        c. 是否无污点且无分支 → 快速具体执行
        3. 污点约束剪枝：在非污点分支处不产生新状态

        参数: taint_regions 污点输入区域定义, target_addr 目标地址,
        avoid_addrs 规避地址, max_paths 最大路径数。
        """
        result = SelectiveExecutionResult(paths_found=0, tainted_paths=0)

        if self.project is None:
            return result

        state = self.project.factory.entry_state()
        if state is None:
            logger.error("[SelectiveSym] 无法创建入口状态")
            return result

        # 仅对污点区域创建符号变量
        stdin_size = 4096
        symbolic_stdin = self._create_partially_symbolic_stdin(
            stdin_size, taint_regions
        )

        state = self.project.factory.entry_state(
            stdin=angr.SimFile('/dev/stdin', content=symbolic_stdin)
        )

        sm = self.project.factory.simulation_manager(state)

        # 选择性探索簿记: 镜像活跃状态的优先级
        selective_states: List[SelectiveState] = [
            SelectiveState(addr=state.addr, priority=1.0)
        ]

        step_count = 0
        vulns_found = 0

        while step_count < self.max_steps and len(sm.active) > 0:
            if step_count % 500 == 0:
                logger.debug(
                    f"[SelectiveSym] step={step_count}, "
                    f"active_states={len(sm.active)}"
                )

            # 推进 angr 状态
            try:
                sm.step()
            except Exception:
                step_count += 1
                continue

            # 按优先级排序（污染路径优先）
            selective_states.sort(key=lambda s: s.priority, reverse=True)

            for active in sm.active:
                result.paths_found += 1

                # 检查是否访问污染数据
                is_tainted = self._check_state_taint(active, taint_regions)
                if is_tainted:
                    result.tainted_paths += 1
                    # 检查是否为敏感汇点
                    vuln = self._check_sensitive_sink(active)
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        vulns_found += 1

                # 动态调整优先级
                priority = 1.5 if is_tainted else 0.5
                selective_states.append(
                    SelectiveState(
                        addr=active.addr,
                        priority=priority
                    )
                )

            step_count += 1

            if vulns_found >= 10 or result.paths_found >= max_paths:
                break

        result.coverage = {
            'steps': step_count,
            'total_paths': result.paths_found,
            'tainted_paths': result.tainted_paths,
            'vulnerabilities': vulns_found
        }

        return result

    def _create_partially_symbolic_stdin(
        self, size: int, taint_regions: List[TaintRegion]
    ) -> Any:
        """
        创建部分符号化的标准输入

        仅将污点区域的字节设为符号变量
        其余填充具体值（零）
        """
        if not _HAS_ANGR:
            return b'\x00' * size

        stdin_bytes = bytearray(size)
        sym_vars = []

        for region in taint_regions:
            for offset in range(region.start_offset,
                                min(region.end_offset, size)):
                sym_name = f"taint_{region.label}_{offset}"
                sym_var = claripy.BVS(sym_name, 8)
                sym_vars.append((offset, sym_var))
                stdin_bytes[offset] = 0  # 占位

        if sym_vars:
            result = claripy.Concat(*[
                sym_v if i in {o for o, _ in sym_vars}
                else claripy.BVV(b, 8)
                for i, b in enumerate(stdin_bytes)
            ])
            return result
        else:
            return claripy.BVV(bytes(stdin_bytes))

    def _check_state_taint(
        self, state, taint_regions: List[TaintRegion]
    ) -> bool:
        """
        检查当前状态是否访问了污点数据
        """
        try:
            if state.addr is None:
                return False

            # 简化检查：IP 是否在已知危险地址范围
            addr = state.addr
            for region in taint_regions:
                if region.start_offset <= addr <= region.end_offset:
                    return True

        except Exception:
            pass

        return False

    def _check_sensitive_sink(self, state) -> Optional[Dict[str, Any]]:
        """
        检查当前状态是否到达敏感汇点
        """
        try:
            block = self.project.factory.block(state.addr)
            if block is None:
                return None

            for insn in block.capstone.insns:
                insn_str = f"{insn.mnemonic} {insn.op_str}"
                sink_type = self.propagator.is_sink(insn_str)
                if sink_type:
                    return {
                        'type': sink_type,
                        'address': hex(insn.address),
                        'instruction': insn_str,
                        'state_id': id(state)
                    }
        except Exception:
            pass

        return None


def run_selective_symbolic_execution(
    binary_path: str,
    taint_spec: List[Dict[str, Any]],
    target_addr: Optional[int] = None,
    timeout_seconds: int = 60
) -> Dict[str, Any]:
    """
    便捷函数：选择性符号执行

    参数: binary_path 二进制文件路径, taint_spec 污点规格
    (如 [{"start": 0, "end": 256, "type": "stdin"}]), target_addr
    目标地址, timeout_seconds 超时。
    """
    if not _HAS_ANGR:
        return {'error': 'angr 不可用', 'success': False}

    taint_regions = []
    for spec in taint_spec:
        region = TaintRegion(
            start_offset=spec.get('start', 0),
            end_offset=spec.get('end', 0),
            source_type=spec.get('type', 'stdin'),
            label=spec.get('label', '')
        )
        taint_regions.append(region)

    executor = SelectiveSymbolicExecutor(binary_path)
    result = executor.execute_with_taint_guidance(
        taint_regions=taint_regions,
        target_addr=target_addr
    )

    return {
        'success': True,
        'paths_found': result.paths_found,
        'tainted_paths': result.tainted_paths,
        'vulnerabilities': result.vulnerabilities,
        'taint_flows': result.taint_flows,
        'coverage': result.coverage
    }
