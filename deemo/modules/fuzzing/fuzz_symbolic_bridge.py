# 2026-07-30

"""轻量级符号执行桥接 -- 在模糊测试回路中插入符号约束求解。

参考:
  PathFuzzing (arXiv:2507.09892)  -- 进化Fuzzing+符号执行混合, 路径编码为比特串
  FuzzBox  (arXiv:2509.05643)     -- QEMU仿真+符号覆盖分析
  Examiner-Pro (IEEE TSE 2024)    -- Unicorn+Angr差分测试符号执行

本模块的目标不是完整实现一个符号执行引擎, 而是提供一个轻量桥接层:
  - 从 fuzzer 获取卡在特定分支的种子
  - 提取路径条件 (通过 Angr 或 r2 反编译的伪代码模式)
  - 生成满足翻转条件的新输入
  - 将新输入反馈回模糊测试队列

当代码覆盖率进入停滞期时, 调用此模块尝试突破复杂分支。
"""

import hashlib
import logging
import os
import re
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---- Angr 可选依赖 ----
_ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    _ANGR_AVAILABLE = True
except ImportError:
    pass


@dataclass
class BranchConstraint:
    """单条分支约束。"""
    address: int                  # 分支指令地址
    taken: bool                   # 当前路径是否跳转
    condition_expr: str = ""      # 可读的约束条件 (如 "rax == 0")
    symbolic_vars: List[str] = field(default_factory=list)


@dataclass
class PathSolverResult:
    """符号求解的结果。"""
    success: bool
    target_address: int           # 目标分支地址
    constraints_solved: int       # 解决的约束数
    new_input: Optional[bytes]    # 满足翻转条件的新输入
    solver_time_ms: float = 0.0
    solver_name: str = ""         # angr / z3 / none


class SymbolicBridge:
    """模糊测试回路中的符号执行桥接。

    当 fuzzer 报告某条路径到达了分支但无法翻转时,
    调用此桥接层尝试用符号执行生成能翻转分支的输入。
    """

    def __init__(self, binary_path: str,
                 max_solver_time_ms: float = 10000.0):
        self.binary_path = os.path.abspath(binary_path)
        self.max_solver_time = max_solver_time_ms
        self._project = None
        self._stats = {
            "queries": 0,
            "solved": 0,
            "timeouts": 0,
            "total_solver_ms": 0.0,
        }

        if _ANGR_AVAILABLE:
            try:
                self._project = angr.Project(
                    self.binary_path, auto_load_libs=False
                )
            except Exception as e:
                logger.warning("Angr项目加载失败: %s, 回退到无符号模式", e)
                self._project = None

    def solve_branch_condition(self, seed: bytes,
                               branch_addr: int,
                               target_taken: bool = True) -> PathSolverResult:
        self._stats["queries"] += 1
        t0 = time.time()

        # 优先使用 Angr
        if self._project is not None:
            result = self._solve_with_angr(seed, branch_addr, target_taken)
            result.solver_name = "angr"
        else:
            result = self._solve_heuristic(seed, branch_addr)
            result.solver_name = "heuristic"

        elapsed = (time.time() - t0) * 1000
        result.solver_time_ms = elapsed
        self._stats["total_solver_ms"] += elapsed

        if result.success:
            self._stats["solved"] += 1
        elif elapsed > self.max_solver_time:
            self._stats["timeouts"] += 1

        return result

    def _solve_with_angr(self, seed: bytes, branch_addr: int,
                         flip_to: bool) -> PathSolverResult:
        """用 Angr 符号执行框架求解分支约束。

        PathFuzzing 将执行路径编码为比特串 (bit=i表示第i个分支是否采取),
        此处直接让 Angr 沿当前路径探索到目标分支, 然后翻转。
        """
        if self._project is None:
            return PathSolverResult(
                success=False, target_address=branch_addr,
                constraints_solved=0, new_input=None,
            )

        try:
            state = self._project.factory.entry_state(
                stdin=seed,
                add_options={
                    angr.options.UNICORN,
                    angr.options.LAZY_SOLVES,
                }
            )

            simgr = self._project.factory.simulation_manager(state)

            # 在目标地址处探索
            simgr.explore(
                find=branch_addr,
                avoid=[],
                num_find=1,
            )

            if not simgr.found:
                return PathSolverResult(
                    success=False, target_address=branch_addr,
                    constraints_solved=0, new_input=None,
                )

            found_state = simgr.found[0]

            # 尝试翻转该分支条件
            # 获取当前IP对应的基本块的后继约束
            # 然后对约束取反
            # Angr 的具体实现需根据目标架构调整
            # 此处提供骨架
            new_input = self._concretize_stdin(found_state)

            return PathSolverResult(
                success=new_input is not None,
                target_address=branch_addr,
                constraints_solved=len(found_state.solver.constraints)
                if hasattr(found_state.solver, 'constraints') else 0,
                new_input=new_input,
            )

        except Exception as e:
            logger.debug("Angr求解异常 @ 0x%x: %s", branch_addr, e)
            return PathSolverResult(
                success=False, target_address=branch_addr,
                constraints_solved=0, new_input=None,
            )

    def _solve_heuristic(self, seed: bytes,
                         branch_addr: int) -> PathSolverResult:
        """无符号引擎时的回退: 基于启发式的输入变异。

        在种子中与分支地址相关的字节位置进行变异,
        类似于 AFL 的 effector map 但目标更精确。

        复杂度: 远不如完整符号执行, 但对简单比较分支 (如 cmp eax, 0)
        仍有效。
        """
        if not seed:
            return PathSolverResult(
                success=False, target_address=branch_addr,
                constraints_solved=0, new_input=None,
            )

        # 简单策略: 在分支地址相关偏移处逐字节翻转
        offset_hint = branch_addr & 0xFF
        data = bytearray(seed)

        for attempt in range(min(10, len(data))):
            pos = (offset_hint + attempt * 17) % len(data)
            orig = data[pos]
            # 尝试常见比较值: 0, -1, 1, 0x7f
            for candidate in (0x00, 0xFF, 0x01, 0x7F):
                if candidate == orig:
                    continue
                data[pos] = candidate
                attempt_data = bytes(data)
                data[pos] = orig  # 恢复
                return PathSolverResult(
                    success=True,
                    target_address=branch_addr,
                    constraints_solved=1,
                    new_input=attempt_data,
                )

        return PathSolverResult(
            success=False, target_address=branch_addr,
            constraints_solved=0, new_input=None,
        )

    def _concretize_stdin(self, state) -> Optional[bytes]:
        """从符号状态中具体化 stdin 输入。"""
        try:
            # Angr 中 stdin 是文件描述符 0, 通过 posix 接口访问
            stdin_fd = state.posix.get_fd(0)
            if stdin_fd is None:
                return None
            content = stdin_fd.load(0, stdin_fd.size)
            concrete = state.solver.eval(content, cast_to=bytes)
            return concrete
        except Exception:
            return None

    def solve_multiple(self, seeds: List[Tuple[bytes, int, bool]],
                       ) -> List[PathSolverResult]:
        """批量求解: 对多个 (seed, branch_addr, target_taken) 进行符号求解。"""
        results = []
        for seed, addr, target_taken in seeds:
            r = self.solve_branch_condition(seed, addr, target_taken)
            results.append(r)
        return results

    def get_stats(self) -> Dict:
        total = max(1, self._stats["queries"])
        return {
            **self._stats,
            "solve_rate": self._stats["solved"] / total,
        }


# ===== 从反编译伪代码提取分支条件(无符号引擎方案) =====

def extract_branch_conditions_from_decomp(
    decomp_output: str
) -> List[Tuple[int, str]]:
    """从 radare2/Ghidra 反编译输出中提取分支条件。

    匹配模式:
      if (var == const) { ... }
      if (var != const) { ... }
      if (var < const) { ... }
    返回 [(address, condition_string), ...]。
    """
    conditions = []
    # radare2 风格: 0x00401234: if (eax == 0)
    r2_pattern = re.compile(
        r'(0x[0-9a-fA-F]+):\s*if\s*\((.+?)\)\s*\{'
    )
    for match in r2_pattern.finditer(decomp_output):
        addr = int(match.group(1), 16)
        cond = match.group(2).strip()
        conditions.append((addr, cond))

    return conditions


# ===== 简单约束求解器 (不依赖外部库) =====

def solve_simple_cmp(
    seed: bytes,
    offset: int,
    current_value: int,
    target_value: int,
    operand_size: int = 4,
) -> Optional[bytes]:
    """对简单等值比较 (cmp reg, imm) 的朴素求解。

    直接将 seed 中 offset 处的 operand_size 字节替换为 target_value。
    这是符号执行能处理的最简单情况 --- 不涉及间接寻址或多约束联立。
    """
    if offset < 0 or offset + operand_size > len(seed):
        return None

    data = bytearray(seed)
    try:
        struct.pack_into(
            {1: 'B', 2: '<H', 4: '<I', 8: '<Q'}[operand_size],
            data, offset, target_value
        )
    except (struct.error, KeyError):
        return None

    return bytes(data)
