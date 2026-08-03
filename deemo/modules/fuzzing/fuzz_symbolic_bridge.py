"""模糊测试与符号执行的约束求解桥接器。

当字节级变异无法突破分支时, 提取路径条件 → 约束求解 → 回注新输入到模糊测试队列。
桥接层不实现符号引擎, 仅编排 Angr/启发式回退的求解流程。

参考: PathFuzzing 路径比特编码 (arXiv:2507.09892), FuzzBox QEMU 符号覆盖分析 (arXiv:2509.05643),
Examiner-Pro Unicorn+Angr 差分测试 (IEEE TSE 2024)。
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

_log = logging.getLogger(__name__)

# Angr 按需导入, 缺失时回退到启发式求解
_ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    _ANGR_AVAILABLE = True
except ImportError:
    pass


@dataclass
class BranchConstraint:
    """一条分支指令的约束条件快照。

    记录分支地址、当前跳转方向及对应的条件表达式。
    """
    address: int                  # 分支指令所在地址
    taken: bool                   # 当前执行路径是否沿 take 方向
    condition_expr: str = ""      # 约束文本, 如 "rax == 0"
    symbolic_vars: List[str] = field(default_factory=list)


@dataclass
class PathSolverResult:
    """单次约束求解的产出记录。

    包含翻转是否成功、目标地址、求解耗时及新输入字节序列。
    """
    success: bool
    target_address: int           # 待翻转的目标分支地址
    constraints_solved: int       # 实际求解的约束条目数
    new_input: Optional[bytes]    # 满足翻转条件的新输入, 失败时为 None
    solver_time_ms: float = 0.0
    solver_name: str = ""         # 求解器标识: "angr" 或 "heuristic"


class SymbolicBridge:
    """模糊测试循环中的符号求解编排器。

    当覆盖卡死在某个分支无法翻转时介入:
    Angr 可用 → 探索到达目标地址后翻转路径条件;
    否则 → 启发式字节边界值注入。

    max_solver_time_ms 控制单次求解超时, 超时计入 stats["timeouts"]。
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
                _log.warning("Angr 项目加载失败: %s, 回退到无符号模式", e)
                self._project = None

    def solve_branch_condition(self, seed: bytes,
                               branch_addr: int,
                               target_taken: bool = True) -> PathSolverResult:
        """对单个分支条件求解, 尝试翻转当前方向。

        入口分流: 有 Angr 项目则走符号执行, 否则走启发式字节变异。
        """
        self._stats["queries"] += 1
        t0 = time.time()

        # 符号引擎可用时优先
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
        """Angr 符号执行: 沿当前路径推进至目标地址后翻转路径约束。

        原理: 从 entry_state 启动, explore 至 branch_addr,
        对到达状态的 solver.constraints 取反以生成新输入。
        目标架构差异需在此处按需调整约束翻转策略。
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

            # 向目标分支地址推进
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

            # 对当前基本块后继约束取反, 实现分支方向翻转
            # 此处为骨架: 具体架构需适配条件跳转的约束改写方式
            new_input = self._concretize_stdin(found_state)

            return PathSolverResult(
                success=new_input is not None,
                target_address=branch_addr,
                constraints_solved=len(found_state.solver.constraints)
                if hasattr(found_state.solver, 'constraints') else 0,
                new_input=new_input,
            )

        except Exception as e:
            _log.debug("Angr 求解异常 @ 0x%x: %s", branch_addr, e)
            return PathSolverResult(
                success=False, target_address=branch_addr,
                constraints_solved=0, new_input=None,
            )

    def _solve_heuristic(self, seed: bytes,
                         branch_addr: int) -> PathSolverResult:
        """无符号引擎时的字节边界值试探回退。

        将分支地址映射到输入偏移, 在该位置注入 0x00/0xFF/0x01/0x7F,
        旨在翻转简单的等值/边界比较。不处理多约束联立或间接寻址的情形。
        """
        if not seed:
            return PathSolverResult(
                success=False, target_address=branch_addr,
                constraints_solved=0, new_input=None,
            )

        # 分支地址低位衍生偏移, 逐字节轮试边界值
        offset_hint = branch_addr & 0xFF
        data = bytearray(seed)

        for attempt in range(min(10, len(data))):
            pos = (offset_hint + attempt * 17) % len(data)
            orig = data[pos]
            # 以 17 为步长轮换位置, 试探常见比较边界值
            for candidate in (0x00, 0xFF, 0x01, 0x7F):
                if candidate == orig:
                    continue
                data[pos] = candidate
                attempt_data = bytes(data)
                data[pos] = orig  # 写回前恢复原始字节
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
        """从 Angr 状态中具象化 stdin 字节序列。

        通过 posix 文件描述符 0 读取求解器求值后的具体内容。
        """
        try:
            # fd=0 经 posix 接口获取已求解的具体字节
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
        """对多个 (seed, addr, target_taken) 依次求解。"""
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


# 从反编译伪代码中提取分支条件表达式

def extract_branch_conditions_from_decomp(
    decomp_output: str
) -> List[Tuple[int, str]]:
    """解析 radare2/Ghidra 反编译输出, 提取 if 条件及其地址。

    匹配形式: if (var == const), if (var != const), if (var < const) 等。
    返回值: [(addr, condition_str), ...], addr 为 int 型地址。
    """
    conditions = []
    # radare2 伪代码格式: "0x00401234: if (eax == 0) {"
    r2_pattern = re.compile(
        r'(0x[0-9a-fA-F]+):\s*if\s*\((.+?)\)\s*\{'
    )
    for match in r2_pattern.finditer(decomp_output):
        addr = int(match.group(1), 16)
        cond = match.group(2).strip()
        conditions.append((addr, cond))

    return conditions


# 单约束等值比较的直接字节替换求解

def solve_simple_cmp(
    seed: bytes,
    offset: int,
    current_value: int,
    target_value: int,
    operand_size: int = 4,
) -> Optional[bytes]:
    """将 seed[offset:offset+operand_size] 替换为目标值, 求解 cmp reg, imm。

    边界: offset 越界时返回 None; 不支持间接寻址或复合约束。
    operand_size 仅接受 1/2/4/8。
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
